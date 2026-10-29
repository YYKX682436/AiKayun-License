# ⑦-1B-2C-3：在线签名密钥受控轮换

## 范围与信任边界

本实现只在隔离开发环境启用签名身份初始化、信任包接受和签名 key 轮换。它没有开放公网换 key 接口，也没有改变 `src/admin/policy.ts` 对 production 管理 CLI 的禁用规则。

三类私钥各自承担不同职责：

| 身份 | 用途 | 本中心的保存方式 |
| --- | --- | --- |
| 离线发行根 | 签署中心 Ed25519 公钥信任包 | 中心只加载受权限保护的公钥 JWK；私钥不进入中心、数据库或镜像 |
| 在线中心签名 key | 签署 lease、status、operation、ticket、receipt、challenge、time-anchor 和 time-reset receipt | 通过本机 keyring manifest 从明确配置的 PKCS#8 文件加载；私钥不进入数据库 |
| 客户实例身份 key | RFC 9421 HTTP 请求签名及实例身份绑定 | 仅由客户实例持有；中心只处理请求中的公钥和其 JKT |

商城客户端、生产客户数据、生产信任包、生产根私钥、生产签名 PEM 和生产部署均不在此交付范围。

## 配置与密钥加载

中心使用 `LICENSE_SIGNING_KEYRING_FILE`、`LICENSE_OFFLINE_ROOT_JWK_FILE` 和 `LICENSE_TRUST_BUNDLE_MIN_VERSION`。keyring 文件是 schema 1 JSON，逐项列出在线 `kid` 与绝对 PEM 路径。在线 PEM 必须是 Ed25519 PKCS#8，普通单链接文件，POSIX 权限为 0400 或 0600；加载器拒绝 symlink、hardlink、其他算法、损坏 PEM 和实际公钥 JKT 与清单不符的文件。密钥不会在启动时生成或替换。离线根只接受严格的 Ed25519 公钥 JWK。

进程配置不包含 active kid。每次签发在 PostgreSQL 事务内取得中心级共享 advisory lock，读取唯一权威 active kid、已接受的根签名信任包和数据库当前时间，再从本进程 keyring 取对应私钥。缺少 active 私钥、密钥身份不匹配、key 已吊销/退休、当前时间越过签发窗口或信任包无效时 fail closed。不会降级到环境变量中的另一把 key。

## 数据库权威与追加历史

迁移 `007_signing_key_rotation` 只追加表与约束，不改写 `001`～`006`：

- `license_signer_authority`：singleton 当前 active kid、单调 signer revision、当前信任包版本与摘要、前一 kid 和切换时间。触发器限制身份 revision 每次只前进一位，禁止退回空值或更改同版本摘要。
- `license_signer_trust_bundles`：通过离线根验签并被接受的原始 bundle JWS、artifact SHA-256、根 kid、撤销及永久退休墓碑。记录不可更新或删除。
- `license_signer_operations` 与 `license_signer_audit_events`：稳定 operation ID、请求摘要、expected revision、动作、理由、OS UID/用户名、PostgreSQL `session_user`、结果与时间。操作和审计不可更新、删除或 truncate；失败的受控切换也记录为 `rejected`。同 ID/同摘要重放返回原记录，不会再次递增 revision；ID 冲突被拒绝。

管理员操作由本机 CLI 的两步摘要确认发起，并复用 allowlisted OS UID 与独立 PostgreSQL 角色。请求摘要绑定 operation ID、expected signer revision、目标、bundle 摘要、理由和隔离 rollout gate。`signer accept-bundle` 不改变 signer revision；`signer rotate` 检查 revision、离线根身份、bundle 版本与摘要、生命周期、当前 active identity、目标 key 的 root-authenticated JKT 和目标私钥持有证明，再在同一事务写入 operation/audit 并切换 active kid。操作读取 PostgreSQL 当前时间，并要求其与本机时间源偏差不超过 60 秒；偏差超限时拒绝并记录失败。未受信 B、重复目标、过期或未到 not_before 的 key、错误私钥、错根/错版本/错摘要都会被拒绝并审计。

本地命令：

```text
npm run admin -- signer get
npm run admin -- signer initialize --operation-id UUID --expected-revision 0 --active-kid JKT --bundle-file /path/bundle.jws --reason TEXT
npm run admin -- signer accept-bundle --operation-id UUID --expected-revision N --bundle-file /path/bundle.jws --reason TEXT
npm run admin -- signer rotate --operation-id UUID --expected-revision N --target-kid JKT --bundle-version N --artifact-sha256 DIGEST --reason TEXT
npm run admin -- signer operation --operation-id UUID
npm run admin -- signer audit --limit 50
```

离线 bundle 签名代码仅位于 `tools/offline-trust/`。Docker 构建只复制 `src/` 到编译阶段，并在 runtime 复制前删除管理 CLI 和 `keygen`；离线签名工具、离线根私钥、在线私钥和测试 key 均不进入最终镜像。

写命令先输出摘要供复核，复用完全相同参数并附上 `--confirm-digest DIGEST` 才能执行。文件型 bundle 只接受普通单链接文件；CLI 不显示 JWS 正文。CLI 仍只面向隔离开发/测试；不能据此宣称生产审批、MFA、密钥托管或客户端分发门禁已经完成。

## 线性化和锁顺序

所有需要签名的业务事务在操作/许可证/实例锁之前取得中心 signer 共享 advisory lock，并持有至事务结束。顺序为：

1. 中心级 signer 共享锁。
2. operation 或 activation-instance advisory lock。
3. license/approval/plan/activation 行锁及 nonce/result 写入。
4. 用该共享锁读出的 signer 完成本事务内签发，提交时释放锁。

轮换事务取得同一中心级 signer 独占 advisory lock，再取得 signer operation advisory lock，锁定 authority 行并写状态。已有业务事务完成后轮换才能提交；独占锁排队后，新挑战请求在第二个 Fastify 进程排在它之后，读到新 revision 后才签名。短时验签上下文查询、challenge、time-anchor 以及 operation query 也读取此数据库权威状态。独立的 RFC 9421 实例 HTTP 签名流程没有因中心 JWS key 轮换而放宽。

真实 PostgreSQL 18 集成测试使用 `pg_locks` 确认独占切换和另一个 Fastify 实例的签发请求均已排队，然后释放前序共享事务，验证数据库先切换到 B、后续 challenge 由 B 签名。切换前已完成的 A challenge 仍可在正常保留期内验签。

## 多公钥验签与用途边界

中心用已接受离线根签名 bundle 构造 `TrustedSigningKeyResolver`，按 JWT header `kid` 选择唯一 key。验签仍要求精确 protected header（仅 alg/kid/typ）、Ed25519、用途专属 typ/audience、中心 issuer、整数 iat/nbf/exp、key 的 not_before/retire_after/verify_until 和各调用方原有精确 claims。没有 token 自带 JWK、jku、x5u 或网络 JWKS 扩展信任的路径。

接入点包括 challenge 验签、normal/disaster transfer ticket、status/operation receipt、lease、嵌套 transfer receipt/lease、time-anchor 和 time-reset receipt。票据签名验证使用数据库当前时间选 key；过期 ticket 的校验只允许验证历史签名与 claims，随后仍由原事务的数据库有效期截止判断其过期，不能把 token iat 当作当前时间。

当前经营授权验证仍执行 exp、subscription_end、generation、entitlement revision、实例绑定和撤销规则。历史 operation query 只将数据库原始 `response_jws` 作为嵌套证据，绝不重签、改写 iat/exp 或延长 lease。紧急吊销会立刻从当前 resolver 排除该 kid：历史字节和 operation 记录保留，但 A 签名不能再生成迁移 Commit 或恢复经营授权；A 吊销不影响仍受信的 B。active kid 被吊销后，在受控批准新 signer 前所有签发 fail closed。

常规退休在 `retire_after` 阻止新的 A 签发；仍在 `verify_until` 内的 A 凭证可按原用途和过期时间继续验证。`verify_until` 到期后，bundle transition 会永久记录退休墓碑，后续 bundle 不能重新登记该 kid。重新轮换必须使用新的 kid；B→A 被拒绝，B→C 需新的 operation 和 revision。

## 基线问题

在冻结实现的单 active key 模型下，隔离 PostgreSQL 18 与真实 Ed25519/HTTPS 场景复现了以下差异：

1. A 签发的未过期 normal transfer ticket 在 B 接任后无法由 B-only 单 key 验证器验证，合法 Commit 被拒。
2. A 签发的 disaster transfer ticket 有同样失败，不能完成原审批下的 Commit。
3. A 签发的 challenge 在切到 B 后不能被 B-only 验证器接受。
4. A 签发的 normal transfer receipt 及其嵌套 lease 不能由 B-only 验证器验证。
5. 两个 Fastify 进程可各自从配置选择不同私钥，数据库没有共享 signer revision/active kid 来阻止身份分叉。

这些是单 key 配置与验签的结构性失败；本轮以同语义的真实 Ed25519、真实数据库事务和真实 HTTPS 回归覆盖。客户端实例请求签名仍独立验证，改用 mock 验签不构成本验收。

## 发布边界

本阶段验证的是隔离环境 A→B。Root-signed bundle 的本地验签和中心接受，只说明中心认可了候选公钥，并不证明任何客户已收到 bundle。生产轮换仍需在发布前建立可审计的 bundle 传播与客户端就绪证据、生产 MFA/双人审批、受管密钥服务、恢复演练和生产门禁；生产 signer 轮换和客户端集成均未完成。
