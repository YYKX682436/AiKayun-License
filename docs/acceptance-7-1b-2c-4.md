# ⑦-1B-2C-4：授权中心全局联合安全验收

## 验收范围与结论

- 只审查/修改授权中心仓库；商城仓库保持只读。本轮代码基线为 `302e998dd4ddb5e0ad15cd90531d981bf81ae0b0`。
- 联合验收使用临时 Ed25519 离线根、A/B/C 在线测试密钥、临时实例身份、证书受信的真实 HTTPS 和隔离 PostgreSQL 18。没有使用真实许可证、客户资料、生产密钥或正式离线发行根。
- 全局审计未发现能由本轮证据证明的中心状态转换、权限或锁序缺陷；未修改生产服务逻辑和数据库迁移。补充的是缺失的跨模块测试顺序，并将 HTTPS 测试夹具改为显式信任其临时证书、保持 TLS 校验开启。
- 原有 48 项单元/RFC 测试和 89 项真实集成测试均保留；新增 1 项确定性 PostgreSQL 锁顺序集成测试，共 138 项。全量结果见“最终验证”。

| 场景 | 结论 | 证据位置 | 结论边界 |
| --- | --- | --- | --- |
| A：轮换 × 正常迁移 | **PASS** | `test/integration/transfer.test.ts`：A-signed ticket 在 B 接班后提交；`test/integration/disaster-transfer.test.ts` 的轮换后迁移竞争；`src/services/operations.ts` `processTransferCommit` | 保留的 A ticket 只能在其仍满足当前受信生命周期、审批、绑定及有效期时完成；提交事务用当前 signer 签结果。正常退休不提前废除仍有效历史 lease，紧急吊销会立即关闭 A 的新授权路径。 |
| B：轮换/吊销 × 正常与灾难迁移竞争 | **PASS** | `test/integration/disaster-transfer.test.ts`：`serializes normal-transfer commit against a disaster approval; no second migration can pass the shared license lock`，以及 normal/disaster approval 两种获得顺序测试；`test/integration/transfer.test.ts` 的 approval revoke/commit 双顺序测试 | 用 PostgreSQL 行锁等待观察器确认请求已排队后再放锁；没有用 sleep 猜测顺序。数据库事务线性化不等于能物理关停离线旧实例。 |
| C：获批 time-reset × generation 变更 | **PASS** | `test/integration/transfer.test.ts`：`serializes an approved time reset against normal migration in both PostgreSQL lock orders`；`test/integration/time-reset.test.ts`：A-signed reset 回执在 B 接班后仍保持原字节/不能重复升 epoch | 两种先后顺序均由实际 PG 锁等待确定；覆盖正常迁移替换原 activation。灾难迁移与 time-reset 的专门组合未单独复测，虽共享相同 license/signing 锁规则。 |
| D：bundle 更新 × A 紧急吊销 × 在途请求 | **PASS** | `test/integration/transfer.test.ts`：A challenge/ticket 吊销后不能 Commit；`test/integration/disaster-transfer.test.ts`：灾难 ticket 吊销；`test/unit/trust-bundle.test.ts`：状态水位/撤销墓碑；`src/crypto/signing-authority.ts` | 新请求从数据库当前 bundle/authority 读取状态，不依赖旧 resolver 缓存决定是否签发。历史 JWS 原字节保留不代表其仍是经营授权。完全离线实例只能在下一次接受新 bundle 时获知吊销。 |
| E：可信时间异常 × bundle × key 生命周期 | **PASS** | `test/integration/time-reset.test.ts`：真实 HTTPS/PG 五年偏差时间锚；`test/unit/trust-bundle.test.ts`：正负五年偏差、nonce/RTT、bundle 有效期和版本、`not_before`/`retire_after`/`verify_until` 边界 | 时间锚仅证明签名中心时间，不含经营 grants。使用真实 TLS 校验；错误系统时钟导致 TLS 证书引导失败仍是商城客户端/部署边界，本轮没有宣称解决。 |
| F：COMMIT 未知 × A→B 轮换 | **PASS** | `test/integration/activation.test.ts`：激活 COMMIT 确认丢失；`test/integration/transfer.test.ts`：正常迁移 COMMIT 确认丢失；`test/integration/time-reset.test.ts`：time-reset COMMIT 确认丢失并在轮换后 query/replay；`test/support/postgres-proxy.ts` | 原 `response_jws` 逐字节保留；B 签发的新 operation query/继续回执引用原结果。新 attempt 递增且 request digest、nonce、actor 与原 operation intent 绑定。真实 rollback/SIGKILL 的原有场景仍在全量集成套件中。 |
| G：中心 signer authority 与商城 bundle store 回退 | **部分 PASS；全局回退 NOT_VERIFIED** | `test/unit/trust-bundle.test.ts`：单状态文件回退、state/checkpoint 分叉、损坏/过期包和原子写中断；`src/db/migrations/007_signing_key_rotation.ts`、`test/integration/admin.test.ts`：数据库 authority/audit 不可变及缺 key fail-closed | TrustBundleStore 可拒绝可确定复现的单文件/状态检查点回退；本地独立检查点不是数据库或所有持久介质的外部单调锚。恢复同时回退的 PostgreSQL 备份、全部持久文件和匹配密钥未被验证，必须列为发行前门禁。 |

## 联合状态转换与锁序矩阵

| 权威/对象 | 允许的单调转换 | 关键竞争结果 | 已有/本轮真实证据 |
| --- | --- | --- | --- |
| 在线 signer | `active A / signer_revision r → active B / r+1`；不按私钥配置自行选择，不回退/复活已退休 kid | signer 更新取独占 signer advisory lock；在途业务共享锁先完成或失败，后续请求读取新的数据库 authority | `test/integration/signing-key-rotation.test.ts`、`test/integration/signing-time-consistency.test.ts`、`src/admin/signing-service.ts` |
| 已接受中心 bundle | `v1 → v2 → v3`，版本水位递增；撤销/退休墓碑不可逆 | 每次操作从数据库 authority 指向的已接受 JWS 构造当前 key resolver；active kid 被吊销时签发 fail closed | `test/integration/signing-key-rotation.test.ts`、`test/unit/trust-bundle.test.ts`、`src/crypto/signing-authority.ts` |
| 普通/灾难迁移 | `prepared → committed|expired|invalidated`；成功时 source 仅退休一次、target 成为唯一 active、generation 增一 | 正常与灾难审批共享 license 行互斥；两个 commit 争同一 license 时只能一个推进 generation | `test/integration/transfer.test.ts`、`test/integration/disaster-transfer.test.ts`、`src/services/operations.ts` |
| time-reset | 仅同一 active activation、expected generation/epoch/授权摘要匹配时 `time_epoch → time_epoch+1` | time-reset 与替换 activation 的迁移在 license 行锁线性化；reset 先完成只改变旧 activation epoch，migration 先完成则旧审批无副作用 | `test/integration/transfer.test.ts`、`test/integration/time-reset.test.ts` |
| operation/attempt/结果 | `operation_id + intent_digest` 固定；attempt_no 只增；terminal result/`response_jws` 不可覆盖 | 查询/继续使用当前 signer 新签外层回执，但内嵌/返回已提交原 JWS；同一操作不重复消费 code、升 generation 或 epoch | `test/integration/activation.test.ts`、`test/integration/transfer.test.ts`、`test/integration/time-reset.test.ts`、`src/services/operations.ts`、`src/receipts.ts` |
| 商城本地 TrustBundleStore | 接受更高受信版本；主状态与独立 checkpoint 一致提交，失败恢复不降低版本/墓碑 | 文件 store 自身的串行和原子替换不是中心 PostgreSQL signer authority，也不保护所有介质同时回滚 | `test/unit/trust-bundle.test.ts`、`src/trust/trust-bundle-store.ts` |

服务端锁序已从源代码核对：需要签名的 API 请求先持有共享 signer advisory lock，再按请求路径取得 operation/instance advisory lock、license 行锁及 approval/plan/activation/nonce 等业务行锁；签名入口在同一事务中重新读取 PostgreSQL `clock_timestamp()` 并检查 bundle/key 时间窗。轮换先取 signer 独占 advisory lock，再取 signer operation advisory lock与 authority/bundle 行。管理员 license 写入以其 operation 与 license 行锁串行，不反向等待 signer 锁。迁移与 time-reset 都按 signer→operation→license 主序，无观测到反向锁边或跨模块环路。`src/services/operations.ts`、`src/crypto/signing-authority.ts`、`src/admin/service.ts`、`src/admin/signing-service.ts` 是对应实现入口。

## A–G 场景细节

### A：签名轮换与正常迁移

真实 A-signed challenge/ticket 可在受控 A→B 切换后验证；ticket 的 operation ID、原字节及审批身份未被重签。Commit 重新按当前 PostgreSQL signer authority 签结果，当前为 B 时结果和新 lease 使用 B。唯一 source retire、target generation `+1`；测试核对 subscription end、entitlement revision、database_id 不被迁移更改。独立覆盖过期 ticket 与过期审批拒绝，吊销后 A challenge/ticket 不能留下新 operation、attempt 或 nonce 消费。

源代码证据：`src/services/operations.ts` `processTransferPrepare/processTransferCommit`；`src/receipts.ts` `verifyTransferTicket/signTransferReceipt`；签发门禁 `src/crypto/signing-authority.ts`。

### B：正常/灾难迁移互斥及撤销

灾难审批和普通迁移 commit 在两种受控锁到达顺序下竞争。若 commit 先取得 license 行锁，它提交后审批只能观察到已改变的代次/修订并失败；若灾难审批先取得锁，已完成的正常迁移使其旧 source/binding 输入失效，不会产生第二个 active。测试在其中一条迁移竞争加入 A→B 轮换，确保同一签名生命周期和业务互斥联合成立。

Approval revoke/commit 两条路径均各自测试先后顺序；吊销先发生时 ticket 失效、无业务副作用，Commit 先完成时不可撤回已提交迁移历史。已经合法存在的 operation 墓碑不会因票据失效或回滚而删除。

### C：time-reset 与 generation

time-reset operation 与正常迁移各先、后取得 PostgreSQL 行锁一次。reset 先完成时只有原 generation 的旧 activation epoch 加一，迁移再 retired 它并以 epoch 0 建立新 generation；迁移先完成时旧 generation 请求返回 binding mismatch，且不消费 reset nonce、不写 reset operation/attempt。双路径都保持管理 revision、entitlement revision、generation、time_epoch 各自独立；B 接班后，已提交 A reset receipt 保持字节不变，重放不能再增加 epoch。测试也证明 revoked/expired license 的 time-reset 不能恢复经营 grants。

### D：信任包更新与吊销

信任包从 A 到 A+B 再到 A revoked+B 的转换覆盖公钥生命周期、candidate 接受、墓碑及在途挑战/ticket。旧 A 的尚未提交经营请求在吊销接受后无法通过当前验证或签发；在途请求如已先完成事务，则保留不可变 committed 历史。历史 A operation 原始 JWS 不改写，当前 operation query 可用 B 签署短期回执来引用该旧 JWS；该历史事实不能代替当前有效 lease。已有 B lease 按其 claims/window 验证；当前 active signer 被撤销时，签发/查询需要签名的接口 fail closed。

### E：可信时间与 key 时间窗

时间引导以 TLS 校验通过的 `/v1/time-anchor`、独立 256-bit nonce、签名 `server_time` 和单调 RTT（0–5000ms）验证；anchor JWS 的 `iat=nbf=server_time`、`exp=server_time+30`。信任候选先通过离线根验签，再由 candidate key 验 anchor，之后使用 anchor 时间验证 bundle/key 窗口，最后才接受持久包。`not_before` 起点可用；`retire_after` 与 `verify_until` 是排除边界；A 正常退休后仍在其 verify 窗口内的历史 lease 保留验证能力。

Bundle 过期、损坏、版本回退、状态/checkpoint 不一致都不替换 last-good；候选时间锚不生成 grants。根签名和 TLS 验证均保持启用。系统绝对时间偏差造成 HTTPS 证书尚未可信时如何安全引导，仍未在本阶段解决。

### F：未知提交与恢复

隔离 PostgreSQL commit-ack proxy 将实际事务提交与客户端确认分离。激活、正常迁移、time-reset 各选一条路径，在持久 `operation_id` 已提交而响应未知后切换到 B：query/continue 返回当前 B 签名的 operation receipt，同时精确返回数据库保存的原 A `response_jws`。重放使用新的唯一 attempt 编号；原 nonce hash、raw request digest、actor JKT、intent digest 和历史 response 不换绑、不重签。原有真实 rollback 与 SIGKILL 测试继续验证事务未提交时同一意图可用合法新 attempt 恢复。

在定向测试中，time-reset replay 首次复用 query 已登记的 `attempt_no`，中心按设计拒绝 `ATTEMPT_NUMBER_REUSED`；用新的 attempt_no 后通过。这是测试夹具遵守既有 attempt 唯一规则的校正，不是服务端状态转换缺陷。

### G：双权威与回退

中心 signer authority 是 PostgreSQL 中的 active kid、signer revision、bundle head、不可变 operation/audit；密钥文件只是被该数据库身份选择的签名材料，缺失或与 active kid/JWK 不匹配时服务拒签，不退回旧 key。迁移触发器保护只追加记录和禁止覆盖/截断；`001`–`007` 文件没有改写。

商城客户端未来的 TrustBundleStore 则把 root pin/minimum version 加在发行工件，由文件主状态与单独 checkpoint 防止可复现的单文件/状态-检查点回退。它不与中心数据库合并成一个权威，也不能证明客户已接受 bundle。

没有外部可信单调锚时，无法从协议上排除管理员同时恢复较旧的中心数据库、匹配的旧密钥和其他持久介质。此类恢复必须由独立备份/密钥恢复流程核对并维持经营关闭，作为发行前门禁；本轮未验证该恢复流程，也不宣称 TrustBundleStore 能抵抗所有持久状态同时回滚。

## 全局跳跃审查

- 所有业务 JWS 汇聚到 `src/crypto/jwt.ts` 的严格 `signTypedJwt()`，签名前在持锁事务内取 PostgreSQL 当前时间；challenge 的 JWT 时间与 nonce 时间同源，并在 signer 锁等待后复核原 RFC 9421 签名窗口。没有使用进程 wall time 来越过 JWT 生命周期。
- 业务 JWS `protected header` 精确为 `{alg,kid,typ}`，Ed25519、issuer、audience、typ 和 claims 均按用途强校验；不接受 token 内嵌 key 或 jku/x5u。商场协议 `aikayun-license+jwt / aikayun-commerce` 与真实 lease schema 一致。
- `authenticateOperationRequest` 在服务访问 operation/license 业务历史前验证 RFC 9421 身份、challenge、actor、原始 body digest 与预期 operation；未授权 actor 无法查询他人结果或制造业务历史。管理员 CLI 的 OS UID + 独立 PostgreSQL role 在 admin service 访问业务前确认。
- 撤销审批、过期 ticket、generation/revision/epoch 冲突均在 nonce/经营效果前验证；认证/授权失败不遗留未授权 operation/attempt/nonce 副作用。单调 identity namespace 不互相替代。
- 到期/撤销限制新增经营授权，历史 operation JWS、订单支付/退款/履约义务与业务解密材料不由授权状态销毁。中心无法证明旧机器物理断电；完全离线实例不能即时接收紧急吊销。
- `npm audit --audit-level=low`、Docker 运行时边界、GitHub Actions 结果见“最终验证”。

## ⑦-1A R3 契约对照

完整客户端对照与后续实现清单见 [`license-client-handoff-7-1b-2c-4.md`](./license-client-handoff-7-1b-2c-4.md)。这里记录关键审阅结果：

- lease typ/audience、schema、`exp=min(iat+7d,subscription_end)`、renew-after、grants、instance/database/JKT/generation/entitlement revision 与 ⑦-1A R3一致。
- operation、challenge、status 使用独立 typ。当前时间 anchor 增加用途独立的 `aikayun-time-anchor+jwt` / `aikayun-time-bootstrap`；time-reset 为 `aikayun-time-reset+jwt` / `aikayun-time-recovery`，均不得作为 lease 验收。
- R3 中灾难迁移概述使用通用 `aikayun-license-transfer+jwt` 与新 lease；授权中心已审查实现使用独立灾难结果 typ，且过期/撤销 license 只返回 `aikayun-license-disaster-binding+jwt` 的无 grants 绑定证明。客户端必须按这两种明确 schema 分开实现；这属于 ⑦-1B-2B-2 的已记录契约细化，需要商城实现按本交接逐字段消费，不能把 binding 当 lease。
- R3 的 `/v1/origin`、商城投影/准入/恢复器仍不在当前中心已实现端点/能力之中。详见客户端交接表，不以接口“将来设计”冒充已上线能力。

## 最终验证

Node `v24.22.0` 下 `npm ci` 成功；`npm run typecheck`、`npm run build` 成功；`npm test` 为 48/48；`npm run test:integration` 在独立 PostgreSQL 18 与真实 TLS 校验 HTTPS 上为 90/90；`npm audit --audit-level=low` 报告 0 vulnerabilities；`git diff --check` 通过。独立 Docker image build 成功，runtime 检查确认以非 root 运行且不含 admin CLI、keygen、offline signer、测试依赖或 PEM/JWK key 文件。`src/db/migrations/001`–`007` 没有 diff；未使用/停止任何商城项目容器、数据卷或服务。GitHub Actions 与最终 main SHA 在提交推送后核对。

本轮结项后停止。商城客户端、生产发行、生产环境配置或部署需另行授权和独立验收。
