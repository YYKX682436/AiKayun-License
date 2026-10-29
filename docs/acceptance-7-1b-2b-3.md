# ⑦-1B-2B-3 正常与灾难迁移全局安全验收

日期：2026-10-29

验收代码基线：`a61907379b0c2b4dd6b4a3595d7aa96acbf9f920`

授权中心：本仓库；商城仅只读核对，基线 `225600b55bbd91bcb7393097b7b5fd44a3465816`。

## 范围和审计依据

逐段核对商城 `AGENTS.md`、⑦-1A R3 协议（`/Users/muchen/Documents/ChatGPT/AiKayun/docs/license-protocol-7-1a.md`）、发行架构（`docs/production-release-architecture-7-1a.md`）和验收契约（`docs/release-license-acceptance-7-1a.md`），以及授权中心⑦-1B-1、⑦-1B-2A、⑦-1B-2B-1 R2、正常迁移协议、⑦-1B-2B-2灾难迁移协议和验收记录。源码覆盖 `src/admin/`、`src/services/`、`src/crypto/`、`src/receipts.ts`、`src/intent.ts`、`src/app.ts`、严格 JSON 解析、数据库类型及不可改写的 `001～005` 迁移；同时核对所有单元、interop 和真实 PostgreSQL/HTTPS 测试。

本轮在原实现上先通过真实 HTTPS/隔离 PostgreSQL 18 重现身份未授权污染、无效激活码写墓碑及跨许可证相同实例竞争返回 500，再修复并回归。新增的“已撤销灾难目标查询未知 operation”用例也先在修复前复现为 attempt 被写入，随后收紧查询授权。没有修改或连接商城数据，没有改写 `001～005`，没有新增迁移。

## 协议状态与信任边界

| 操作 | 发起身份/签名证明 | 权威批准条件 | 成功状态与权益效果 |
| --- | --- | --- | --- |
| 首次激活 | 新实例 Ed25519 JWK；RFC 9421 请求签名；中心一次性 challenge；有效激活码 | 激活码属于该 license，未消费、未撤销、未过期；许可证 active 且未过期 | `generation 0→1`；管理 revision 随绑定更新；签发当前 lease。无效激活码是 403，不形成业务 operation/attempt/audit。 |
| 正常迁移 | 当前 source activation 持钥者 Prepare；经批准 target 持钥者 Commit | 本地管理员审批固定 license、database、source/target、source generation、binding revision、管理 revision 和截止时间；审批未撤销 | 同一 database、同一逻辑 instance 换 JKT；`generation +1`、管理 revision `+1`、entitlement revision 不变；有效权益下返回 transfer receipt + 新 lease。A→B→C 可行，历史 JKT 不可回退到 A。 |
| 灾难迁移 | 管理员记录事故核验后，批准的 target 对 Prepare 与 Commit 各自持钥签名 | 独立管理员审批固定恢复请求、account、DB、source activation、target、generation、binding/管理/entitlement revision；Commit 重验未撤销审批及 source 仍 active | 可保留或按批准替换逻辑 instance；source retired、target 成为唯一 active；generation/管理 revision 各加一，entitlement revision、订阅截止、revoked 状态不被迁移修改。有效权益才给新 lease；expired/revoked 只给 binding-only 证据。 |
| 撤销/恢复/续费 | 仅本机管理员 CLI；进程 OS UID 与真实 UID 一致且在 allowlist，私有 policy/凭据文件权限受限，数据库 loopback 且 session/current role 与指定角色一致 | 请求摘要二次确认、operation 幂等、预期 revision；迁移审批/撤销也是独立、只追加管理操作 | 各自通过 license 行锁与迁移串行。撤销/恢复影响管理与 entitlement revision；续费只按授权业务事件延长 subscription。无生产管理员 MFA。 |
| 查询/重放 | 已关联的 activation 身份，或当前有效且未撤销的批准 target；challenge 与请求签名仍须有效 | operation 的 actor、intent、license、DB 必须再匹配；没有业务操作权限时不得读取保护结果或写业务历史 | 未知但合法可查询请求返回签名 `not_found`，不封死原 operation；同 operation `continue` 可恢复。历史 committed 查询/重放返回持久化原结果，不重新迁移、不延长 lease。 |

中心只验证请求密码学身份，不把“签名正确”视为“有许可证权限”：权限另由当前 activation、一次性激活码或与当前绑定匹配的有效管理员审批决定。管理员审批和实例签名各自独立，不能互相代替；当前实现不强制双人审批。灾难审批中的备份核对、客户核验及旧服务器隔离字段是本机管理员声明，中心没有从外部设备、网络或商户数据库证明这些事实。

## 认证、授权、业务拒绝与审计顺序

HTTP 层只接受 Ed25519 RFC 9421 签名，精确覆盖 method、target URI、content-type、content-digest；签名参数、nonce、JWK thumbprint、目标 origin、最多 60 秒签名窗口和 challenge 绑定逐项校验。重复关键 header、错签名、错 key、错 nonce/challenge、跨 operation challenge 在业务事务前失败。challenge JWT 最长 5 分钟且严格绑定数据库 nonce 行。

业务写入顺序收紧为：请求认证 → operation advisory lock → license `FOR UPDATE` →（需要时）实例 advisory lock → 当前 activation/激活码/有效审批验证 → nonce 消费 → 确定性业务分支 → 同事务写 operation、attempt、审计、票据/权益状态。具体边界如下：

| 请求 | 修复前真实 HTTPS 结果 | 修复后结果 |
| --- | --- | --- |
| 没有关联 activation/审批的身份查询已知 operation | 对已知结果与未知查询可观察到不同响应；未知查询会写 attempt/audit | 隐藏结果，返回签名 `not_found`；不读 operation、不写 attempt/audit。 |
| 初次激活在 COMMIT 结果未知后查询 `not_found` | `not_found` 同时留下业务 attempt/audit | challenge 被消费，返回签名 `not_found`，不写业务 operation/attempt/audit；同 operation `continue` 仍成功，generation 只增一次。 |
| 随机/跨许可证/撤销/过期激活码 | 签名 409 业务拒绝并落 operation 墓碑/attempt/audit | 403 授权拒绝，无受害 license 业务写入；另一有效激活码可正常使用。 |
| 无当前 source 或无有效审批的正常 Prepare | 可签确定性 409 并创建 operation 墓碑 | 403 `TRANSFER_PREPARE_FORBIDDEN`，不写业务 operation/attempt/audit/ticket。有效审批下的真正业务冲突仍走签名拒绝。 |
| 缺失、跨许可证、过期/撤销、source/DB/target 不匹配的灾难 Prepare | 可创建业务拒绝墓碑 | 403 `DISASTER_PREPARE_FORBIDDEN`，无 operation/attempt/audit/plan/ticket；授权 target 的有效业务冲突才落签名拒绝。 |
| 未经许可的跨许可证同 `instance_id` 首次激活竞争 | 唯一索引保护最终状态，但败者返回 500 | 实例 advisory 锁内检查全局 active；授权激活码持有者败者收到签名 409 `ACTIVATION_INSTANCE_ALREADY_ACTIVE`。无效激活码仍先 403。 |
| 已撤销灾难 target 查询随机未知 operation | 仅检查历史 approval 行，仍记录一次业务 attempt/audit | 当前有效 target 判断包括成功管理员操作、摘要一致、未撤销、未过期、revision/generation 与当前状态一致及 source activation 一致；撤销目标只能得到 `not_found`，不产生业务历史。 |

认证/授权失败为 401/403 等原始 API 错误；签名但经授权的确定性业务拒绝才创建有签名回执的不可逆 operation；已获授权但 challenge nonce 过期可写 retryable attempt；数据库错误/触发器错误使对应事务全部回滚。为限流而产生的独立安全计数不属于合法业务审计，本轮没有增加额外安全计数机制。

## JWT 与签名回执契约

`verifyTypedJwt` 对每种用途要求唯一精确 header `{alg,kid,typ}`、Ed25519、当前中心 `kid`、预期 issuer/audience、`clockTolerance=0`，token 限 16 KiB；payload/header 用严格 JSON 解析，拒绝重复字段；各正式验证器使用精确 claim allowlist，拒绝未知 claims。签名正确但绑定不一致的测试向量均由隔离 Ed25519 测试中心 key 重新签名，而非篡改后假设签名会失效。

| 类型 | 验证契约/用途边界 |
| --- | --- |
| Challenge `aikayun-license-challenge+jwt` | 精确 claims；5 分钟内；`sub=instance_id`，operation/id/intent/instance/JKT/client nonce/server nonce 必须与 HTTP、DB nonce 行一致。 |
| Lease `aikayun-license+jwt` | 精确 claims；`exp=min(iat+7天, subscription_end)`、`renew_after=min(iat+6小时, exp)`；只允许中心固定两项 grants，当前权益/续签逻辑负责重签。 |
| License status / operation receipt | 中心仅按各自 typ 签发，TTL 5 分钟；query receipt 内的 `result_jws` 是历史保存结果。此授权中心没有独立消费商城 status/operation receipt 的客户端实现，商城是否严格验证仍未验收。 |
| Normal transfer ticket `aikayun-license-transfer-ticket+jwt` | 专用于 target Commit，精确 claims、最大 600 秒、由 target JKT/DB/license/plan/source/prepare request 绑定；Commit 再与不可变 plan、原 prepare operation/accepted attempt、ticket digest 对照。 |
| Normal transfer receipt `aikayun-license-transfer+jwt` | 独立 verifier；外层 `sub=license_id`；generation 与 revision 各加一；`exp=min(iat+600, subscription_end)`。嵌套 lease 的 license、DB、target instance/JKT/generation、entitlement revision、subscription end、request nonce/digest、iat 必须与外层完全一致。 |
| Disaster ticket `aikayun-license-disaster-transfer-ticket+jwt` | 专用于灾难 target Commit；精确 claims、`exp=iat+600`，验证 recovery request、approval digest、account、DB、source activation/identity/generation、target、revision 与 prepare nonce/digest。 |
| Disaster active receipt `aikayun-license-disaster-transfer+jwt` | `result_mode=active_lease` 且 license active；精确 claims、generation/revision 算术正确、`exp=min(iat+600, subscription_end)`；嵌套 lease 与外层 license/DB/target/JKT/generation/entitlement revision/end/nonce/digest/iat 全匹配。 |
| Disaster binding-only receipt `aikayun-license-disaster-binding+jwt` | 单独 typ、精确 claims、`result_mode=binding_only`、`purpose=historical_obligations_identity_rebinding`、10 分钟 TTL、generation/revision 算术；不允许 `new_lease`/`grants`，普通 lease 验证器拒绝。expired 必须 `subscription_end<=iat`；revoked 状态必须互相一致。 |

回归重新签名后逐项拒绝 normal/disaster receipt 外层 DB、entitlement revision、subscription end 不一致；嵌套 lease 的 license、DB、instance、JKT、generation、entitlement revision、end、nonce、digest 不一致；unknown claims、重复 JSON claim、错误 iss/aud/typ/alg、错误 `nbf`、未来 `iat`、超长时效和跨用途 token。Binding-only 添加 lease 或把 TTL 延长到 601 秒同样拒绝。灾难旧阶段协议文档中 `historical_obligations_only` 与实现不一致，本轮已更正为真实签发值 `historical_obligations_identity_rebinding`。

status/operation receipt 的中心签发路径和字段已检查，但没有自建消费端 validator；本轮不声称商城已完成 receipt 验签，也不把签名历史事实视作当前经营授权。

## 并发与线性化验收矩阵

所有标为“受控”场景都在 PostgreSQL 18 上通过显式行锁/advisory lock 阻塞并观测 `pg_stat_activity` waiter 后才放行；不是随机 `Promise.all` 或固定 sleep。operation lock 解决同 operation；所有单 license 管理/迁移竞争由 `licenses FOR UPDATE` 线性化；实例跨 license 竞争由 `activation-instance:<uuid>` advisory lock 线性化，唯一索引做最终约束。

| 风险/测试证据 | 线性化点与获胜顺序 | 期望并已断言的终态 |
| --- | --- | --- |
| 同 license 两个首次激活；同 operation 并发/迟到旧 attempt | license 行锁；同 operation advisory 锁；challenge nonce 唯一消费 | 仅一 active/generation=1；败者授权或 attempt 冲突不生成重复终态；相同 operation 重放只有一个 business effect。 |
| 跨 license 竞争同一个 active instance（激活、灾难 replace） | 同一 instance advisory lock；两个 license 各自行锁 | 第一个提交；第二个签名业务 409；一个 active instance、赢家 generation=2、输家原 generation=1。激活败者用有效 code 才是已授权业务拒绝。 |
| Normal 与 disaster approval 竞争（两种 waiter 顺序）；normal Prepare 与 disaster approval 竞争（两种顺序） | admin operation advisory lock后，各 contender 排队于同一 license 行锁 | 只留一种有效审批/plan；正常 Prepare 已有正常审批时灾难审批失败，反向授权组合亦被拒；generation 不变。 |
| Normal approval revoke 与 normal Commit；disaster approval revoke 与 disaster Commit | revoke 和 Commit 都必须先拿 license 行锁；approval/plan 后续行锁 | revoke-first：旧 plan invalidated，Commit 签名拒绝且 generation 不增；commit-first：迁移只提交一次、撤销以 revision conflict 失败，target 唯一 active。两种顺序均实测。 |
| Disaster Commit 与管理员 revoke/restore/renew（三操作、两种顺序） | 同 license `FOR UPDATE` | commit-first 只迁移一次且随后管理操作 revision conflict；admin-first 管理 mutation 成功，旧 ticket/审批不能迁移；每个终态一个 active、generation/revision 对应一个获胜提交。 |
| Normal Commit 与 disaster approval（两种 waiter 顺序）及两类审批冲突 | license 行锁；disaster approval 检测正常 approval/plan；normal Prepare 检查有效 disaster approval/plan | 已批准的正常 plan 成功时灾难审批拒绝；灾难审批有权成立的状态下 normal Prepare 被拒。两套有效 plan 不并存。 |
| 不同 target 竞争同一 license；A→B→C、A→B→A | license 行锁/一 license 一个 prepared partial unique index；历史 activation 唯一 | 一计划提交；历史 source/JKT 永不重新 active；A→B→C 可行，A→B→A 回退拒绝。 |
| 同票据换 commit operation、prepare/ticket 跨用途替换 | plan `FOR UPDATE`、唯一 commit operation、票据 digest、一次性 challenge | 同票据只能一个不可逆 committed/cancelled/expired 状态；另一个 operation 收签名 consumed/rejected，不重复 generation。 |

迁移是同一事务中的 source retire、target insert、license generation/revision、plan 终态、ticket 使用、operation 结果、attempt、审计与迁移事件。不存在“operation 先提交、业务后提交”的拆分窗口。不同 license 锁不同行，再争同一 instance 锁不会形成循环等待；目标唯一性还由数据库唯一索引兜底。

## 长故障恢复与当前经营权

| 事件 | 中心端可证明的事实 | 恢复规则 |
| --- | --- | --- |
| Normal/Disaster ticket 已超 10 分钟 | ticket 过期；提交不得推进 generation；plan 变 expired | 正常迁移和灾难迁移均有真实 HTTPS Commit 过期测试（灾难测试用测试签名 key 与过期历史 plan fixture）。必须重新走审批/prepare，不能延长旧 ticket。 |
| 审批到期但 Commit 未执行 | Prepare/Commit 代码重新比较 `approval.expires_at > databaseNow`；发现不再有效会拒绝并使 plan invalidated | 本轮没有等待至少 1 小时做 elapsed-time PostgreSQL 集成，因此“审批时间经过后旧 Commit”的端到端时钟场景列为 NOT_VERIFIED；有效期判断逻辑与同类撤销/revision 失效分支已代码审查和撤销竞争实测。 |
| HTTP 响应丢失、PostgreSQL COMMIT ACK 丢失 | 通过同 operation ID 查询持久 operation/plan；返回数据库保存的原签名结果 | 不新建 commit operation；不二次增加 generation。覆盖 normal/disaster HTTPS，含 COMMIT ACK 丢失、HTTP 丢包。 |
| 真实 rollback / SIGKILL / restart | 未提交事务所有迁移行、票据消费、审计一起回滚 | 原 operation 在确认 rollback 后以同 operation/新 challenge 继续；SIGKILL 和服务重启由测试真实触发。 |
| 数日后 query/replay，原 lease/receipt 过期 | 历史操作、签名字节、attempt 与结果真实性仍可查；原签名时间/expiry 不变 | 查询生成的是新鲜的 operation-query 外层回执，但内含原始 `result_jws`；operation 重放返回原 `response_jws`。历史 lease 不刷新、不复活 revoked/expired 权益。 |
| 原 prepare COMMIT 未知，query 暂时 `not_found`；新 challenge 与迟到请求并发 | `not_found` 不是“事务绝未提交”的证明；operation lock/nonce 唯一性决定真实写入 | 同 operation、同 intent 的 `continue` 重试；不新建业务 operation。灾难 target 在 active 前，只要审批仍有效且绑定一致，仍可查询恢复；提交后可由 activation 历史关联。 |
| 期间发生 revoke/restore/renew/订阅过期/更新迁移 | revision、generation、entitlement revision 和当前 activation 是新事实 | 旧 approval/ticket 按当前状态拒绝；binding-only 不携带经营权；需要当前经营资格必须用当前身份完成已有续签/恢复流程得到新 lease。 |

nonce 清理只在有受限 cleanup authorization 时删除超过保留边界的 nonce；不会删除 operation、attempt、审批、审计、迁移事件或重写历史。数据库触发器的负面验证覆盖直接 UPDATE/DELETE/TRUNCATE/CASCADE；它们只能防范普通应用/业务角色误操作，不能防数据库 owner/superuser 关闭触发器、改 DDL、直接篡改存储或备份。

## 数据库最终组合边界（001～005）

- active activation 有两个唯一索引：每 license 一个、每逻辑 instance 一个；每 license generation 唯一。
- `license_operations.operation_id` 是主键；每 operation 的 attempt_no 唯一、server nonce 唯一。ticket plan 的 prepare operation 唯一，commit operation 唯一；每 license 同时只有一个 `prepared` transfer plan。plan 状态只允许 `prepared→committed|expired|invalidated`，绑定字段不可变。
- activation code 的 hash 唯一；同 license 仅一个 unresolved code；消费/撤销是单向状态转换。
- 管理审批、审批撤销、disaster recovery request、实例 attempt/operation、管理与授权审计、normal/disaster transfer event 受 append-only 或只允许单向状态机触发器保护；nonce 是受控清理例外，不改写其他证据。
- 唯一键、外键、检查约束、license 行锁和事务共同约束 generation、state、ticket consumption 与结果事实。迁移提交与审计/签名结果在一个事务中原子落库。
- 001～005 最终组合经本轮 PostgreSQL 18 真实集成应用；无新增 migration，也未改写已验收迁移。
- 真实数据库负面用例核验更新/删除/截断受保护操作、审批、attempt、审计和迁移表均失败。此结论不外推到超级用户/DDL 管理员威胁。

## 交接给未来商城恢复器（本轮未实现）

商城恢复器在下一阶段至少应独立验证以下契约，完成本地事务后再恢复业务 worker：

1. 用受信任中心公钥验证 HTTPS response 外层及 receipt 的精确 `alg/kid/typ/iss/aud`、严格 JSON/claim 集、时间、签名和 operation/intent/request 摘要；仅 UUID、HTTP 200 或一次 `not_found` 均不足以证明迁移提交。
2. 对 normal receipt 验证 `license_id`、`database_id`、source/target instance 与 JKT、旧 generation、新 generation=`old+1`、`binding_revision` 预期值及管理 `expected_revision→result_revision`，同时对照商城本地不可变 prepare/commit operation、attempt number、body/request digest、challenge nonce 和原响应字节。
3. 对 disaster receipt 额外核对 `account_reference`、历史 source `activation_id`、source DB/instance/JKT/generation、target instance/JKT、管理员批准的 recovery request/approval ID 与摘要；保存独立管理员核验记录，不把中心 receipt 当作商户库内容证明。
4. `database_id` 必须同时等于旧商城持久化身份记录、历史授权 receipt 和中心签名字段；不能因目标服务器新建了空库而只信其自报 UUID。迁移不更换或重写历史订单、退款、提现、履约、付款/退款回调幂等记录。
5. 保留旧公钥/JKT/lease/签名回执与所有 operation/attempt 历史，验证 source 与 target 的身份链。灾难流程没有旧私钥 PoP，不能伪造旧 key 已签；其信任依据是独立管理员批准 + target 新 key 的 challenge/request/commit PoP。
6. 校验 `entitlement_revision`、`subscription_end`、license status 未被迁移提升。`binding-only` 只能更新历史义务记录的身份关联，不得携带 grants/new lease 或恢复经营；active lease 也按当前客户端 lease verifier 校验，并要求中心当前身份/权益续签流程确认资格。
7. 在本地原子绑定 operation 与 receipt 后，显式停用旧 worker、定时任务、队列消费者、支付/供应商回调、外部出站凭据和旧机器流量；对 pending order/refund/withdrawal/fulfillment 做独立对账及恢复。中心 generation 只阻止旧 identity 获得新 lease，不会物理停机旧服务器。

## 本地验收结果

环境为 Node `24.22.1`、PostgreSQL `18-alpine` 临时容器、真实 TLS HTTPS、随机中心 Ed25519 signing key 与每测试独立实例 Ed25519 key、临时许可证/激活码。数据库容器没有数据卷，未连接生产或商城数据库。原验收记录列出 76 项；本轮保留原断言语义并将无效凭证旧的 409 墓碑断言改为新的授权阶段 403/无写入契约，另新增 8 项测试；当前测试集共 84 项。

| 命令 | 结果 |
| --- | --- |
| `npm ci` | PASS，Node 24；安装成功。 |
| `npm run typecheck` | PASS。 |
| `npm run build` | PASS。 |
| `npm test` | PASS，4 个文件、18 项 unit/interop。 |
| `npm run test` | PASS，独立重复执行，4 个文件、18 项 unit/interop。 |
| `npm run test:integration` | PASS，4 个文件、66 项隔离 PostgreSQL 18/HTTPS 集成。与 unit/interop 当前合计 84 项。 |
| `npm audit` | PASS，167 个依赖项，0 vulnerabilities（info/low/moderate/high/critical 均 0）；没有自动升级依赖。 |
| `git diff --check` | 在提交前执行并要求无输出/exit 0。 |

与原测试相比，复用已有的正常/灾难 commit、审批撤销、revoke/restore/renew、同 operation 重试、PG COMMIT ACK 丢失、HTTP response loss、rollback、SIGKILL/restart、A→B→C/A→B→A、JWT 重签负向量及数据库 append-only 用例；没有复制相同语义的测试来填数字。既有身份隔离查询用例加强了无业务历史断言，另新增 8 项集成覆盖：无效激活码授权污染、跨 license 同实例激活竞争、normal/disaster approval 双序竞争、normal Prepare/disaster approval 双序竞争、disaster revoke/commit 双序竞争、跨 license disaster replace 同目标实例、撤销 disaster target 查询污染、过期 disaster ticket Commit。

## 最终结论

- **PASS**：授权中心当前 source/审批校验顺序；未知/非当前身份的 operation 查询不污染业务历史；正常/灾难 Prepare 失效审批不落业务墓碑；跨许可证同 instance 竞争只允许一 active；normal/disaster 正式回执与 lease 严格绑定；binding-only 不取得经营 grants；迁移事务与现有 `001～005` 数据完整性；本地 84 项测试及构建/类型/依赖审计。
- **BLOCKED**：无已发现且未修复的授权中心代码阻断项；未执行生产部署或修改真实数据。
- **NOT_VERIFIED**：审批时限自然经过后再 Commit 的 elapsed-time 全端到端运行；生产管理员 MFA 和生产审批保管措施；真实灾备现场的 DB/备份/customer verification/旧机隔离事实；商城客户端 receipt 消费、binding revision/历史义务恢复器及商户 worker 停机；生产 database owner/superuser 反制；真实生产恢复演练。审批 expiry 比较、拒绝/失效分支已审阅，但没有伪造“已等待 1～24 小时”的实时证据。

本轮只交付授权中心验收与客户端交接契约，不开发商城恢复器，不宣称历史订单、退款、提现或履约会因 license 到期整体锁死。中心端所有 recovery claims 限于本地 PostgreSQL/HTTPS 可观察事实。
