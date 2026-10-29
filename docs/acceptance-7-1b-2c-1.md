# ⑦-1B-2C-1 可信时间引导与受审校时恢复

## 交付范围

本阶段在独立授权中心实现时间锚、管理员校时审批、单次 `time_epoch` 提升、独立签名回执和可重放的持久操作结果。商城仓库保持只读，正式商城客户端、客户端数据库/文件投影、中心签名密钥轮换、trust bundle、生产 MFA 和部署均不在本阶段。

冻结基线为 `b5733c4256cdc2e2230f803ad290f398ff95c178`。新增迁移 `006_time_reset`；迁移 `001` 至 `005` 未修改。已有 RFC 9421 `created` / `expires` 校验没有放宽。

商城的产品边界仍以商城仓库 `AiKayun/docs/license-protocol-7-1a.md` 的 R3 时间水位、实例身份与 time-reset 契约为准：完整身份水位包含 activation generation 和该 activation 的 epoch；校时回执只恢复时间状态，不授予经营权限。

## 协议

### 可信时间首次引导

客户端向 `POST /v1/time-anchor` 发送唯一随机 `client_nonce`，必须是 32 字节、Base64URL 无填充编码。此用途端点：

- 不要求基于客户端 wall clock 的 HTTP 签名，也不读取 HTTP `Date` 响应头。
- 请求体最大 512 字节；每个请求 IP、每个进程最多 12 次/分钟，限流在请求体解析前执行。
- 只签发时间证据，不写业务审计、不消费 nonce/激活码、不读取或修改许可证和 activation 状态。
- 返回独立 `typ=aikayun-time-anchor+jwt`、`aud=aikayun-time-bootstrap` 的 Ed25519 JWS，claims 精确限定为 `v, iss, aud, sub, jti, iat, nbf, exp, server_time, client_nonce`。`jti` 唯一，`exp=server_time+30` 秒。
- 使用中心配置的固定公钥及 `kid` 验签。商城不得从未经信任的在线 JWKS 临时获取该密钥。

时间锚响应往返时间由客户端的单调时钟测量；超过 5 秒不得用于校时。测试客户端对签名、`typ`、issuer、audience、nonce、签发时间、短有效期、唯一 ID 和固定 `kid` 进行验证。时间锚只用于计算后续 RFC 9421 `created`，业务请求仍走原签名验证和 60 秒时间窗口。

中心签发时间来自 PostgreSQL `clock_timestamp()`。本阶段在时间锚和 time-reset 事务中增加数据库时钟与中心进程 wall clock 相差超过 60 秒时 fail closed 的一致性检查，时间锚返回 `503 TIME_SOURCE_UNHEALTHY`。该检查能发现两者明显分歧，不能证明两者同时正确；生产运行仍必须配置独立的 NTP/chrony 健康监控及 fail-closed 运维门禁，不能把 PostgreSQL 时钟或本机时间锚当作可信 NTP 的替代品。当前未连接外部时间健康服务，也未部署生产环境。

### time-reset 审批和执行

管理员先用 `license approve-time-reset` 生成摘要并独立核对，再以相同参数追加 `--confirm-digest` 执行。审批沿用当前管理员 CLI 的 OS UID、PostgreSQL `session_user`、稳定 operation ID、expected revision、摘要确认及不可变审计。审批有效期为 1–72 小时，支持追加式撤销。管理员 CLI 原有 production 禁用限制保持不变。

审批和中心执行均绑定以下内容：

- license ID、database ID、instance ID、activation ID 和 identity JKT。
- 当前 activation generation、license management revision、entitlement revision。
- 当前 epoch 和预期新 epoch（必须恰为 `current + 1`）。
- 客户端提供的旧本地水位摘要、time-reset operation ID、完整 intent digest。
- 审批 operation ID、审批请求摘要、审批人身份、理由、审批有效期和审计引用。
- 新 challenge 的 client/server nonce、原始签名请求摘要及 HTTP Ed25519 持钥证明。

服务端不把客户端上传的旧水位摘要视为本地文件真实性证明。提交事务检查当前 active activation、generation、JKT、revisions、epoch、审批、撤销记录、challenge nonce 和摘要；在同一 PostgreSQL 事务内消费 challenge nonce、单调提升 epoch、写不可变 operation/attempt/audit/event、签发并保存 `aikayun-time-reset+jwt` 后提交。重复的同 operation 请求返回原 JWS，不再次提升 epoch。不同 operation 并发竞争同一 epoch 时最多一个成功。

time-reset 回执使用独立 `aud=aikayun-time-recovery`，有效期 10 分钟，claims 精确限定，不包含 `grants`、`new_lease`、`subscription_end` 或其他经营许可字段。它绑定完整 activation generation + epoch、revisions、operation/intent、nonce/request 摘要及管理员审批审计身份。客户端验证器使用预置中心公钥、最近有效的可信时间锚和待处理操作中的完整预期字段；不匹配的新 generation/JKT/epoch 必须拒绝。

校时不改变 license status、generation、management revision、entitlement revision、订阅结束时间、激活码或经营权限。中心可为已撤销或已过期的许可证恢复时间水位，但商城仍须按当前签名 license 判断经营授权。历史订单及已存在订单恢复按既有 R3 边界独立处理。

## 数据与迁移

`006_time_reset` 为每条 activation 增加 `time_epoch bigint NOT NULL DEFAULT 0`。数据库触发器只允许 active activation 的 epoch 单调、每次最多加一；retired activation 的 epoch 不再可变。正常迁移/灾难迁移创建新 generation 时，新 activation 从 epoch 0 开始。不可把上一代的 epoch、审批或回执直接移交给新 JKT。

审批、审批撤销、校时事件均追加写并禁止 UPDATE/DELETE/TRUNCATE。operation 存储恢复 JWS 原文及其摘要。中心 operation replay 还要求原 activation 仍是当前 active generation；generation 已迁移时旧实例不能再从中心取出旧 reset 回执作为当前身份的恢复证据。

## 商城客户端交接：本阶段未实现的本地投影

客户端必须先持久化稳定 operation ID、intent digest、完整 activation 身份、旧 DB/file 水位快照及摘要，再开始网络请求。断网或响应丢失时沿用同一 operation ID 查询或重放，不得创建新操作来“猜测”是否已提交。恢复步骤建议如下：

1. 读取 DB 与独立持久化水位文件中的 `license/database/instance/JKT/generation/epoch`。两者不一致时停止新经营操作；不要自动选择较低 epoch。
2. 生成新的 32 字节 client nonce，使用单调时钟测量 HTTPS 请求往返。只用预置中心公钥验签时间锚并核对 nonce/claims；超过 5 秒、过期、验签失败或中心不可达时不调整任何本地水位。进程重启导致单调时钟基准丢失后必须重新请求锚；运行时再次观察到时钟异常也重新引导，不能沿用旧进程的 wall-clock 偏移。
3. 用 `server_time + monotonic_elapsed` 生成 RFC 9421 签名时间，依次请求普通 challenge 和 time-reset commit。不要读 HTTP Date、用户输入时间或在线 JWKS。
4. 验证 reset JWS 的 typ、issuer、audience、短有效期、精确 claims、签名及完整 pending tuple；检查 epoch 恰好加一、请求 nonce/request digest/审批 ID 和摘要匹配。回执无业务 grants；不能据此创建订单、续订或恢复许可证。
5. 在执行前将 pending intent 写入本地 journal 临时文件，`fsync` 文件、原子 `rename` 并 `fsync` 父目录。收到并验证回执后，把回执原文和 digest 写回 journal，同样执行 fsync/rename/fsync。所有记录都使用唯一 operation ID。
6. 在本地 DB 事务中按 operation ID 唯一键写 `projection_pending` 记录，包含旧/新 epoch、完整身份 tuple、回执摘要和客户端高水位；只接受 DB 当前值仍等于审批预期值或同 operation 已写入的完全相同结果。
7. 将包含新 epoch、中心时间、身份 tuple、operation ID 和回执摘要的水位文件写入同目录临时文件，`fsync`，原子 rename 为正式文件，再 `fsync` 目录。随后 DB 事务核对 projection 与该文件内容一致并将投影标记 complete。只有 DB complete、文件 epoch/tuple/digest 相符且 journal 可解释时才恢复依赖可信时间的经营流程。
8. 重启后按 journal 状态幂等续做。DB pending 而文件未更新时继续投影；文件已更新但 DB 仍 pending 时完成 DB 投影；发现旧 epoch、不同 operation/receipt 或无法解释的分叉时 fail closed 并要求受审处理。清理 journal 只能发生在 DB 与文件读回一致之后。

这不是跨 DB 和文件系统的原子事务保证：journal 使崩溃后可判定和幂等续做；每个持久写必须 fsync，文件替换必须使用同文件系统原子 rename。客户端 DB schema、journal 代码、文件格式、恢复流程及故障注入验收仍需后续单独实现。本阶段没有声称已经完成客户端原子恢复。拥有 root 并能同步回滚程序、数据库、身份文件和系统时钟的操作者不在保证范围内。

## 验收覆盖

本阶段真实 HTTPS + 隔离 PostgreSQL 18 测试包含：

- 将客户端签名 `created` 人为偏移五年，确认现有 `/v1/challenges` 以 `HTTP_SIGNATURE_INVALID` 拒绝；再使用真实 HTTPS 时间锚和单调往返测量，在固定公钥验签后生成有效 RFC 9421 challenge。
- 时间锚的 nonce、公钥 pin、RTT 上限、body limit、独立限流、无业务副作用，以及中心 DB/进程时间源明显分歧时的 fail-closed 检查。
- 审批批准/撤销/过期，revision 与身份绑定；撤销或 revision 过期不消耗 challenge、不升 epoch。
- 单 operation 重放、同 operation 并发、不同 operation 竞争、响应丢失、PostgreSQL COMMIT ack 丢失、触发器真实 rollback 和 SIGKILL。
- license revoked/订阅过期仍可只恢复 epoch，但 status/订阅期不变且回执无经营授权字段。
- 真实正常迁移后，新 generation 从 epoch 0 开始；旧身份无法再次从中心重放旧 generation 的 reset evidence。已提交迁移的 operation 历史仍可查询，重放不再次迁移。
- 正常及灾难迁移审批自然过期边界：使用严格隔离的历史审批 fixture 与测试时间注入，不等待真实审批时长、不修改全局时钟、不改受保护的生产历史；Commit 拒绝、source activation 保持 active、generation 不变、准备计划按规则失效且没有成功迁移回执。

本地验收结果：`npm ci` 完成；`npm run typecheck`、`npm run build` 和 `git diff --check` 通过；`npm test` 的 unit/interop 19/19 通过；真实 PostgreSQL/HTTPS 集成 80/80 通过；`npm audit` 报告 0 vulnerabilities。原有 84 项全部纳入回归，本阶段增加 15 项。GitHub Actions 的精确 run 状态、推送 SHA 和临时 PostgreSQL 清理结果在最终交付记录中给出。所有测试私钥、许可证、数据库及故障 fixture 均为临时/隔离数据。
