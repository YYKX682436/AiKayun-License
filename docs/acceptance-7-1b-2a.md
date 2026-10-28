# ⑦-1B-2A 授权中心管理操作内核交付与验收报告

## 范围与基线

本阶段从授权中心基线 `aa90eb2a357075ec93fb84cc8c3e0d7697a8fa1e` 开始，只在 `/Users/muchen/Documents/ChatGPT/AiKayun-License` 实现本机受控管理员 CLI、独立管理服务、追加迁移、测试和文档。已审阅商城仓库 `AGENTS.md`、⑦-1A R3 四份协议/生产架构/审计/验收文档及授权中心 ⑦-1B-1 R1 报告。商城仓库仅作只读参考，没有业务代码变更；没有真实生产授权或部署。

新增迁移 `002_admin_operations` 建立管理员操作及管理审计表，并为激活码增加不可逆作废状态与每许可证单个未消费、未作废码的唯一约束。⑦-1A R1 报告记录 `001_core` 尚未进入生产，因此本次保留 `001_core` 不变，使用可重放的追加迁移。迁移不自动创建生产管理员账号或应用数据库权限。

## 已实现行为

- 本机 CLI 提供月/年许可证创建、一次性激活码签发/作废重发、续费、撤销、恢复，以及许可证/实例、操作和审计查询；没有公网管理员 HTTP 路由。
- CLI 身份由 POSIX effective UID/用户名和 PostgreSQL `session_user`/`current_user` 分别取得，并按私有策略文件校验。命令备注不是身份材料，不接受 `actor` 参数；只连接 loopback PostgreSQL，`NODE_ENV=production` 会拒绝启动。当前没有管理员 MFA，因此仅供隔离测试与受控开发运维，不能作为正式生产或远程管理方案。
- 写命令要求固定 operation UUID、明确目标、预期 revision、原因及对规范化请求摘要的第二步人工确认。操作 ID 通过 PostgreSQL advisory lock 串行化；同 ID 同请求/身份读取原结果，同 ID 不同请求或执行身份拒绝。提交结果未知时查询原 ID，不自动生成另一个 ID。
- 管理操作行、管理审计、必要的授权审计/权益事件和许可证更新在同一事务提交。管理员操作与审计只追加，直接 `UPDATE`、`DELETE`、`TRUNCATE`（含 `CASCADE`）被拒绝。
- 月/年首账期使用数据库 UTC 时间、固定 UTC 锚点和现有日历算法。续费复用现有锁序与 `applyConfirmedRenewal`，要求人工确认业务事实；不连接收款渠道，也不把备注当成付款证明。
- 激活码使用 Node.js `crypto.randomBytes(32)`，数据库只存摘要；明文不进入操作结果、数据库审计或查询。CLI 仅在提交成功后且 stdout 为 TTY 时显示一次。明文输出未知/丢失后不可查询恢复，只能查询旧 operation，再基于当前 revision 用新 operation 明确作废并重发；消费、过期和作废代码均不能再次使用。
- 发码、作废重发、正常续费、撤销和恢复都按许可证管理 revision 做 compare-and-swap。撤销/恢复只变更 `active ↔ revoked` 并推进 `revision` 与 `entitlement_revision`；保留截止时间、generation、激活实例、数据库绑定、identity thumbprint、激活码和历史签名。恢复不会绕过到期时间；续费也不会清除 revoked。
- 继续复用现有 lease 规则 `exp = min(iat + 7 天, subscription_end)`；集成测试断言签名 lease 不超过七天且不跨越订阅截止。商城客户端离线缓存/断网时的行为不在授权中心仓库内，本轮未替商城作出该项验收声明。

## 本地验证结果

| 检查 | 结果 |
| --- | --- |
| `npm run typecheck` | 通过 |
| `npm run build` | 通过 |
| `npm test` | 17/17 通过 |
| 真实 PostgreSQL + HTTPS `npm run test:integration` | 28/28 通过 |
| 合计 | 45 项通过；⑦-1B-1 的原 30 项完整回归通过，并新增 15 项测试 |
| `git diff --check` | 通过 |

管理集成测试实际执行迁移并核验 PostgreSQL 中的已提交状态、唯一约束、不可变触发器和操作/审计行；通过真实 TLS HTTP 服务核验签名的 revoked、restored、expired、superseded 响应与 lease。另覆盖月/年许可证、激活码哈希/一次显示/重放/过期/作废重发、revision 单调性、发码与许可证操作并发 CAS、renew/revoke 冲突、未知 COMMIT 确认后的原操作恢复、环境 actor 伪造、错误 UID/数据库角色、没有管理员 API、审计变更与清空拒绝，以及到期恢复、旧签名状态回执乱序不改变较新数据库状态。

| GitHub Actions CI | `d3a8914ed4afcec4052c847e20a715910614301e` 的 run [`40700827363`](https://github.com/YYKX682436/AiKayun-License/actions/runs/40700827363) 通过；PostgreSQL 服务初始化、`npm ci`、类型检查、构建、17 项单测及 28 项真实 PostgreSQL 集成测试均通过 |

CI 仅报告了 runner 对 `actions/checkout` / `actions/setup-node` 的 Node.js 20 弃用提示，以及 `ubuntu-latest` 将迁移到 Ubuntu 26 的提示；步骤均成功。这些提示不影响本次验证结果。

## 边界与未验证项

- 没有真实支付、真实生产授权、线上数据库或生产部署；续费仅是受控人员依据独立人工业务核实所做的记账操作。
- 没有管理员 MFA，也没有公网管理入口；本阶段不宣称达到正式生产管理员安全标准。
- 没有修改 AiKayun 商城客户端、离线授权投影、支付、订单或履约逻辑；商城客户端投影/乱序回执处理仍需在相应后续阶段单独实现并验收。本测试证明中心实际返回的签名证据及中心数据库状态。
- 没有实现实例迁移、灾难迁移、time-reset、换钥/密钥轮换，也没有生成或提交正式商业签名私钥。
- PostgreSQL 表所有者或超级用户仍可修改 DDL、移除触发器或更改数据；本轮通过本机身份、独立角色配置边界和数据库追加保护约束管理服务，不把数据库超级用户视为可由触发器限制的对手。
- 本地测试使用隔离凭据和本轮新建的 PostgreSQL 测试卷；既有 Docker 卷及商城目录未清理或改动。

本报告是实现方的证据记录，最终严格验收由用户进行。本阶段交付后即停止，不自动开始 ⑦-1B-2B。
