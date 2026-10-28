# ⑦-1B-2B-2：授权中心灾难迁移协议

## 范围、信任边界与相对⑦-1A R3的补充

本阶段只实现授权中心的灾难恢复审批和两阶段身份接管，不修改商城仓库。灾难迁移用于来源私钥遗失/不可信、旧实例不能完成持钥证明的情况。它不使用正常迁移的来源签名，也不代表数据恢复成功。

⑦-1A R3曾将迁移完成描述为返回新 lease。本阶段将该行为收窄为按当前权益状态返回两种不同结果：只有 `license.status=active` 且当前订阅截止时间仍在未来时，灾难迁移回执才嵌套正常经营 lease；过期或已撤销的许可证只返回身份重绑证据。身份重绑不续费、不解除撤销，也不赋予新订单权限。客户端必须根据严格 JWT `typ` 分流，不得把绑定证据当 lease。

授权中心只能验证 Ed25519 持钥事实、签名挑战/请求、管理员受控操作上下文、许可证当前数据库状态和自己保存的迁移历史。审批中的联系人核验、备份检查、旧服务器隔离、事故原因及核验记录引用都是管理员完成外部工作的审计声明；授权中心无法证明操作者实际联系了客户、备份可恢复、数据库内容真实或旧机器已经停机。`database_id` 是中心与商城本地 binding 的关联字段，不是数据库真实性证明。持有或猜到 license/database UUID、激活码、旧域名、用户邮箱或付款截图都不会得到恢复授权。

若原业务数据库、历史解密密钥或履约/资金所需数据永久丢失，不得创建空数据库并复制原 `database_id` 冒充恢复。那是需单独人工处理的数据丢失事件，不是授权中心迁移。

## 身份与权益不变量

- `license_id`、原 `database_id` 保持不变；中心从当前 active activation 读取来源 database，而不是相信请求自行指定的 database。
- 可保留原逻辑 `instance_id`。仅在身份资料确实丢失并由管理员明确批准时，才允许换新 `instance_id`。新 ID 在 commit 时不能与其他许可证的 active activation 冲突。
- 目标必须以新生成的 Ed25519 私钥发起请求；目标 JKT 必须不同于该 license 所有当前和历史 activation JKT。审批绑定目标 JKT 与 instance ID，Prepare 和 Commit 都核对该绑定。
- 每次成功 commit 严格增加 activation generation 与中心管理 `revision` 各 1。`entitlement_revision`、套餐、订阅截止、撤销状态、激活码行均不因迁移改变。原 activation 行保留并转为 `retired`，新目标成为唯一 active activation。
- 灾难迁移审批允许已过期或 revoked 的 license，以便人工审批恢复旧订单、退款、提现或交付所需身份。状态 `unknown`、数据库读失败、签名结果不能安全确定时 fail closed，不签发任何经营凭证。

## 管理员灾难申请、审批及撤销

使用已有受控本机管理员 CLI、allowlisted OS UID、PostgreSQL `session_user`、稳定 operation ID、当前 expected revision、请求摘要双步确认和不可变管理审计。管理员实际 OS UID、OS 用户名、数据库 role、请求摘要、理由、来源/目标身份、事故类型、核验引用、备份检查结果、旧机隔离声明及有效期都进入审批/审计事实。request 与 approval 是分开的不可变表记录，并通过管理 operation 关联。

`--verification-record-ref` 仅接受类似 `case:IR-123`、`ticket:...` 或 `audit:...` 的外部记录引用格式，内容仍由管理员负责核验。它不会自动验证邮箱、域名、付款截图或身份文件。

`--backup-check-result` 必须明确选择：

- `database_identity_and_history_reviewed`：管理员声明已检查数据库身份与历史资料。
- `identity_material_missing`：管理员声明部分身份资料已丢失；这不证明业务数据库及历史解密材料仍完整。
- `unable_to_verify`：审批被拒绝。

`--old-server-isolation` 必须明确选择 `confirmed_isolated`、`unknown` 或 `not_confirmed`。后两种值会原样审计；它们不是通过迁移获得的隔离。旧服务器可能仍运行订单 worker 或持有有效的历史 lease，因此任何后续真实切流前都必须另行完成旧机器/容器/worker及出站路径隔离、恢复资料核对和未决资金/履约查单。授权中心 generation 不是物理资金或执行隔离。

审批默认为24小时，可指定1至72小时。撤销使用独立 operation ID，追加不可变撤销记录，并在同一 license 行锁下将已准备的灾难计划标记 `invalidated`。不能删除、改写或复活原审批；更换目标 JKT/instance 必须撤销旧审批，再以新请求重新审批。续费、撤销、恢复或其他改变 management revision 的操作会令旧批准失效。

现有 CLI 的 `NODE_ENV=production` 禁用和 loopback/UID/DB-role 限制保持不变。本阶段没有真实管理员 MFA、客户身份核验系统或公网管理员接口；审批功能只适用于隔离测试与受控开发，不能宣称已经具备可直接商用的灾难找回能力。

## RFC 9421两阶段接口

两个灾难端点与正常 `/v1/transfers/*` 完全隔离：没有来源私钥证明，也不接受正常迁移 ticket。新目标私钥是唯一实例签名者；中心管理员审批是独立条件，二者缺一不可。

### Prepare：`POST /v1/disaster-transfers/prepare`

目标私钥对新 challenge 和完整 HTTPS 请求签名。RFC 9421/RFC 9530 验证覆盖方法、目标 URI、Content-Type 和收到的原始 body digest。challenge/nonce、intent digest、operation ID、instance ID、JKT 和 raw body request digest 都进入既有 operation/attempt 链。

Prepare 核对审批/request/admin operation 的摘要与状态、license 当前 account、来源 activation ID/instance/JKT/database/generation、目标 instance/JKT、expected 管理 revision、expected 本地 binding revision、权益 revision、审批有效期和撤销事实。目标 JKT 必须与签名公钥 thumbprint 一致、且未出现在该 license activation 历史。换 instance 时会核对全局 active instance 冲突。有效正常迁移审批或 prepared ticket 必须先通过原管理流程撤销或处理；不会静默绕过。

通过后签发不超过600秒的独立 `typ=aikayun-license-disaster-transfer-ticket+jwt`。ticket 严格限定 claim 集合并绑定 approval/request、来源与目标、数据库、原 generation、expected 管理/binding revision、权益 revision、prepare operation/intent、nonce、请求摘要和签发/到期时间。ticket 不含 grants、不是 lease，也不能单独改变 activation。Prepare 不退役来源、不增 generation/revision、不签经营授权。

同一 prepare operation 用原 intent、目标身份和新的有效 challenge/递增 attempt 重放时返回已存原 ticket。不能借原 approval 创建并行 plan；plan 的一条 `prepared` 部分唯一索引与 license 锁共同阻止竞争。ticket 到期后可在有效审批仍适用时另建 prepare；已撤销审批、revision 变化或来源替换不能继续。

### Commit：`POST /v1/disaster-transfers/commit`

目标私钥再次对独立 commit challenge/request 签名，并提交原 prepare operation 的 ticket。提交前严格验证 ticket `typ`、签名、时效、完整 claim schema、目标公钥及数据库内 plan/ticket digest 的完全一致。普通 challenge/lease/正常迁移票据不能替代灾难票据。

Commit 使用既有 operation advisory lock 后锁定 license 权威行，再按需要获取目标逻辑 instance advisory lock；在同一事务中锁定计划、审批及来源 activation，并重验审批未撤销/过期、来源仍 active、generation/revision/权益 revision仍匹配、ticket未过期/消费、目标 ID/JKT未冲突。所有正常迁移、灾难迁移、撤销、恢复、续费均通过同一 license 行锁串行化。

成功事务原子执行：

1. 将来源 activation 标记 `retired`。
2. 插入同 license、同原 database、新 target identity/new generation 的唯一 active activation。
3. generation 与管理 revision 各加1；保留 entitlement revision、套餐、订阅截止及 revoked/active 状态。
4. 若权益当前 active 且订阅未过期，签发正常 `aikayun-license+jwt` lease 并嵌入正式迁移回执。
5. 若订阅过期或 license revoked，只签 `typ=aikayun-license-disaster-binding+jwt` 身份恢复证据；无 `grants`、无 `new_lease`，并写明 `purpose=historical_obligations_only` 和当前状态。
6. 同事务写入 commit operation墓碑/结果、ticket消费（plan从`prepared`单向转`committed`）、request attempt、管理审计/授权审计和迁移事件，然后提交。只有数据库事务成功提交后才返回。

若事务触发器失败或进程被强杀，来源退休、目标插入、license revision、operation、ticket消费、attempt与审计全部回滚。若 PostgreSQL COMMIT确认或 HTTP 响应丢失，同一 commit operation ID + intent 重放返回保存的原签名结果，不再次增加 generation。结果已未知时不得另建 commit operation。

## JWT用途与恢复规则

| `typ` | 用途 | 可带经营 grants |
| --- | --- | --- |
| `aikayun-license-disaster-transfer-ticket+jwt` | 目标持钥的短期 commit 票据 | 否 |
| `aikayun-license-disaster-transfer+jwt` | active、未过期权益下的正式迁移证据 | 内含单独签发的标准 lease |
| `aikayun-license-disaster-binding+jwt` | expired/revoked 时身份重绑/历史义务证据 | 否；不得含 `grants` 或 `new_lease` |
| `aikayun-license+jwt` | 标准当前经营 lease | 是，且需当前有效权益 |

上述用途由固定 Ed25519 protected `typ`、精确 claim allowlist 和独立验证函数约束。绑定回执的短时 JWT 可作为当次恢复响应；即使保存为历史证据，它也不能产生后续 lease。订阅之后由管理员合法续费，或撤销之后由管理员合法恢复，必须通过现有权益操作推进权益/管理 revision，再由新 active identity 正常调用 lease renew；旧 binding-only 回执不会升级。

成功替换后旧 activation generation 已落后；来源身份请求新 lease只能取得签名 `superseded` 状态，不能得到新 generation lease。目标身份在权益仍有效时可正常续签。普通 `/v1/operations/query` 仍要求 operation 原 actor JKT；不会因为身份替换就向任何新 identity 开放历史 operation。commit 恢复通过不可变 plan/approval/operation 绑定和原 target JKT完成。

## 实际数据库锁顺序与 operation 生命周期

```text
challenge：验证签名 → 单独事务 INSERT request_nonce
  │
  ├─ 管理审批/撤销：admin-operation advisory → license FOR UPDATE
  │                 → 来源 activation / target-instance advisory（需要时）
  │                 → approval / plan 行 → operation + 审计 + events → COMMIT
  │
  ├─ 灾难 Prepare：operation advisory → license FOR UPDATE → target-instance advisory
  │                → consume nonce → approval/request/source 检查 → plan 行/唯一约束
  │                → ticket + prepare operation + attempt + 审计 + event → COMMIT
  │
  └─ 灾难 Commit：operation advisory → license FOR UPDATE → target-instance advisory
                  → plan FOR UPDATE → consume nonce → approval FOR UPDATE → source FOR UPDATE
                  → retire/insert activation + generation/revision CAS + signed result
                  → commit operation + ticket state + attempt + 审计 + event → COMMIT
```

关键串行点是共享 `licenses` 权威行：迁移 commit、正常迁移 prepare/commit、灾难审批/撤销、续费、license revoke/restore 均先在各自操作 advisory lock 后取得同一 license 行锁，再触碰路径各自的 activation/approval/plan/权益记录。请求 nonce由已经验证的挑战建立；业务事务在记录 attempt 前消费 nonce。所有业务写入与结果共同提交，失败则共同回滚。instance advisory 锁解决不同 license 争用同一个 target instance ID；数据库 active 唯一约束仍作为最终防线。

事务外状态：Challenge issued（nonce 未消费）。事务内状态：Prepared（仅 ticket/plan）或 Commit mutation。提交后终态：Committed（原 operation 与回执可重放，generation只加一次）；校验失败可保存 Rejected operation；网络错误/强杀/事务回滚不形成部分授权状态。审批状态为 Approved →（可选）Revoked 的只追加投影；审批到期由数据库时间判断。plan状态仅允许 `prepared → committed | expired | invalidated`。

## 真实切流前置检查契约

授权中心代码不执行这些外部步骤；任何真实切流/恢复器必须独立完成人工复核：

1. 明确停止并隔离旧服务器、容器、worker、定时器、消费者及对真实支付/供应商的出站访问。旧机存活不确定时，双执行风险仍存在。
2. 在一致的静止点确认恢复的是原业务数据库及其 database binding，恢复历史解密密钥、媒体/私有文件和必要配置。仅 UUID 相同不能证明内容相同。
3. 逐项查询未决支付、退款、提现、订单交付和供应商操作，沿用原业务身份与幂等号对账，不随迁移重放真实操作。
4. 核对商城 binding revision 和签名响应用途。active 回执才携带正常 lease；binding-only 结果只能恢复历史身份，不得开启新订单。
5. 在所有复核/隔离项通过前停止在目标环境，不进行DNS切流或外部写操作。旧 lease 在有效期内无法远程删除，license generation 不能终止离线旧 worker。

商城端本地 binding/key recovery、密钥文件journal、备份工具、DNS、支付对账、time-reset、中心签名密钥轮换及生产运维均不在本阶段范围。
