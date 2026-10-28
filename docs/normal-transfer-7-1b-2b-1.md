# ⑦-1B-2B-1：授权中心正常服务器迁移

## 范围与状态

本阶段只实现授权中心的正常迁移协议，从已验收基线 `b4667b631a9dfd80e2fde5c4c4f73c33bbc8d12e` 继续开发。商城协议按 `225600b55bbd91bcb7393097b7b5fd44a3465816` 和⑦-1A R3文档只读核对，没有修改商城仓库。

正常迁移表示把同一套商城恢复到目标服务器，不创建新 license 或新业务数据库。中心协议不验证备份文件/数据库内容，也不执行安装器、商城本地身份切换、文件 journal、支付/供应商切流或真实服务器迁移。

## 相对⑦-1A R3的身份强化

⑦-1A R3建议正常迁移“通常仍保留原 instance/key”。本轮改为目标服务器使用新生成的 Ed25519 实例身份私钥，且 `target_identity_jkt` 必须不同于来源 JKT。保留同一私钥无法在续签层可靠区分旧机器与新机器；仅升 generation 会让仍持有同一私钥的旧机器也能证明 possession 并尝试请求新 lease。

协议固定以下关系：

- `license_id`、商城逻辑 `instance_id` 和 `database_id` 保持不变。
- 来源身份必须是当前 active activation；目标身份必须是管理员批准的不同 JKT。
- 目标 JKT 在该 license 的 activation 历史中不得出现，防止 A→B→A；此规则只约束正常迁移，不建立阻断灾难迁移身份恢复的全局唯一约束。
- 成功 commit 时 `activation_generation` 严格加 1，来源 activation 变为 `retired`，目标 activation 是唯一 `active`。
- 中心管理 `revision` 加 1；`entitlement_revision`、套餐、订阅截止时间和 license 状态不变。迁移不续费、不消耗激活码。
- 订单、资金、业务 UUID、历史解密密钥及业务数据库/文件不在授权中心；本轮不修改这些商城事实。

`expected_binding_revision` 是审批所绑定的商城侧声明值。中心既不知道客户数据库真实内容，也无法验证本地 revision；该字段只是协议证据，后续商城恢复器仍须读取并检查本地 binding、数据库和文件。中心回执不是数据真实性证明。

## 管理员审批

`license approve-transfer` 复用⑦-1B-2A受控管理会话、OS UID/database role身份、operation ID、不可变请求摘要、双步确认、管理审计和 license 行锁。摘要绑定 license、原 database/instance/JKT/generation、目标 instance/JKT、当前 expected 管理 revision、expected binding revision、原因和操作身份。

审批有效期为24小时，审批行和管理操作结果不可变。成功审批本身不改 license revision、entitlement revision、generation 或 activation。有效审批要求许可证 active 且未过期，来源仍为当前 active activation，revision/generation 与审批时一致。续费、撤销、恢复、其他管理revision变化或generation替换后，旧审批不能继续使用。一个 license 同一revision最多保留一个有效迁移审批。

`license revoke-transfer-approval` 以独立 operation ID、审批 ID、原因、expected revision 和同一受控管理员两步确认来撤销。不可变撤销投影和审计记录保留原审批历史；撤销不改变 license revision、权益、订阅或 activation。Prepare 与 Commit 在 license 行锁内复查撤销投影，旧 prepared ticket 失效；撤销与 Commit 由同一行锁决定先后。已提交迁移不可被撤销回滚。撤销后允许对新目标密钥重新审批。

现有管理 CLI 保持 `isolated-development` 和 loopback 数据库限制；`NODE_ENV=production` 继续拒绝启动。没有正式管理员 MFA、公网管理入口或生产部署，因此迁移审批与本轮端点只允许隔离测试/受控开发，不能宣称可直接用于生产。

## 两阶段协议

### Prepare

`POST /v1/transfers/prepare` 由当前 active 来源私钥完成 HTTP 持钥签名。RFC 9421签名覆盖HTTPS目标、方法、Content-Type和RFC 9530原始body digest；challenge/nonce绑定 operation ID、intent digest、instance和JKT。intent digest使用RFC 8785固定字段规范化，`request_digest`仍按原始body bytes计算。

请求必须绑定审批中的全部来源/目标字段。中心重新检查当前 activation、数据库ID、代次、管理revision、许可证 active/订阅截止和审批有效期。目标instance必须等于来源逻辑instance；目标JWK thumbprint须等于审批目标且不同于来源JKT。

通过后中心签发独立 `typ=aikayun-license-transfer-ticket+jwt`，有效期600秒，绑定审批ID、prepare operation/intent/request摘要与nonce、source/target身份、license/database、原generation、管理revision、binding revision和权益revision。ticket不含经营grants，不能按普通lease使用，也不能单独改变activation。Prepare只写计划、operation、nonce/attempt和审计，不修改active activation或任何revision。

同一个prepare operation以新challenge和递增attempt续接时返回原ticket。另一个operation不能在同一license创建并行有效计划。过期计划先被审计为 `expired` 后可重新prepare；若审批/revision/来源已变化，计划记为 `invalidated`。ticket过期且从未commit时，来源activation仍active。

### Commit

`POST /v1/transfers/commit` 必须同时提供有效ticket和目标新私钥的HTTP持钥签名。仅有ticket字符串不够。中心验证ticket签名、type、claims、目标JKT、公钥、审批和计划记录。

成功路径在一个PostgreSQL事务内完成：

1. 获取稳定commit operation advisory lock和license行锁，按既有服务约定再取logical instance advisory lock。
2. 锁定并核对ticket计划、审批和来源activation；按数据库时间重验active状态、订阅截止、generation、entitlement revision及expected管理revision。
3. 退役旧activation，插入同license、同instance、同database的新generation active activation；保留既有license/instance唯一索引保护。
4. generation和管理revision各加1，entitlement revision和订阅截止不变；用目标JKT签发标准新lease。
5. 签发独立 `typ=aikayun-license-transfer+jwt` 正式迁移回执，嵌套目标lease并包含issuer/audience、operation/intent/request nonce及digest、来源/目标身份、database、旧/新generation、expected binding revision、旧/新管理revision和权益revision。
6. 同事务保存不可变commit operation结果、attempt、授权审计、迁移生命周期事件及ticket消费事实，然后提交。

任何事务中途失败都回滚以上全部变化。实例表继续由部分唯一索引保证同license最多一个active、同instance最多一个active；迁移先在事务内retire来源再插入目标。迁移后新的active activation和更高generation仍受这些约束。

### 幂等与未知结果

prepare和commit使用现有 `operation_id`、`intent_digest`、request nonce及append-only attempt。网络超时或COMMIT确认未知时，客户端必须保留原operation身份和业务intent：相同commit operation重试会返回原始回执；`/v1/operations/query` 可用目标JKT、原commit operation ID和intent digest查询已提交结果，即使ticket后来到期。不能因结果未知而新建迁移operation或再次prepare。

一个已提交ticket以其他commit operation重放会被拒绝，generation不会再次提高。审批过期、ticket过期或审批绑定的revision/代次变化都不能提交。审批或ticket尚未commit时，旧activation保持active。

中心只围栏后续续签：迁移后原私钥以旧generation续签得到绑定原身份的签名 `superseded` 状态，不能取得新generation lease；新私钥只在对应新active activation下续签。此前签发的旧lease不会被中心远程删除，旧机器离线时仍可能在旧lease `exp` 前本地有效。

## 后续部署工具必须遵守的迁移前置检查契约

本轮不实现迁移安装器或切流，但后续工具及运维流程必须先满足以下条件：

1. 暂停旧API全部写入入口，并停止所有写入worker、定时任务、消息消费者和异步dispatcher；仅停网页/API进程不算停写。
2. 在一致的静止点制作并校验完整备份集，至少包含业务数据库、历史业务解密密钥、媒体、全部私有文件、实例身份/私钥、license binding和必要配置。备份必须可恢复，不能只复制PostgreSQL。
3. 目标先在网络隔离环境恢复，阻断真实支付渠道、退款/提现和供应商出站访问，不得拿恢复副本对真实服务商重放操作。
4. 支付unknown、退款、提现、供应商未决操作要保留原业务身份、幂等号和凭据，恢复后按原渠道查单与对账；不因license generation变化而重建或丢弃历史执行身份。
5. 回调域名切换前，确认旧域名仍可能收到支付商迟到/重试回调，并准备能按原签名、原商户配置将回调送到同一恢复业务库或进入安全对账队列的方案。不能假设改DNS后旧请求立即消失。
6. 迁移commit前确认旧主机、旧容器、旧worker和旧业务卷已停机/隔离；授权中心generation不是物理fencing，也不能停止旧机器运行历史worker。
7. 目标侧完整核对数据库与身份key、媒体/私有文件、binding revision、未决资金和履约状态后，才允许后续商城恢复器应用正式回执并恢复出站。切流步骤、回切和支付回调保留期需要单独验收。

未满足上述条件时，迁移只能保持来源active并停止在prepare之前或等待人工处理。若commit已成功但目标本地应用未完成，按原operation查询/恢复；不能反向降低中心generation。回切必须作为另一次受控迁移递增generation。

## 数据迁移和验收边界

`001_core`、`002_admin_operations` 与 `003_normal_transfers` 未修改。本轮以追加迁移 `004_transfer_approval_revocations` 保存审批撤销投影并扩展管理员动作。迁移审批、ticket、正式回执和测试代码均不接入商城仓库。

真实PostgreSQL/HTTPS集成测试使用临时许可证、临时Ed25519实例key、临时中心签名key和本地测试数据库；不使用真实生产许可证、真实业务私钥或商户数据。进程强杀、HTTP响应丢失和PostgreSQL COMMIT确认丢失均在隔离测试数据库演练。此中心端验收不等于商城本地文件/DB恢复、生产管理员认证或真实服务器切流验收。
