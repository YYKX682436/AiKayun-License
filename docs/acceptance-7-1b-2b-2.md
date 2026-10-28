# ⑦-1B-2B-2 灾难迁移独立验收报告

## 交付边界

本阶段只修改授权中心仓库。商城仓库只读。本地代码在冻结基线 `e3f64c729c42abad4308245b11c2aee336d0f241` 上追加 migration `005_disaster_transfers`；`001_core` 至 `004_transfer_approval_revocations` 未改写。完整协议、实际锁序、JWT用途和切流前置契约见 [`disaster-transfer-7-1b-2b-2.md`](disaster-transfer-7-1b-2b-2.md)。

交付包括受控管理员灾难恢复申请/批准/撤销 CLI、不可变审批/撤销/计划/生命周期审计表、目标新私钥签名的 disaster prepare/commit HTTPS接口、独立严格 JWT ticket/active回执/binding-only回执、原 operation/nonce/attempt/审计幂等以及真实 PostgreSQL + HTTPS 集成验收。正常迁移现有实现与验收路径完整保留。

## 确定性验收覆盖

- 无审批、跨 license 审批、错误数据库、过期 revision、替换目标 JKT 均不能 Prepare；审批快照与当前 activation 不符也会拒绝。
- 目标必须使用审批指定的新 Ed25519 JKT；同 license activation 历史 JKT 不能重用。替换逻辑 instance 时，其他 license active instance 冲突会拒绝。
- 成功接管保留 license ID、account、原 database ID、套餐、订阅截止、激活码和 entitlement revision；generation 与管理 revision 各增加一次，原 activation 退休，目标唯一 active，完整历史 activation 保留。
- 有有效正常迁移批准/plan时灾难审批拒绝；正常迁移旧 ticket先撤销/失效后仍不能在灾难接管后提交。灾难批准有效时新的普通迁移审批被拒绝。已撤销目标审批不可复活，替换目标需新审批。
- disaster prepare/commit均经过真实 TLS HTTP RFC 9421签名、中心 challenge、nonce、intent/raw body digest、递增 attempt 和数据库 operation 状态校验。错误签名、旧 attempt/challenge、正常迁移 ticket跨用途、重复消费 ticket 均拒绝；相同 commit operation重放返回原结果且 generation 不再增加。
- HTTP Prepare/Commit响应丢失及 PostgreSQL COMMIT确认丢失后，按同一 operation 恢复原 ticket/回执。触发器造成的事务回滚和子进程 SIGKILL 均不留下半迁移状态；释放数据库锁后同 operation可成功重试。
- 使用真实 PostgreSQL锁等待观测和测试门闩确定事务先后，覆盖灾难 Commit 与 revoke/restore/renew两种获锁次序，以及正常迁移 Commit 与灾难审批两种获锁次序。无需固定 sleep决定胜负。
- 接管后旧 key续签得到 `superseded`；新 active key在当前权益有效时正常续签。到期或 revoked 权益只获得 `aikayun-license-disaster-binding+jwt`，没有 grants/new lease；正式续费/恢复后通过正常续签取得新 lease。
- `unable_to_verify` 备份声明拒绝审批；可用测试证明管理员声明与中心密码学验证的边界分离。

## 本地验证结果

最终验证命令及结果：

```text
npm run typecheck                     PASS
npm run build                         PASS
npm test -- --reporter=dot            PASS — 4 files, 18 tests
LICENSE_TEST_DATABASE_URL="$TEMP_PG18_URL" npm run test:integration -- --reporter=dot
  PASS — 4 files, 58 tests
```

集成验收使用本地一次性 PostgreSQL 18 容器和独立测试数据库；容器使用 `--rm`、只映射 loopback 随机端口、没有挂载任何数据卷。HTTP服务启用临时 TLS 证书，中心签名key与每个实例 Ed25519 key均为临时测试key。测试没有连接商城数据库、生产授权、商户支付、供应商或客户业务服务。完整单元和集成测试合计76项通过，其中原有集成用例完整回归。

## 未完成事项与限制

- 当前本机管理员 CLI仍受 allowlisted OS UID、独立 PostgreSQL role、loopback和 `NODE_ENV=production` 禁用限制。真实生产 MFA、正式客户身份核验系统、公网管理员入口均未实现。
- 联系人核验、业务数据库和密钥备份完整性、旧服务器/worker隔离都是不可由授权中心证明的人工声明。批准或 commit不证明历史订单、付款、退款或履约数据真实。
- `database_id`只是绑定标识。若业务数据库或历史解密key永久丢失，不得用空数据库复制 UUID 伪造恢复。本阶段没有商城本地 binding/key journal、备份工具、DNS切流、资金对账、time-reset或生产运维。
- license generation只围栏后续中心签发，不是物理资金隔离；旧机器可能仍持有未到期 lease或运行离线 worker。任何真实切流前必须完成旧机隔离、历史密钥和数据核对、未决资金/履约查单及目标环境出站限制。

本报告只证明隔离测试和受控开发环境下的授权中心协议与事务行为。它不声明已具备可直接商用的灾难找回服务。完成⑦-1B-2B-2后停止，等待严格验收；不开始⑦-1B-2B-3或商城客户端实现。
