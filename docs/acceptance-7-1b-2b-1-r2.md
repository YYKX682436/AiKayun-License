# ⑦-1B-2B-1 R2 验收证据

基于 R1 `9912ab2e20a794c9a373f8aa69be1628e5dd3678`，本轮只补迁移审批撤销的未知 COMMIT 与撤销/Commit锁竞争验收；没有商城或灾难迁移改动。

## 确定性故障和竞争控制

- `CommitAckDropProxy` 代理 PostgreSQL 协议，等待真实 COMMIT 的 `ReadyForQuery` 后丢弃确认并关闭连接。管理员服务随后以原 operation ID 查询已提交操作；断言返回 `replayed=true`，撤销投影、管理员操作及管理员审计均只有一行，原审批仍存在，prepared计划为 `invalidated`，旧ticket再次Commit被拒绝。
- 对撤销投影表安装临时 PostgreSQL BEFORE INSERT 故障触发器，验证事务回滚后没有撤销记录或管理员操作；移除触发器后用相同 operation ID 和摘要重试成功。
- 竞争测试先用独立事务持有 license 行锁，再按指定顺序启动撤销或 HTTPS Commit。测试观测到首个服务等待该行，再启动另一服务并观测两个 PostgreSQL 行锁等待会话后才释放门闩；未使用固定 sleep 决定先后。

## 最终数据库断言

- 撤销先获锁：恰有一条撤销事实和审批撤销事件；计划 `invalidated`；Commit 操作终态 `rejected`；原 activation 仍 active，generation/revision/entitlement revision 均不变。
- Commit先获锁：计划 `committed`；目标 activation 唯一 active、旧 activation `retired`；generation只加1；签名回执 `typ=aikayun-license-transfer+jwt`；Commit操作及迁移事件各只有一条。后续撤销是 `EXPECTED_REVISION_MISMATCH`，没有撤销投影；原 Commit operation 重放返回原回执。

## 验收命令

在提交时本地运行 `npm run typecheck`、`npm run build`、`npm test` 和 `LICENSE_TEST_DATABASE_URL=... npm run test:integration`。最终结果：18项单元测试、45项真实 PostgreSQL/HTTPS 集成测试通过。测试数据库为本地隔离 Docker PostgreSQL，使用临时license和临时Ed25519密钥；测试后删除该测试卷。

这些测试验证授权中心数据库事务和协议响应，不验证商城恢复器、业务数据、真实服务器切流或生产管理员部署。
