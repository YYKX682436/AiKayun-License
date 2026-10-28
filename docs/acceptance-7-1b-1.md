# ⑦-1B-1 授权中心验收记录

## 验收边界

本记录对应独立私有仓库中的 ⑦-1B-1 服务端基础闭环。实现依据为 AiKayun ⑦-1A R3 协议；没有改动商城代码、订单、支付、履约或经营门禁。没有部署到公网或生产环境。

AiKayun ⑦-1A 审定基线：`225600b55bbd91bcb7393097b7b5fd44a3465816`。

## 本地结果

验收环境：Node.js 24.22.0；Docker PostgreSQL 18 镜像按 digest 固定；测试数据库与 API 请求均为本地隔离数据。测试私钥、TLS 证书、license、激活码与权益事件均临时生成。没有使用真实商业授权、商户凭据或线上数据库。

| 命令/套件 | 结果 |
| --- | --- |
| `npm run typecheck` | 通过 |
| `npm run build` | 通过 |
| `npm test` | 12 项通过：RFC/HTTP 签名互操作 7 项、UTC 账期 3 项、安全启动配置 2 项 |
| `npm run test:integration` | 14 项通过：真实 PostgreSQL 迁移、HTTPS/RFC 9421 请求、签名 JWT 回执和数据库状态断言 |
| 总数 | 26 项测试通过；没有依赖固定 sleep 推测锁顺序 |
| GitHub Actions | GitHub 创建了 push workflow run，但拒绝启动 runner；没有任何代码步骤执行，不能据此判定 CI 通过或测试失败 |

集成测试包括：

1. 首次激活、签名 lease 字段精确校验、激活码/nonce 原子消费。
2. 相同操作的提交重放、正文意图冲突和防止二次消费。
3. 对已提交操作的原始正文与签名目标篡改拒绝；状态和 attempts 不变。
4. 不同签名身份不能读取已知操作或改变其 attempts。
5. 两个实例争用同一许可证，使用 PostgreSQL 行锁等待状态确定并发顺序。
6. 同一 operation 并发重试，使用 advisory lock 等待状态断言唯一业务结果。
7. query `not_found` 不构成永久围栏；continue 使用同一 operation 完成一次激活。
8. 新 challenge/continue 成功后，迟到的过期 challenge 不能再次提交。
9. 已过期的历史 lease 在仍有效订阅上恢复最新 revision，不提高 generation；重复权益事件不重复延长。
10. revoked 与 superseded 只返回签名状态，不签发恢复 lease。
11. 数据库拒绝修改终态 operation、attempt、审计事件，且拒绝复位已消费的激活码和 nonce。
12. 通过 HTTPS 响应丢弃代理丢弃已提交激活的真实 HTTP 响应；原 operation continue 可取回原结果。
13. 通过 PostgreSQL 协议代理丢弃 COMMIT 确认，产生未知提交结果；原 operation 可恢复已提交 lease。
14. 强制终止服务进程，观察实际 PostgreSQL 行锁等待会话，再终止该会话以确定性完成回滚；重启服务后 continue 原 operation。

TLS 集成测试使用短期自签名证书，客户端测试工具允许该临时证书。测试证明 API 的实际连接使用 TLS，不证明外部生产证书链、域名或反向代理部署配置。

## 标准互操作验证

- Ed25519 JWS 使用 `jose` 的 RFC 9864 `Ed25519` 标识签发与验签；拒绝 JOSE `EdDSA` 回退及错误曲线。
- RFC 9421 Appendix B.2.6 Ed25519 签名向量由选定 HTTP Message Signatures 库成功验证，错误 key 被拒绝。
- RFC 9530 Appendix D SHA-256 `Content-Digest` 向量与预期字节一致，正文变化被拒绝。
- RFC 7638 已发布 RSA JWK Thumbprint 向量匹配。
- 本服务 profile 对身份/JKT、算法、nonce、原始正文摘要、签名目标和严格 JSON 重复键拒绝路径均有断言。

参考： [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html)、[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)、[RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html)、[RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html)。

## 数据库与安全断言

核心迁移创建 `licenses`、`license_activations`、`activation_codes`、`request_nonces`、`license_operations`、`license_operation_attempts`、`entitlement_events` 和 `license_audit_events`。数据库用部分唯一索引约束 active license/instance；操作只能插入完整终态；operation、attempt、权益事件与审计事件使用不可变/只追加触发器；激活码与 nonce 只能一次转为 consumed。业务更改通过事务 advisory lock 和 license 行锁串行化。

HTTP 日志关闭，异常回执只返回稳定错误码；签名私钥、TLS 私钥必须来自独立文件且权限不宽于 0600。生产缺少任一密钥、TLS key 或证书会拒绝启动。非隔离环境只允许 loopback 监听；本地 Compose API 端口仍映射到宿主机 loopback。

## 未完成与未验证

- 未实现中心管理员界面、支付/人工确认事件入口、取消、transfer、灾难迁移、time-reset、完整后台或密钥轮换。
- 未实现商城客户端、授权本地投影、最终经营事务门禁；不据此宣称商城已受授权保护。
- 未执行生产部署、正式证书/域名验证、外部反向代理互操作、备份恢复演练或真实商户付款验收。
- 没有验证同一私钥被完整复制后的物理单实例性；网络协议无法区分持有相同密钥的复制实例。
- 本次 GitHub Actions 检查注释说明：近期账户付款失败或支出限额不足，导致 job 在 runner 启动前被 GitHub 拒绝。最终 `main` 提交的 CI 同样需要账户恢复后重新运行，现阶段不宣称远端 CI 通过。

工作流记录：[GitHub Actions](https://github.com/YYKX682436/AiKayun-License/actions/workflows/ci.yml)。
