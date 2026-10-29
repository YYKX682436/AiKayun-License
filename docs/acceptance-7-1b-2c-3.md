# ⑦-1B-2C-3 验收记录

## 验收范围

- 唯一修改仓库：`AiKayun-License`，基线 `2caee9d42057cba1d8c2676314931d853537605d`。
- 测试环境：本地隔离 PostgreSQL 18.6、临时 Ed25519 A/B/C 与离线根密钥、临时 HTTPS 证书、两个真实 Fastify 进程。测试 helper 为每个运行时创建独立临时数据库，并在测试结束后删除。
- 未连接商城、真实客户数据或生产密钥；未部署生产；未开放 HTTP 换 key 接口。

## 冻结基线问题

在原单 key 实现中，以真实 Ed25519 签名和 HTTPS/数据库路径确认：

1. A 签发的未过期正常迁移 ticket，在中心只配置 B 后不能通过原验证路径，合法 Commit 被拒。
2. A 签发的灾难迁移 ticket 同样不能由 B-only 中心完成原审批下的 Commit。
3. A 签发的 challenge 在中心切换到 B 后不能通过单 key 验证器。
4. A 签发的正常迁移 receipt 及嵌套 lease 不能由 B-only 验证器验证。
5. 两个进程可以各自按本地配置选择签名 key；冻结数据库没有共同 active kid/revision 阻止签发身份分叉。

## 交付与回归

- 追加迁移 `007_signing_key_rotation`；`001`～`006` 未修改。数据库记录唯一 active kid、单调 signer revision、被接受的 root-signed bundle、稳定管理 operation 和不可变审计。数据库不保存在线私钥。
- 在线 keyring 只从显式配置的 PKCS#8 文件加载；校验 Ed25519 类型、文件类型、链接数、POSIX 权限和实际公钥 JKT。轮换使用独立管理员会话、摘要确认、expected revision、B 的持钥证明与隔离 rollout gate。
- 共享 advisory lock 保护业务签发事务，独占锁保护切换；集成测试通过 PostgreSQL `pg_locks` 确认切换前签发、排队切换与第二进程 B 签发的顺序。
- A→B 后，A challenge、lease、normal/disaster ticket、normal/disaster receipt、嵌套 lease、time-anchor 与 time-reset 证据通过当前 root-authenticated resolver 按 kid 验证。正常和灾难迁移的 A ticket 均可在有效期内由 B 接班后 Commit，最终结果用 B 签名；原 ticket/response 字节不变。
- 过期 ticket 仍以数据库当前时间检查截止；历史查询保留原 `response_jws`，不会重签或续长 lease。time-reset operation 重放返回同一个 A receipt，不会提升第二次 epoch。
- A 紧急吊销会使旧 A ticket 无法 Commit，并将未完成 plan 追加审计为 invalidated；原墓碑和票据字节保留。受信的 B/C 凭证继续工作；active signer 被吊销后签发 fail closed，不自动回退。
- A→B→C 使用新的 kid 与独立 operation；回退至 A 被拒。JWT 验证仍严格限制 JWS header、Ed25519、issuer、audience、typ、生命周期和 exact claims；RFC 9421 实例 HTTP 签名未放宽。

## 命令结果

在提交前工作区执行：

| 命令 | 结果 |
| --- | --- |
| `npm ci` | 完成；依赖安装成功，0 vulnerabilities |
| `npm run typecheck` | 通过 |
| `npm run build` | 通过 |
| `npm test` | 48/48 通过，6 个测试文件 |
| `npm run test:integration` | 86/86 通过，6 个测试文件；HTTPS + PostgreSQL 18.6 |
| `npm audit --audit-level=low` | 0 vulnerabilities |
| `git diff --check` | 通过 |

最终 Docker 镜像本地构建成功。对合并后的镜像 rootfs 导出扫描了 5,804 个普通文件：未发现真实 PEM 私钥块、测试 key、管理 CLI、keygen 或离线 bundle 签名入口；服务端 `dist` 中离线签名函数符号计数为 0。Docker build 在 runtime 复制前移除 admin CLI/keygen，并清理 npm 与 Node 编译缓存。镜像仅用于隔离环境构建验收，没有运行或部署。

## 生产边界

本记录不证明客户已收到新版 bundle。生产管理员 MFA/双人审批、密钥托管、bundle 传播和客户端就绪证明、生产发布门禁与恢复演练仍未完成；生产轮换、客户端集成和生产部署不属于本阶段。

## R1：签发时间与 key 生命周期锁等待回归

R1 基线：`8c1473b42d581bb504ffadf3dbb434f13e59e965`。修复前复现证据使用真实 PostgreSQL 18、HTTPS 和临时 Ed25519 身份：

| 路径 | PostgreSQL/HTTP 证据 | 旧实现结果 |
| --- | --- | --- |
| A lease 跨 `retire_after` | PID 89 持有 signer `ShareLock` 并等待 license `FOR UPDATE`；退休秒 `1793269886`，放锁时 DB 秒 `1793269887` | HTTP 200；A `kid`、`iat=1793269887`；operation `response_jws` 和 generation=1 已提交；当前可信 resolver 拒绝 `JWT was signed outside the center key issuance window` |
| challenge 等待 signer lock | PID 94 在 PostgreSQL advisory lock 队列；真实 RFC 9421 `expires=1793269917`，旧响应时 DB 时间已为 `1793269917` | HTTP 201；受控旧 challenge 时钟产出 `iat=1793269287`、`exp=1793269587`，nonce `expires_at` 早于 DB 当前时间；当前 resolver 拒绝 token |

修复后将数据库当前时间与生命周期重检放入每次 JWT 实际签发的统一入口；仍使用原 signer 共享锁、原事务和原锁顺序。resolver 的 `retire_after` 端点改为排除，和签发侧 `now >= retire_after` 一致。challenge 在 signer 锁后使用 PostgreSQL 时间生成并重新核验 HTTP 签名有效窗。注入时间限于开发配置，production app 与 service 拒绝注入。

R1 专项集成结果：

- license 行锁等待跨过 A 的退休秒后返回 503 `ACTIVE_SIGNING_KEY_OUTSIDE_LIFECYCLE`；operation/attempt/audit 不存在，generation 仍为 0，activation code 未消费，challenge nonce 未消费。`pg_locks` 证实业务后端等待期间持有 signer `ShareLock`。
- A 退休前签发的 lease 在当前 resolver 下仍有效；A 退休后管理员切换到已预发布 B，B 新 activation challenge/lease 由 B `kid` 签发并验证通过。
- RFC 9421 签名窗口跨过后返回 401 `HTTP_SIGNATURE_INVALID`，没有 nonce 或 operation 写入；未超窗的短 signer 锁等待返回 HTTP 201，JWT `iat/exp` 与 nonce `created_at/expires_at` 一致。
- 单元测试验证 `iat=retire_after-1` 可验证，`iat=retire_after` 被拒绝。
- 修复前两条真实锁等待记录保留在专项设计文档；临时复现测试文件已替换为稳定回归测试。

### R1 命令结果

使用 Node 24.22.0 与本地临时 PostgreSQL 18 容器（`127.0.0.1:55674`，独立于商城容器）运行：

| 命令 | 结果 |
| --- | --- |
| `npm ci` | 完成，依赖安装成功；npm 报告 0 vulnerabilities |
| `npm run typecheck` | 通过 |
| `npm run build` | 通过 |
| `npm test` | 48/48 通过，6 个测试文件 |
| `npm run test:integration` | 89/89 通过，7 个测试文件；真实 PostgreSQL 18/HTTPS |
| `npm audit --audit-level=low` | 0 vulnerabilities |
| `git diff --check` | 通过 |

R1 Dockerfile 镜像构建通过。导出 rootfs 并扫描 6,147 个普通文件：没有完整 PEM 私钥块，`/app` 下没有 `.pem`、`.key` 或 `.jwk` 私钥材料；不存在 admin CLI、keygen 或离线签名目录。临时镜像、扫描容器和 rootfs 目录已删除。Docker build 的共享缓存未做全局 prune，以免清除其他项目缓存。

最终提交 SHA、`origin/main` 一致性及 GitHub Actions 对应精确 SHA 的状态将在推送后补录。
