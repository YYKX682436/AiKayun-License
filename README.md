# 艾卡云独立授权中心

这是独立运行的授权中心仓库，服务使用 Node.js 24、TypeScript、Fastify 5、PostgreSQL 18、Kysely、`jose` 和 RFC 9421/9530 HTTP Message Signatures 实现。**截至 2026-10-29，GitHub 仓库可见性为 Public**，与正式闭源商业发行目标冲突；本轮没有改变可见性，商业发行前必须处理该风险。⑦-1B-2B-1实现正常迁移，⑦-1B-2B-2实现受控灾难迁移；⑦-1B-2C-1实现中心时间锚和受审 time-reset；⑦-1B-2C-2实现离线根签名信任包、公钥生命周期和本地单调版本存储；⑦-1B-2C-3实现隔离环境 PostgreSQL signer authority 与受控 A→B 轮换；⑦-1B-2C-4完成全局联合安全验收。2C-3/2C-4不代表已生成生产发行根或完成商城客户端接入。详见 [`docs/signing-key-rotation-7-1b-2c-3.md`](docs/signing-key-rotation-7-1b-2c-3.md)、[`docs/acceptance-7-1b-2c-3.md`](docs/acceptance-7-1b-2c-3.md)、[`docs/acceptance-7-1b-2c-4.md`](docs/acceptance-7-1b-2c-4.md) 与 [`docs/license-client-handoff-7-1b-2c-4.md`](docs/license-client-handoff-7-1b-2c-4.md)。

当前仓库不依赖商城进程或商城数据库。它提供挑战、首次激活、lease 续签/恢复、实例操作查询/继续、正常和灾难迁移 prepare/commit、time-anchor/time-reset、离线信任包签发/验证及数据库权威 signer 轮换。灾难回执在权益已过期或 revoked 时仅证明身份重绑，不包含经营 grants 或新 lease。商城客户端的生产 root pin/minimum bundle、联网信任更新与时间引导、持久化 pending/projection/journal、密钥轮换接入、签名回执投影、经营准入、安装器和真实切流尚未实现。正式发行根、bundle 发布传播与客户确认也未建立。

## 本地隔离运行

需要 Node.js 24、npm、Docker Compose 和 OpenSSL。Compose 仅提供隔离的本机 PostgreSQL 与 API 容器；数据库和 HTTPS API 端口绑定到 `127.0.0.1`，数据库首次初始化会另建 `license_center_test`。`.env.example` 中的数据库账号只用于本机开发。

**当前仓库没有从空目录一键生成全部开发凭据并初始化 signer authority 的 bootstrap 命令。** `docker compose up` 不会替你生成或安装在线 keyring、离线 root 公钥、A/B 在线私钥、root-signed trust bundle，也不会在数据库中创建 signer authority；缺少任何一项时 API 不可用。不要使用旧版单密钥 keygen 步骤：`npm run keygen` 只产生孤立在线密钥，无法初始化当前数据库权威 signer。

首次启动前须按需准备以下隔离开发材料，并确认都不是生产材料：

- `secrets/license-tls-key.pem` 与 `secrets/license-tls-cert.pem`：`license.example.test` 的本机 HTTPS 证书/私钥；TLS 私钥权限为 `0600` 或更严。
- `secrets/license-signing-key-a.pem`、`secrets/license-signing-key-b.pem`：两个不同的 Ed25519 PKCS#8 在线测试私钥，权限为 `0600` 或 `0400`。
- `secrets/online-signing-keyring.json`：schema `1` 清单，`keys` 项为 `{ "kid": "<对应公钥 RFC7638 JKT>", "path": "/run/secrets/license-signing-key-a.pem" }` 等绝对容器路径；初始权威指向的 key 必须在清单中。
- `secrets/offline-root-public.json`：严格 Ed25519 公钥 JWK `{ "kty":"OKP", "crv":"Ed25519", "x":"..." }`。其配对的临时开发根私钥仅供离线工具签 bundle，不挂载进 API 容器。
- 由该临时根签署、issuer 为 `https://license.example.test`、包含 A/B 公钥及有效 lifecycle 的 bundle；bundle 与当前 `LICENSE_TRUST_BUNDLE_MIN_VERSION` 相容。

数据库准备、测试与服务可用是三个不同步骤。以下命令只启动空的隔离开发 PostgreSQL，不表示 signer 已初始化，也不会启动可用 API：

```sh
npm ci
cp .env.example .env
docker compose up -d postgres
```

接着需由维护者按 [`docs/signing-key-rotation-7-1b-2c-3.md`](docs/signing-key-rotation-7-1b-2c-3.md) 的 root-signed bundle 格式/离线签名流程准备临时开发材料，并按照 [`docs/admin-cli.md`](docs/admin-cli.md) 配置受保护的本机 CLI 策略和独立数据库角色。用 `signer initialize` 执行两步摘要确认后，才可以启动 API。`docker compose up -d api` 使用的 A/B key 文件挂载和 `.env` 配置必须与上述 keyring 完全匹配。完整的空目录自动化启动流程尚未验证；本 README 不提供会看似成功但无法启动的完整命令。

PostgreSQL 的首次初始化会创建独立 `license_center_test` 数据库。本机真实数据库集成测试使用该库，不连接业务数据库：

```sh
LICENSE_TEST_DATABASE_URL=postgres://license:license-dev-only@127.0.0.1:55432/license_center_test npm run test:integration
```

如果 PostgreSQL 数据卷是在测试数据库初始化脚本加入前创建的，可只在本机开发容器里补建一次：

```sh
docker compose exec postgres psql -U license -d license_center -c 'CREATE DATABASE license_center_test OWNER license;'
```

`/v1/time-anchor` 只有在 signer authority 已初始化且 API 配置有效后才可签发锚。验收测试中的临时根/key、数据库 signer 初始化和测试证书由测试夹具创建，不应复制为生产凭据。清除本机开发数据时，`docker compose down --volumes` 会删除该 Compose 项目的整个 PostgreSQL 数据卷。

## 验证

```sh
npm run typecheck
npm run build
npm test
LICENSE_TEST_DATABASE_URL=postgres://license:license-dev-only@127.0.0.1:55432/license_center_test npm run test:integration
npm audit --audit-level=low
```

`npm test` 使用 RFC 发布向量和临时 Ed25519/TLS 测试密钥。集成套件对隔离 PostgreSQL 18 执行迁移，以 TLS 验证开启的 HTTPS 服务发送 RFC 9421 请求；测试许可证、权益事件、私钥和证书均为临时数据，不使用客户或商业授权凭据。历次验收记录包括 [`docs/acceptance-7-1b-1.md`](docs/acceptance-7-1b-1.md)、[`docs/acceptance-7-1b-2a.md`](docs/acceptance-7-1b-2a.md)、[`docs/acceptance-7-1b-2c-1.md`](docs/acceptance-7-1b-2c-1.md)、[`docs/acceptance-7-1b-2c-2.md`](docs/acceptance-7-1b-2c-2.md)、2B 迁移验收、[`docs/acceptance-7-1b-2c-3.md`](docs/acceptance-7-1b-2c-3.md) 和 [`docs/acceptance-7-1b-2c-4.md`](docs/acceptance-7-1b-2c-4.md)。

## 本机管理 CLI（隔离环境）

CLI 可创建月/年许可证、签发或轮换一次性激活码、办理人工确认续费、撤销/恢复，以及查询管理操作与审计。它要求受保护策略文件中的本机 UID allowlist 和独立 PostgreSQL `session_user`，仅连接 loopback 数据库；写命令先生成请求摘要供人工复核，再以相同摘要确认。激活码明文只在首次成功发码且 stdout 为 TTY 时显示一次。完整权限边界、策略样例与操作步骤见 [`docs/admin-cli.md`](docs/admin-cli.md)。

本 CLI 仅用于隔离测试与受控开发运维；`NODE_ENV=production` 时拒绝启动。当前没有管理员 MFA，也没有公网管理入口，不符合正式生产远程管理安全标准。它不接收付款，也不能把命令备注当作身份认证。

## 服务接口

所有服务接口仅通过 HTTPS 提供，并设置严格 JSON schema、32 KiB 请求限制、限流和 `no-store` 响应头。请求使用 RFC 9421 HTTP Message Signatures 和 RFC 9530 `Content-Digest`；签名覆盖方法、HTTPS 目标 URI、Content-Type 与原始请求体摘要。实例身份只接受 Ed25519 公钥，JWK thumbprint 按 RFC 7638 计算。授权 lease 使用 `typ=aikayun-license+jwt`、`alg=Ed25519`，最大有效期 7 天；挑战与状态、操作回执使用独立 `typ`。

实现的接口为：

- `POST /v1/challenges`
- `POST /v1/time-anchor`
- `POST /v1/activations`
- `POST /v1/leases/renew`
- `POST /v1/operations/query`
- `POST /v1/operations/continue`
- `POST /v1/transfers/prepare`（旧 active 身份签名）
- `POST /v1/transfers/commit`（目标新身份签名）
- `POST /v1/disaster-transfers/prepare`（审批指定的目标新身份签名）
- `POST /v1/disaster-transfers/commit`（目标新身份二次持钥签名）
- `POST /v1/time-resets/commit`（需中心管理员预先审批）

`leases/renew` 只为数据库中已确认且仍有效的权益签发新 lease，也可为原绑定实例恢复最新权益 revision。它不接受客户端申报付款，不修改订阅截止时间。测试夹具会直接在隔离数据库准备许可证、激活码和确认权益事件；服务没有可在生产调用的测试放行或权益发放接口。

无效、过期、撤销、已消费或属于其他许可证的激活码，在通过请求签名、Challenge 和新鲜 nonce 校验后返回 HTTP 409 签名 `rejected`；continue 使用 HTTP 200 返回同一格式的新鲜拒绝。此类拒绝不写业务 operation、attempt 或 audit；过期且尚未终结的目标许可证激活码在同一事务中永久撤销。query 无法恢复未持久化拒绝，应以原 intent 和新 Challenge 重新 continue。完全不存在的码依赖现有 256 位随机发码的密码学假设，数据库没有不存在码的黑名单；不要将此保证扩展为抵御管理员自行插入指定 hash 或全量数据回滚。全局 operation ID 约束保持不变。

操作 `intent_digest` 使用 RFC 8785 JCS 对固定业务意图字段规范化后计算 SHA-256/base64url。激活意图只包含激活码摘要，不把明文码写入 operation 或审计。原始请求 `request_digest` 则严格按收到的 body bytes 计算，不能以 JSON 重排替代。

## 目录边界

- `src/config.ts`：必须显式提供的 PostgreSQL、发行者、签名密钥与 TLS 配置。
- `src/crypto/`：JOSE/JWK 身份与 HTTP Message Signature 验证。
- `src/db/`：Kysely/PostgreSQL schema、迁移与只追加/不可变约束。
- `src/services/`：挑战、操作事务、权益账期和状态机。
- `test/`：RFC 向量、UTC 日历规则、真实 PostgreSQL/HTTPS 验收和仅测试用夹具。
- `.github/workflows/ci.yml`：Node.js 24.22.0 + PostgreSQL 18 的 typecheck、build、unit 与 integration CI。

## 后续阶段边界

中心 signer key 的数据库权威和隔离环境轮换已有实现及验收，但生产 key 配置、MFA/双人审批、受管密钥托管、离线根正式生成/备份、bundle 发布传播与客户确认、商城端 root pin/minimum、time-anchor 网络客户端、商城凭证投影/journal/经营准入、商业授权管理网页/公网管理 API 和生产部署尚未完成。`NODE_ENV=production` 下本机管理员 CLI 仍被硬性拒绝。灾难审批中的客户核验、备份内容和旧机隔离均为不可由授权中心自行证明的人工声明；license generation 不等于物理执行隔离。商城客户端必须在受信发行工件中预置生产根公钥和最低 bundle 版本，并保持 HTTPS/TLS 验证。`001_core` 至 `007_signing_key_rotation` 历史迁移保持原样；本轮没有新增迁移。生产数据库回退恢复、备份恢复、独立时间源监控、TLS 错时引导和真实灾备演练都需单独评估；见 2C-4 验收与客户端交接文档。
