# 艾卡云独立授权中心

这是独立私有的授权中心仓库，服务使用 Node.js 24、TypeScript、Fastify 5、PostgreSQL 18、Kysely、`jose` 和 RFC 9421/9530 HTTP Message Signatures 实现。⑦-1B-2B-1实现授权中心正常迁移；⑦-1B-2B-2追加来源私钥不可用时的受控灾难迁移。正常迁移使用目标新 Ed25519 key并需来源持钥证明；灾难迁移使用受控管理员审批加目标新 key持钥证明，两者端点、ticket及回执用途隔离。协议和边界分别见 [`docs/normal-transfer-7-1b-2b-1.md`](docs/normal-transfer-7-1b-2b-1.md) 与 [`docs/disaster-transfer-7-1b-2b-2.md`](docs/disaster-transfer-7-1b-2b-2.md)。

当前仓库不依赖商城进程或商城数据库。它提供挑战、首次激活、lease 续签/恢复、实例操作查询/继续、正常和灾难迁移 prepare/commit 接口，以及隔离测试与受控开发运维用的本机管理 CLI。灾难回执在权益已过期或 revoked 时仅证明身份重绑，不包含经营 grants 或新 lease。商城客户端的本地密钥切换、签名回执投影、安装器和真实切流尚未实现。

## 本地隔离运行

需要 Node.js 24、npm、Docker Compose 和 OpenSSL。`.env.example` 中的数据库账号只用于本机开发。Compose 将 PostgreSQL 与 HTTPS API 端口绑定到 `127.0.0.1`，API 容器只在本地 Compose 网络监听通配地址。

```sh
npm ci
cp .env.example .env
mkdir -p secrets
npm run keygen -- secrets/license-signing-key.pem secrets/license-signing-public.pem
chmod 600 secrets/license-signing-key.pem
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj '/CN=license.example.test' \
  -addext 'subjectAltName=DNS:license.example.test' \
  -keyout secrets/license-tls-key.pem \
  -out secrets/license-tls-cert.pem
chmod 600 secrets/license-tls-key.pem
export LICENSE_CONTAINER_UID="$(id -u)"
export LICENSE_CONTAINER_GID="$(id -g)"
docker compose up -d --build
```

JWT Ed25519 签名密钥与 HTTPS 服务器密钥是两把独立密钥。服务启动时必须读取两把私钥和证书；缺少文件、权限过宽或证书无法读取时会拒绝启动，不会自动生成生产密钥。`.env`、`secrets/`、私钥、证书和本地构建文件均已加入忽略规则。

PostgreSQL 的首次初始化会创建独立的 `license_center_test` 数据库。本机真实数据库集成测试使用它，不连接业务数据库：

```sh
LICENSE_TEST_DATABASE_URL=postgres://license:license-dev-only@127.0.0.1:55432/license_center_test npm run test:integration
```

如果 PostgreSQL 数据卷是在测试数据库初始化脚本加入前创建的，可只在本机开发容器里补建一次：

```sh
docker compose exec postgres psql -U license -d license_center -c 'CREATE DATABASE license_center_test OWNER license;'
```

清除本机开发数据时，`docker compose down --volumes` 会删除该 Compose 项目的整个 PostgreSQL 数据卷。

## 验证

```sh
npm run typecheck
npm run build
npm test
LICENSE_TEST_DATABASE_URL=postgres://license:license-dev-only@127.0.0.1:55432/license_center_test npm run test:integration
```

`npm test` 使用 RFC 发布向量和临时 Ed25519/TLS 测试密钥。集成套件对本地真实 PostgreSQL 18 执行迁移，以真实 TLS HTTP 服务发送 RFC 9421 请求；测试中的激活码、许可证、权益事件、私钥和证书均为临时数据，不使用商户或商业授权凭据。基线验收见 [`docs/acceptance-7-1b-1.md`](docs/acceptance-7-1b-1.md)，管理内核见 [`docs/acceptance-7-1b-2a.md`](docs/acceptance-7-1b-2a.md)，正常迁移与本阶段灾难迁移分别见 [`docs/acceptance-7-1b-2b-1-r2.md`](docs/acceptance-7-1b-2b-1-r2.md) 和 [`docs/acceptance-7-1b-2b-2.md`](docs/acceptance-7-1b-2b-2.md)。

## 本机管理 CLI（隔离环境）

CLI 可创建月/年许可证、签发或轮换一次性激活码、办理人工确认续费、撤销/恢复，以及查询管理操作与审计。它要求受保护策略文件中的本机 UID allowlist 和独立 PostgreSQL `session_user`，仅连接 loopback 数据库；写命令先生成请求摘要供人工复核，再以相同摘要确认。激活码明文只在首次成功发码且 stdout 为 TTY 时显示一次。完整权限边界、策略样例与操作步骤见 [`docs/admin-cli.md`](docs/admin-cli.md)。

本 CLI 仅用于隔离测试与受控开发运维；`NODE_ENV=production` 时拒绝启动。当前没有管理员 MFA，也没有公网管理入口，不符合正式生产远程管理安全标准。它不接收付款，也不能把命令备注当作身份认证。

## 服务接口

所有服务接口仅通过 HTTPS 提供，并设置严格 JSON schema、32 KiB 请求限制、限流和 `no-store` 响应头。请求使用 RFC 9421 HTTP Message Signatures 和 RFC 9530 `Content-Digest`；签名覆盖方法、HTTPS 目标 URI、Content-Type 与原始请求体摘要。实例身份只接受 Ed25519 公钥，JWK thumbprint 按 RFC 7638 计算。授权 lease 使用 `typ=aikayun-license+jwt`、`alg=Ed25519`，最大有效期 7 天；挑战与状态、操作回执使用独立 `typ`。

实现的接口为：

- `POST /v1/challenges`
- `POST /v1/activations`
- `POST /v1/leases/renew`
- `POST /v1/operations/query`
- `POST /v1/operations/continue`
- `POST /v1/transfers/prepare`（旧 active 身份签名）
- `POST /v1/transfers/commit`（目标新身份签名）
- `POST /v1/disaster-transfers/prepare`（审批指定的目标新身份签名）
- `POST /v1/disaster-transfers/commit`（目标新身份二次持钥签名）

`leases/renew` 只为数据库中已确认且仍有效的权益签发新 lease，也可为原绑定实例恢复最新权益 revision。它不接受客户端申报付款，不修改订阅截止时间。测试夹具会直接在隔离数据库准备许可证、激活码和确认权益事件；服务没有可在生产调用的测试放行或权益发放接口。

操作 `intent_digest` 使用 RFC 8785 JCS 对固定业务意图字段规范化后计算 SHA-256/base64url。激活意图只包含激活码摘要，不把明文码写入 operation 或审计。原始请求 `request_digest` 则严格按收到的 body bytes 计算，不能以 JSON 重排替代。

## 目录边界

- `src/config.ts`：必须显式提供的 PostgreSQL、发行者、签名密钥与 TLS 配置。
- `src/crypto/`：JOSE/JWK 身份与 HTTP Message Signature 验证。
- `src/db/`：Kysely/PostgreSQL schema、迁移与只追加/不可变约束。
- `src/services/`：挑战、操作事务、权益账期和状态机。
- `test/`：RFC 向量、UTC 日历规则、真实 PostgreSQL/HTTPS 验收和仅测试用夹具。
- `.github/workflows/ci.yml`：Node.js 24.22.0 + PostgreSQL 18 的 typecheck、build、unit 与 integration CI。

## 后续阶段边界

本阶段未实现商业授权管理网页/公网管理 API、MFA、支付事件接入、商城本地凭证投影、time-reset、中心签名私钥轮换或生产部署。正常和灾难迁移审批仅沿用受限本机 CLI 的 OS UID 与数据库 role 身份；`NODE_ENV=production` 仍被硬性拒绝。灾难审批中的客户核验、备份内容和旧机隔离均为不可由授权中心自行证明的人工声明。真实切流前仍须完成旧机器隔离、历史密钥/业务数据核对、未决资金与履约查单；license generation 不等于物理执行隔离。因此这些迁移代码只能在隔离测试/受控开发中验收，不能宣称可直接商用。`001_core` 至 `004_transfer_approval_revocations`保持不变；本阶段只追加 `005_disaster_transfers`。强认证/MFA、正式密钥管理、商城恢复器、备份恢复、运维演练和部署安全审查仍需单独完成。
