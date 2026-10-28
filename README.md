# 艾卡云独立授权中心

这是独立私有的授权中心仓库，按 AiKayun ⑦-1A R3 最终协议实现 ⑦-1B-1 的服务端基础闭环。服务使用 Node.js 24、TypeScript、Fastify 5、PostgreSQL 18、Kysely、`jose` 和 RFC 9421/9530 HTTP Message Signatures 实现。

当前仓库不依赖商城进程或商城数据库。它只提供本轮约定的挑战、首次激活、lease 续签/恢复和操作查询/继续接口；没有商城客户端、经营门禁、支付接入、授权管理网页或生产部署配置。

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

`npm test` 使用 RFC 发布向量和临时 Ed25519/TLS 测试密钥。集成套件对本地真实 PostgreSQL 18 执行迁移，以真实 TLS HTTP 服务发送 RFC 9421 请求；测试中的激活码、许可证、权益事件、私钥和证书均为临时数据，不使用商户或商业授权凭据。完整验收记录见 [`docs/acceptance-7-1b-1.md`](docs/acceptance-7-1b-1.md)。

## 服务接口

所有服务接口仅通过 HTTPS 提供，并设置严格 JSON schema、32 KiB 请求限制、限流和 `no-store` 响应头。请求使用 RFC 9421 HTTP Message Signatures 和 RFC 9530 `Content-Digest`；签名覆盖方法、HTTPS 目标 URI、Content-Type 与原始请求体摘要。实例身份只接受 Ed25519 公钥，JWK thumbprint 按 RFC 7638 计算。授权 lease 使用 `typ=aikayun-license+jwt`、`alg=Ed25519`，最大有效期 7 天；挑战与状态、操作回执使用独立 `typ`。

实现的接口为：

- `POST /v1/challenges`
- `POST /v1/activations`
- `POST /v1/leases/renew`
- `POST /v1/operations/query`
- `POST /v1/operations/continue`

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

本轮未实现商业授权管理后台、支付事件接入、取消接口、实例替换/迁移、灾难迁移、商城本地凭证投影、time-reset、密钥轮换、灾难恢复迁移或生产部署。这里的单一 `001_core` 迁移仅建立本轮核心数据结构；后续上线前仍需专门完成正式密钥管理、证书/域名与代理互操作、管理面授权审计、备份恢复、运维演练和部署安全审查。
