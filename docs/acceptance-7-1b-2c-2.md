# ⑦-1B-2C-2 验收记录

## 基线与边界

- 冻结基线：`d80baae43ba03c220966e26217005dc10e2c49b0`；起始 `HEAD` 与 `origin/main` 一致。
- 只修改 `/Users/muchen/Documents/ChatGPT/AiKayun-License`。商城 `/Users/muchen/Documents/ChatGPT/AiKayun` 只读。
- `src/db/migrations/001_core.ts` 至 `006_time_reset.ts` 均未修改；没有新增 migration、数据库部署或生产部署。
- 没有创建生产发行根私钥、真实授权、客户数据或商户数据；没有切换中心实际签名私钥、改变仓库可见性或开始⑦-1B-2C-3。
- 基线原有99项 unit/interop 与 PostgreSQL/HTTPS 测试全部保留。

## 实现验收

- 添加严格 `aikayun-license-trust-bundle+jwt` v1 格式：固定离线根 issuer、独立 audience、精确中心 `sub`、固定 schema、十进制字符串 `bundle_version`、时间窗及显式发布传播预算。使用 `jose` 与标准 Ed25519 JWS，不实现密码算法或完整 TUF 更新服务。
- 根公钥必须来自调用方预置 pin，且根 kid 通过 RFC 7638 thumbprint 复核；中心在线 key 不能冒充离线根。包、protected header、key JWK 和 key 生命周期字段均采用精确 allowlist；拒绝重复 JSON 字段、未知/critical header、私钥字段、错曲线、未知字段、非规范 Base64URL、重复/伪造 kid、超限包及错误 JWT 用途。
- `tools/offline-trust/sign.ts` 是显式根 key 文件输入的两步离线签发工具；严格检查 POSIX 文件类型、owner、hardlink 和权限。预览列出公钥、issuer、版本、时间窗、预算与 signing-input 摘要；签发要求相同摘要确认，JWS 以文件/目录 fsync 和原子 rename 发布。构建配置和 Dockerfile 均不把签发入口打包进服务镜像。
- `TrustBundleStore` 使用受信发行工件提供的初始最低版本，持久保存签名工件、最高版本、最低版本和吊销墓碑。低版本、同版本不同工件、无效/过期包、损坏状态和初始化后状态丢失均拒绝；同一工件幂等接受。临时文件写入、fsync、原子 rename、目录 fsync 和单写者恢复都有真实文件系统测试。
- 引入 `TrustedSigningKeyResolver`，只按已接受包中的 kid、目标 issuer、JWT typ/audience、可信时间、签发时间和到期时间返回唯一 key。正常退休仅约束签发 `iat`，保留期覆盖最大7天 lease 加显式传播预算；新 bundle 的紧急吊销立即拒绝新经营证据，并通过墓碑拒绝复活。
- 可信时间引导先验证根签名候选，再以候选中的中心 key 验证独立 time-anchor nonce 与不超过5秒 RTT，最后用锚时间完成整包策略及版本验证。引导候选不能直接解析经营 lease；正式 resolver 只由接受的 bundle 提供。
- 真实 `signLicenseLease()` 生成的中心 JWS 与真实 `signTimeAnchor()` JWS 已使用相同的 strict JOSE 验签核心和受信 key resolver 验证；不是 mock `kid`。同一信任内核也接入 time-reset receipt resolver。

## 验收矩阵

| 范围 | 结果 | 覆盖 |
| --- | --- | --- |
| 根签名与格式 | PASS | 临时独立离线根签署并验签；中心在线 key 冒充根、错误根/kid、issuer、aud、typ、重复字段、critical/未知 header 均拒绝；格式错误的 JWK、私钥字段、未知字段、重复身份、伪造 thumbprint 和非规范 Base64URL 均拒绝。 |
| 单调版本与完整性 | PASS | v1→v2；v2→v1 拒绝；相同版本同工件幂等；相同版本不同摘要拒绝；可信发行最低版本阻止首次旧版包；下载失败、过期包和损坏/丢失状态不覆盖 last-good。 |
| 生命周期 | PASS | not_before 前签发拒绝；轮换窗口中两把独立 Ed25519 key 各自验证真实 lease；retire_after 前签发的未过期 lease 可在 verify_until 前续用；超出签发窗口/verify_until 拒绝新经营授权；紧急吊销立即拒绝，后续包不能复活墓碑 kid。 |
| 时间引导 | PASS | 根签名候选中的真实中心 time-anchor 绑定随机 nonce、固定 issuer/typ/aud、精确 claim 和单调 RTT≤5秒；模拟客户端 wall clock 快5年仍以锚中的签名时间完成验证。 |
| 崩溃恢复 | PASS | 对部分写、写后、文件 fsync 后、rename 后和目录 fsync 后故障注入；重建 Store 后读取 last-good 或已提交的更高版本，从不降低水位。离线发布文件在 rename 前故障时仍保留原工件。 |
| 既有授权中心 | PASS | 原有 PostgreSQL 18/HTTPS 80项集成回归全通过，验证迁移、RFC 9421、签名回执和授权操作状态。 |
| Docker | PASS | 完整构建最终镜像并检查导出文件清单；无 `tools/offline-trust`、根私钥/PEM 或测试工件。 |

## 本地命令结果

环境使用 Node.js 24.22.1；PostgreSQL 18 容器为 `--rm` 临时容器、只绑定 loopback、没有数据卷。TLS 与全部 Ed25519 私钥均为测试临时材料。

| 命令 | 结果 |
| --- | --- |
| `npm ci` | PASS；安装成功，安装阶段报告0漏洞。 |
| `npm run typecheck` | PASS，含 `src/`、tests 与离线签发工具。 |
| `npm run build` | PASS；生产构建只编译 `src/**/*.ts`。 |
| `npm test -- --reporter=dot` | PASS；6个文件，36项 unit/interop。 |
| `LICENSE_TEST_DATABASE_URL=… npm run test:integration -- --reporter=dot` | PASS；5个文件，80项 PostgreSQL 18/HTTPS 集成。 |
| 合计 | PASS；116项通过，原99项完整保留，新增17项。 |
| `npm audit --audit-level=low` | PASS；0 vulnerabilities。 |
| `git diff --check` | PASS。 |
| `git diff --quiet -- src/db/migrations` | PASS；001～006没有差异。 |
| 最终 Docker 构建与镜像清单检查 | PASS；无缓存构建完成，OCI manifest list digest `sha256:b2a20146ebb4805cb585484f66e653ec0599f36ab35c8e14ce24ceb1905c7779`。最终文件系统没有 `tools/offline-trust`、`trust-bundle:offline`、离线/发行根、配置签名 key 或 secrets 路径；运行时 `package.json` 也没有离线签发脚本。基础镜像保留的 `etc/ssl/cert.pem` 是公开 CA 证书束，不含私钥。 |

本机 Docker/PostgreSQL 测试容器、最终检查镜像和所有临时 Ed25519 根/中心 key 文件均已移除。`.DS_Store` 已从本仓库移除并加入 `.gitignore`。

## 发行边界与尚未验证项

- 这是授权中心中的可复用内核，不表示商城已集成根公钥/版本基线、信任包下载、TLS 时间引导、key resolver 或本地水位恢复。未来商城发行工件必须预置离线根公钥及最低版本；TLS 证书验证保持开启。
- 没有生成正式根、实施双人发行批准、双备份或密钥托管；测试传播预算仅是确定性配置，不是生产发布预算。
- 全离线安装无法及时接收紧急吊销。目录权限、marker、fsync 与原子替换不防御可同时回滚程序、发行配置和所有本地文件的 root 操作者。
- 信任包过期/网络失败不被本组件转译成许可证撤销；商城仍需按既有 lease `exp/subscription_end` 决定新经营资格，历史义务保持独立。
