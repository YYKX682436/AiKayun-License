# ⑦-1B-2C-2 验收记录

## R1 修复记录

- R1 基线：`1779d909a9bbe381f689f7c8cad09684bbabdad4`（⑦-1B-2C-2 完成提交）；R1仅修复公钥生命周期连续性和状态文件单独回退检测。
- 先在该基线上加入两个回归复现并运行：静默丢弃 A 的 v2 被旧 `accept()` 成功接受；v2 吊销 A 后恢复已保存的 v1 状态文件，旧 `getAccepted()` 成功返回 v1 且墓碑消失。两项回归断言均如预期失败，确认了修复前缺口。
- 修复后，同样的用例拒绝静默删除和状态/检查点分叉；v1(A)→合法退休(A)+B→保留期结束后删除 A 可成功，退休前真实 A lease 继续验签；已吊销 A 后可在后续包省略，但墓碑持续拒绝复活。
- 存储升级为主状态加独立单调检查点；检查点以 pending→主状态→committed 的顺序持久化，并保存足够的根签名恢复证据。旧 marker schema 不作为新安装或迁移输入。

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
- `TrustBundleStore` 使用受信发行工件提供的初始最低版本；独立检查点持久保存签名工件、最高版本、发行最低版本和吊销墓碑，主状态与检查点必须一致。低版本、同版本不同工件、无效/过期包、损坏状态、状态单文件回退和状态/检查点分叉均拒绝；同一工件幂等接受。
- Lifecycle 连续性明确阻止 active kid 无声明删除；未退休 key 必须保持原样、进入不可回退退休状态或明确吊销。`not_before` 不可变；已设置的 `retire_after/verify_until` 不可修改；退休不能回填到可信接受时间之前；退休 key 在 `verify_until` 前不可删除。完成保留期后允许清除 key 记录，紧急吊销的墓碑仍独立保存。
- 文件系统持久顺序为检查点 pending fsync/rename/dir-fsync → 主状态 fsync/rename/dir-fsync → 检查点 committed fsync/rename/dir-fsync。pending 时旧状态匹配则安全中止；新状态精确匹配则基于旧 head 与新根签名工件重验生命周期并补交；其余组合 fail closed。进程锁及跨进程锁串行更新，陈旧同机锁仅在 PID 确认退出后回收。
- 引入 `TrustedSigningKeyResolver`，只按已接受包中的 kid、目标 issuer、JWT typ/audience、可信时间、签发时间和到期时间返回唯一 key。正常退休仅约束签发 `iat`，保留期覆盖最大7天 lease 加显式传播预算；新 bundle 的紧急吊销立即拒绝新经营证据，并通过墓碑拒绝复活。
- 可信时间引导先验证根签名候选，再以候选中的中心 key 验证独立 time-anchor nonce 与不超过5秒 RTT，最后用锚时间完成整包策略及版本验证。引导候选不能直接解析经营 lease；正式 resolver 只由接受的 bundle 提供。
- 真实 `signLicenseLease()` 生成的中心 JWS 与真实 `signTimeAnchor()` JWS 已使用相同的 strict JOSE 验签核心和受信 key resolver 验证；不是 mock `kid`。同一信任内核也接入 time-reset receipt resolver。

## 验收矩阵

| 范围 | 结果 | 覆盖 |
| --- | --- | --- |
| 根签名与格式 | PASS | 临时独立离线根签署并验签；中心在线 key 冒充根、错误根/kid、issuer、aud、typ、重复字段、critical/未知 header 均拒绝；格式错误的 JWK、私钥字段、未知字段、重复身份、伪造 thumbprint 和非规范 Base64URL 均拒绝。 |
| 单调版本与完整性 | PASS | v1→v2；v2→v1 拒绝；相同版本同工件幂等；相同版本不同摘要拒绝；可信发行最低版本阻止首次旧版包；下载失败、过期包和损坏/丢失状态不覆盖 last-good。 |
| 生命周期连续性 | PASS | v1(A)→v2(B)静默删除拒绝；active A 退休并引入 B 后，退休前真实 Ed25519 lease 仍可验证；verify_until 前删除拒绝，保留期结束后删除允许；修改同 kid 的 not_before/retire_after/verify_until 和回填退休时间均拒绝。 |
| 紧急吊销与墓碑 | PASS | 吊销 A 立即拒绝真实未过期 lease；后续包可省略 A，但检查点墓碑保留；后续重新引入 A 为未吊销 key 拒绝。 |
| 时间引导 | PASS | 根签名候选中的真实中心 time-anchor 绑定随机 nonce、固定 issuer/typ/aud、精确 claim 和单调 RTT≤5秒；模拟客户端 wall clock 快5年仍以锚中的签名时间完成验证。 |
| 检查点和崩溃恢复 | PASS | v2 提交后仅恢复 v1 主状态文件时拒绝，吊销历史不复活；检查点准备、主状态、检查点提交及恢复提交各阶段的部分写、写后、文件 fsync、rename 和目录 fsync 均注入故障，恢复仅保留 v1 或推进/恢复 v2，不回退；并发写者与陈旧锁测试通过。 |
| 既有授权中心 | PASS | 原有 PostgreSQL 18/HTTPS 80项集成回归全通过，验证迁移、RFC 9421、签名回执和授权操作状态。 |
| Docker | PASS | 完整构建最终镜像并检查导出文件清单；无 `tools/offline-trust`、根私钥/PEM 或测试工件。 |

## 本地命令结果

环境使用 Node.js 24.22.1；PostgreSQL 18 容器为 `--rm` 临时容器、只绑定 loopback、没有数据卷。TLS 与全部 Ed25519 私钥均为测试临时材料。

| 命令 | 结果 |
| --- | --- |
| `npm ci` | PASS；安装成功，安装阶段报告0漏洞。 |
| `npm run typecheck` | PASS，含 `src/`、tests 与离线签发工具。 |
| `npm run build` | PASS；生产构建只编译 `src/**/*.ts`。 |
| `npm test -- --reporter=dot` | PASS；6个文件，42项 unit/interop。 |
| `LICENSE_TEST_DATABASE_URL=… npm run test:integration -- --reporter=dot` | PASS；5个文件，80项 PostgreSQL 18/HTTPS 集成。 |
| 合计 | PASS；122项通过，原116项完整保留，新增6项。 |
| `npm audit --audit-level=low` | PASS；0 vulnerabilities。 |
| `git diff --check` | PASS。 |
| `git diff --quiet -- src/db/migrations` | PASS；001～006没有差异。 |
| 最终 Docker 构建与镜像清单检查 | PASS；R1 无缓存构建完成，OCI manifest list digest `sha256:0afcb31103b127d88bcbb166c36f7da025b26eb401e5aa3bbe3e190cb46ad50d`。最终镜像 `/app` 不含 `tools/offline-trust` 或离线签发入口；文件系统未发现离线根/签名 key/PEM 私钥，运行时 `package.json` 不含 `scripts` 与 `devDependencies`。 |

本机 Docker/PostgreSQL 测试容器、最终检查镜像和所有临时 Ed25519 根/中心 key 文件均已移除。`.DS_Store` 已从本仓库移除并加入 `.gitignore`。

## 发行边界与尚未验证项

- 这是授权中心中的可复用内核，不表示商城已集成根公钥/版本基线、信任包下载、TLS 时间引导、key resolver 或本地水位恢复。未来商城发行工件必须预置离线根公钥及最低版本；TLS 证书验证保持开启。
- 没有生成正式根、实施双人发行批准、双备份或密钥托管；测试传播预算仅是确定性配置，不是生产发布预算。
- 全离线安装无法及时接收紧急吊销。目录权限、marker、fsync 与原子替换不防御可同时回滚程序、发行配置和所有本地文件的 root 操作者。
- 信任包过期/网络失败不被本组件转译成许可证撤销；商城仍需按既有 lease `exp/subscription_end` 决定新经营资格，历史义务保持独立。
