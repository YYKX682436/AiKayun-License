# ⑦-1B-2C-2：离线发行根、信任包与公钥版本水位

状态：授权中心仓库内的可复用验证与存储内核已实现；没有创建生产离线根，没有切换中心在线签名私钥，没有修改商城或生产环境。本文件补充商城 `docs/license-protocol-7-1a.md` 的信任根与生命周期协议，并落实⑦-1B-2C-1的可信时间引导顺序。

## 信任边界和使用顺序

唯一接受信任包的根依据是调用方随受信发行工件预置的 `TrustedOfflineRootPin`：严格的公开 `OKP/Ed25519` JWK 和它的 RFC 7638 SHA-256 thumbprint。根身份不能来自 HTTPS 响应、中心在线签名 key、信任包自身或 token 的 `jwk/jku/x5u`。`OFFLINE_ROOT_ISSUER` 固定为 `urn:aikayun:license:offline-release-root:v1`；发行根和中心在线签名 key 必须是不同的 thumbprint。

客户端在 wall clock 不可信时按此顺序操作：

1. 以发行工件内的离线根公钥调用 `verifyTrustBundleSignature()`。它只产生进程内的 `RootAuthenticatedTrustBundleCandidate`，验证根签名、固定 `iss`、中心 `sub`、独立 `aud`、精确 schema、JWK 和全部格式约束。候选尚未成为经营信任集合。
2. 生成32字节随机 nonce，通过 HTTPS 获取 time-anchor；调用 `verifyTimeAnchorWithTrustBundleCandidate()`，用候选包中与 `kid` 对应的中心公钥验证 `typ=aikayun-time-anchor+jwt`、固定中心 issuer、`aud=aikayun-time-bootstrap`、nonce、短有效期和 key 生命周期。它使用显式传入的单调 RTT，最大5秒，不读取 HTTP `Date` 或 host wall clock。
3. 只把已验签锚中的 `server_time` 作为可信秒数传给 `TrustBundleStore.accept(candidate.token, serverTime)`。完整包的 `iat/nbf/exp`、key 窗口、最低版本和吊销历史全部通过后，状态才原子持久化并成为正式集合。
4. 每次需要验 lease/receipt 时，使用 `getAccepted(trustedTime)` 取得当前 bundle resolver，再调用 `verifyLicenseLeaseWithTrustedKeys()` 或 `verifyTimeResetReceipt(..., { resolver, ... })`。resolver 要求精确 issuer、JWT `typ` 与对应 audience，按 `kid` 唯一选 key，并同时检查可信时间和 JWT `iat/exp`。

候选包的根签名不会信任其自报时间。时间锚签名先由根认证候选中的公钥验证；随后候选包自身有效期和该 key 的 `not_before/retire_after/verify_until` 均以已经验签的锚时间检查。只有完整接受以后，resolver 才允许经营 lease key。HTTPS 下载必须保留正常 TLS 证书链校验；本项目没有实现商城的 TLS 校时网络客户端，也没有任何关闭 TLS 验证的路径。

主要接口在 `src/trust/trust-bundle.ts`、`src/trust/trust-bundle-store.ts`、`src/crypto/jwt.ts`、`src/crypto/time-reset.ts` 和 `src/receipts.ts`。中心服务端继续使用当前单 key 配置签发；本轮没有修改或轮换中心实际签名 key。

## 信任包 JWS v1

Compact JWS 最大16KiB。protected header 必须精确为 `{ "alg":"Ed25519", "kid":"<offline root RFC7638 SHA-256 thumbprint>", "typ":"aikayun-license-trust-bundle+jwt" }`，不允许额外参数、`crit`、`jwk`、`jku`、`x5u` 或压缩。header、payload、signature 的 Base64URL 均要求规范编码。header/payload 使用严格 JSON，拒绝重复字段。

payload claim 集精确为：

| Claim | 规则 |
| --- | --- |
| `iss` | 固定离线根身份 `urn:aikayun:license:offline-release-root:v1` |
| `aud` | 固定且独立于经营 JWT 的 `aikayun-license-signing-keys` |
| `sub` | 与发行客户端预期中心 issuer 完全一致的 HTTPS origin |
| `bundle_schema` | 整数 `1`；未知 schema 拒绝 |
| `bundle_version` | 正整数、规范十进制字符串，最多19位；不接受 JSON number/浮点数 |
| `iat`, `nbf`, `exp` | 正整数 NumericDate 秒；`iat <= nbf < exp`，包最长90天；接受时要求 `iat <= trusted_time`、`nbf <= trusted_time < exp` |
| `propagation_budget_seconds` | 必填的正整数秒，最大90天；没有默认0 |
| `keys` | 1～32个严格 key record |

每个 key record 字段精确为 `kid/alg/kty/crv/x/not_before/retire_after/verify_until/revoked_at`。`alg=Ed25519`、`kty=OKP`、`crv=Ed25519`；`x` 是32字节公钥的规范无填充 Base64URL。拒绝 `d`、所有私钥材料和任何未知字段。`kid` 必须由 `jose.calculateJwkThumbprint(JWK, 'sha256')` 对实际 JWK 计算得出。重复/冲突的 kid 或公钥身份、伪造指纹、非规范编码、非法数值和超过限额的 key 均拒绝；离线发行根自己的 key 不能出现在中心 key 集合中。

`not_before/retire_after/verify_until/revoked_at` 是整数 UTC 秒；`retire_after/verify_until/revoked_at` 显式使用整数或 `null`。没有计划退休时 `retire_after` 与 `verify_until` 必须同时为 `null`。计划退休时必须满足：

```text
verify_until >= retire_after + 604800 + propagation_budget_seconds
```

发布传播预算必须由发行输入显式提供并随签名包记录。key 的 `not_before` 和 `retire_after` 限制 token 签发 `iat`；`retire_after` 本身不会提前使旧 lease 失效。退休前签发、当前仍未过 `exp`、且整个 token 未越过 `verify_until` 的 lease 可继续验签。`trusted_time >= verify_until`、JWT `exp > verify_until` 或 `iat > retire_after` 均不能授予新经营资格。

当已接受的新包声明 `revoked_at` 后，该 key 即刻被禁止用于新的经营证据，包括尚未过期的旧 lease。吊销 kid 会写入持久化墓碑；后续包可省略该 key，但不能把墓碑 kid 作为未吊销 key 重新引入。已经提交的历史凭证可保留为历史业务证据，不能用历史验签恢复新订单权限。完全离线安装无法立即收到紧急吊销；本内核不承诺网络隔离时远程即时撤销。

生命周期是同一 key record 的单向状态转换：未退休的 key 可保持不变，或在接受新 bundle 时设置 `retire_after/verify_until`；正常退休的 `retire_after` 不能早于当次可信接受时间，且 `verify_until` 必须继续满足七天 lease 保留期加显式传播预算。退休前的 lease 在 `verify_until` 前仍可验证。退休字段一旦设置便不可修改，`not_before` 从首次接受后不可修改；因此不能抬高起效时间、回填退休时间或缩短保留期来废除旧凭证。紧急吊销是唯一可跳过正常保留期的退出路径，墓碑不可逆。未吊销 active key 不能从新包删除；退休 key 只有在可信时间到达 `verify_until` 后才能删除。已经完成保留期或已吊销的 key 可从后续包移除，墓碑仍留在持久检查点，不要求 key 列表永久增长。

正常退休移除与紧急吊销使用两类独立历史墓碑：`retired_kids` 记录已完成 `verify_until` 并从当前 bundle 退出的 kid；`revoked_kids` 记录紧急吊销。正常退休墓碑只在 R1 生命周期检查允许移除的同一次版本提交中写入。key 在 `verify_until` 前仍留在 bundle，可用于验证合法历史 lease；时间到达后，其经营验证窗口已经结束，再将它移除并永久记入 `retired_kids`。墓碑一旦提交，任何后续 bundle 即使由同一离线根签名、版本更高，也不得再次包含该 kid。两类墓碑不会互相转换或互相代替。

## 离线签发

专用入口位于 `tools/offline-trust/sign.ts`，并不属于 `src/` 构建入口。该命令只读取明确传入的根私钥文件，不检查中心在线签名 key 配置，也没有任何自动回退路径。根 key 文件必须是当前有效 UID 拥有的普通单链接文件，拒绝 symlink/hard link；POSIX 权限仅允许非可执行 `0400` 或 `0600`。文件大小上限8KiB，使用 `O_NOFOLLOW` 和打开后 inode/size 复核。读取缓冲区使用后清零；私钥不输出到 stdout/stderr。

发行输入是严格 JSON 文件，字段为 `bundle_version/iat/nbf/exp/propagation_budget_seconds/keys`；`iss/aud/sub/bundle_schema` 由工具固定生成。建议在与在线服务隔离的受控环境，先用公开信息准备输入文件，再执行两步审核：

```sh
npm run trust-bundle:offline -- preview \
  --center-issuer https://license.example.test \
  --root-key-file /offline-control/license-release-root.pem \
  --bundle-input /offline-control/bundle-v1.json

npm run trust-bundle:offline -- sign \
  --center-issuer https://license.example.test \
  --root-key-file /offline-control/license-release-root.pem \
  --bundle-input /offline-control/bundle-v1.json \
  --confirm-digest <preview中的signingInputSha256> \
  --output /release/trust-bundle-v1.jws
```

preview 展示中心 issuer、版本、包时间窗、显式传播预算、完整公钥清单和两个 SHA-256 摘要。`signingInputSha256` 覆盖实际 protected header 与 canonical JSON payload 的 JWS signing input；第二次操作重新读取根文件与输入，并要求摘要逐字匹配。编辑任何内容都必须重新审核。签名结果是公开工件，使用同目录临时文件、文件 `fsync`、原子 `rename` 和目录 `fsync` 发布；失败不会留下半截工件覆盖原发布文件。

本轮没有正式生产根私钥，也没有建立正式根生成、双备份、密钥托管、签发双人审批或生产传播预算。测试只生成临时 Ed25519 key 并放在临时目录/进程内，结束后清理。生产根创建、备份与发行人员流程属于后续生产发行门禁。

本 profile 只采用 TUF 的离线根信任、过期元数据和单调版本 rollback/freeze 防护原则，不实现完整 TUF metadata graph、阈值角色、在线更新服务或 delegated targets；JWT 类型隔离与 audience 校验遵循 RFC 8725 的应用 profile。参考：[TUF Specification v1.0.36](https://theupdateframework.github.io/specification/v1.0.36/)；[RFC 8725 §3.11–3.12](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.11)。

Dockerfile 只把 `src/` 编译进服务镜像，不复制 `tools/`；`tsconfig.build.json` 也只编译 `src/**/*.ts`。运行镜像使用构建阶段生成的无 `scripts`/`devDependencies` 运行时 manifest，最终镜像中不保留离线签发命令声明。

## 版本水位与可恢复存储

`TrustBundleStore` 是无数据库依赖的客户端中立组件。构造时必须从可信发行工件获得 `trustedRoot`、`expectedCenterIssuer` 和 `minimumBundleVersion`。不能把下载到的第一个包自动作为根或初始版本。最低版本和 bundle 版本使用独立正整数十进制字符串，与数据库 `time_epoch`、generation、entitlement revision 无关。

每个私有目录有主状态 `trust-bundle-state.json` 和独立单调检查点 `trust-bundle-store.marker.json`。R2 的 state/checkpoint schema 为2，不兼容旧 schema。主状态保存当前签名 JWS、版本、工件摘要及分离的 `revoked_kids/retired_kids`；检查点另行保存已提交 head 的相同身份、完整 JWS、两类完整墓碑、受信发行最低版本，以及提交期间的 pending 转换证据。检查点不是发生分叉时可任选的备份副本：无 pending 时两个文件必须精确一致；状态单文件回滚、丢失、损坏或同版本摘要冲突均 fail closed。旧版仅含最低版本 marker 的结构不再兼容，不能被当作新安装或用它重置水位。目录要求 POSIX `0700` 或更严，文件 `0600` 或更严。

接受版本的持久顺序是：

1. 先将检查点原子写为“旧 committed head + pending 新 JWS、摘要、版本、墓碑及可信接受时间”，并对临时文件、检查点 rename 和目录执行 `fsync`。此前崩溃不改变旧 head。
2. 再原子写主状态的新 head，并对临时文件、rename 后目录执行 `fsync`。
3. 最后将检查点原子提交为新 committed head 并清除 pending；该检查点目录 `fsync` 成功后 `accept()` 才返回成功。

重启时，pending 检查点若仍对应旧主状态，说明新状态尚未安装，安全丢弃 pending 并保留旧 head；若主状态精确对应 pending 新状态，则重新验根签名、版本、生命周期连续性、接受时有效期及两类墓碑，再补交检查点。退休移除形成的 `retired_kids` 在 pending、主状态和 committed 检查点中一致恢复；任何第三种组合均拒绝。检查点已提交而状态较旧时不能降级；特别是确认 v2 后单独恢复 v1 状态文件会与 v2 检查点分叉并 fail closed。检查点提交后状态文件缺失也拒绝，不从副本自动重建业务信任。每个文件的部分写入、文件 fsync、rename、目录 fsync 中断都按上述规则重试或拒绝，不会选择较低版本。

两类墓碑合计最多保存256个kid，保证最大bundle和状态文件仍在持久化大小限制内。到达容量时，若新接受会新增墓碑，操作直接拒绝，不截断或覆盖任何历史；两个墓碑集合也不得重叠。发行方需在受控升级/存储容量处置前停止该次轮换；绝不以丢弃墓碑换取接受新包。

单目录更新、读取和 resolver 当前性检查经进程内队列与排他文件锁串行；同机陈旧锁只在确认 PID 不存在后清理，无法解释或属于其他主机的锁状态保持拒绝。并发写入不会绕过版本比较。

规则：低版本拒绝；同版本同一完整签名工件幂等；同版本不同工件摘要拒绝；只有严格更高版本可以更新。新包必须完整通过根签名、issuer、时间、JWK、生命周期、最低版本及吊销历史校验后才能覆盖 last-good。`getAccepted()` 不会把过期包续签或标记为新版本；过期包不能解析新凭证 key。客户端应独立遵循既有授权契约：下载失败或信任包过期不会伪造许可证撤销，也不会延长/提前作废已有 last-good lease；经营资格仍由原签名 lease 的 `exp/subscription_end` 和撤销事实决定，历史义务始终独立。

文件权限、原子替换和独立检查点可检测单个主状态文件的回滚/损坏，但不防御拥有 root 权限并能协调回滚程序、发行工件、根配置、检查点和全部持久化文件的操作者。未来商城还需将根公钥和初始最低版本放进经审查的发行工件；需实现 TLS 保持开启的信任包获取/可信时间引导、单调时间源和本地业务投影。本仓库没有修改商城数据库，也没有声明客户端已完成这些工作。
