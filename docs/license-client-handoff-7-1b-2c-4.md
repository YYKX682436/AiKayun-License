# 授权中心 → 商城客户端交接（⑦-1B-2C-4）

本文件依据商城只读的 ⑦-1A R3 协议、发行架构与验收契约，以及授权中心截至 `302e998dd4ddb5e0ad15cd90531d981bf81ae0b0` 的源码和本轮联合验收整理。它是交接材料，不代表商城客户端已实现，也不构成进入下一阶段的授权。

## 1. 当前 HTTPS 配置与路由

授权中心要求 `LICENSE_ISSUER` 与 `LICENSE_PUBLIC_ORIGIN` 完全相同，二者必须为不带路径的 HTTPS origin。仓库示例为 `https://license.example.test`；**尚无正式生产域名/端点**。测试 origin 不能用于商业发行。

所有客户端 API 使用 HTTPS、严格 JSON schema（拒绝额外字段）、原始 body bytes、`no-store` 响应和 RFC 9421 HTTP Message Signatures。HTTP 签名按 R3 覆盖 `@method`、`@target-uri`、`content-type`、`content-digest`；`Content-Digest` 是 RFC 9530 SHA-256。使用 RFC9421 `alg=ed25519`、实例公钥 RFC7638 JKT 作为 `keyid`、`tag=aikayun-license-v1`，签名时间窗口不超过 60 秒。`request_digest` 是收到的 body 原始字节 SHA-256/base64url；不得重新 JSON 序列化来计算。

| HTTPS 路由 | 当前状态 | 关键请求字段/响应 |
| --- | --- | --- |
| `POST /v1/time-anchor` | 已实现 | `{client_nonce}`；返回 `{time_anchor}` 特殊 JWS，用于受信时间引导，不签商业许可。 |
| `POST /v1/challenges` | 已实现 | `{operation,operation_id,intent_digest,instance_id,public_jwk,client_nonce}`；以当前实例 key 证明持钥，返回一次性 challenge。 |
| `POST /v1/activations` | 已实现 | 公共 attempt 字段 + `activation_code,origin`。 |
| `POST /v1/leases/renew` | 已实现 | 公共 attempt 字段 + `expected_generation,known_revision`。 |
| `POST /v1/operations/query` | 已实现 | 公共 attempt 字段；`operation` 用 challenge 绑定 query；只查当前 actor 有权读取的 operation。 |
| `POST /v1/operations/continue` | 已实现 | activation/renewal/recovery 原业务字段 + `kind`；使用原 operation ID、原 intent 与新 attempt。 |
| `POST /v1/transfers/prepare` | 已实现 | 公共字段 + `approval_id,target_instance_id,target_identity_jkt,target_public_jwk,source_generation,expected_binding_revision,expected_revision`。 |
| `POST /v1/transfers/commit` | 已实现 | 公共字段 + `approval_id,prepare_operation_id,transfer_ticket`；目标实例签名。 |
| `POST /v1/disaster-transfers/prepare` | 已实现 | 公共字段 + `approval_id,request_id,account_reference,source_activation_id,source_instance_id,source_identity_jkt,target_instance_id,target_identity_jkt,source_generation,expected_binding_revision,expected_revision`。 |
| `POST /v1/disaster-transfers/commit` | 已实现 | 公共字段 + `approval_id,prepare_operation_id,disaster_ticket`；目标实例签名。 |
| `POST /v1/time-resets/commit` | 已实现 | 公共字段 + `activation_id,approval_id,expected_generation,expected_revision,expected_entitlement_revision,expected_time_epoch,old_watermark_digest`。管理员先在隔离 CLI 创建/审核审批；没有公网管理员 HTTP API。 |
| `POST /v1/origin` | **未实现** | R3 中的 origin 更新草案不属于当前中心路由。 |

公共 attempt 字段为：`operation_id,intent_digest,attempt_no,license_id,database_id,instance_id,identity_jkt,public_jwk,challenge`。`public_jwk` 精确为 `{kty:"OKP",crv:"Ed25519",x}`，禁止 `d` 和未知字段。实际每个 endpoint 的唯一 schema 以 `src/app.ts` 为准；request schema 不可通过“兼容”而放宽。

### JWT/JWS 类型

所有中心 token 的受保护 header 精确只有 `{alg:"Ed25519",kid,typ}`，无 `crit/jwk/jku/x5u`。Compact JWS、严格 JSON、Base64URL 和精确 claims allowlist；不可对错误 typ/audience 做 fallback。

| 用途 | Header `typ` / Audience | 必要字段和时间边界 |
| --- | --- | --- |
| 经营 lease | `aikayun-license+jwt` / `aikayun-commerce` | 精确 claims：`v,iss,aud,sub,jti,iat,nbf,exp,instance_id,database_id,identity_jkt,activation_generation,entitlement_revision,plan,subscription_end,renew_after,grants,request_nonce,request_digest`。`nbf=iat`；`exp=min(iat+604800,subscription_end)`；`renew_after=min(iat+21600,exp)`；grants 固定为 `create_order,create_top_up`。 |
| Challenge | `aikayun-license-challenge+jwt` / `aikayun-commerce` | `v,iss,aud,sub,jti,iat,nbf,exp,operation,operation_id,intent_digest,instance_id,identity_jkt,client_nonce,server_nonce`；最长 300 秒，绑定 operation/intent/实例/JKT 和两个 nonce，不是 lease。 |
| Operation 查询/继续 | `aikayun-license-operation+jwt` / `aikayun-commerce` | `v,iss,aud,sub,jti,iat,nbf,exp,actor_jkt,operation_id,intent_digest,state,outcome_code,attempt_no,request_nonce_hash,request_digest,committed_attempt_no,committed_request_nonce_hash,committed_request_digest,result_jws`；外层最长 5 分钟。`result_jws` 是数据库保存的历史原始结果，不重签。 |
| Status | `aikayun-license-status+jwt` / `aikayun-commerce` | `v,iss,aud,sub,jti,iat,nbf,exp,instance_id,identity_jkt,activation_generation,current_generation,entitlement_revision,subscription_end,status,request_nonce,request_digest`；状态为 expired/revoked/superseded，最长 5 分钟，不含 grants。 |
| 正常迁移 ticket | `aikayun-license-transfer-ticket+jwt` / `aikayun-commerce` | 绑定 plan、approval/prepare operation 与摘要、nonce/digest、license/database/source/target identity、generation、binding revision、管理和 entitlement revision；有效不超过 10 分钟。 |
| 正常迁移 receipt | `aikayun-license-transfer+jwt` / `aikayun-commerce` | `src/receipts.ts` `transferReceiptClaims` 精确列出 operation/request、source/target generation 与 JKT、binding/management/entitlement revision、subscription_end、嵌套 `new_lease`；最长 10 分钟且不能越 subscription_end。 |
| 灾难 ticket | `aikayun-license-disaster-transfer-ticket+jwt` / `aikayun-commerce` | 另含 `account_reference,source_activation_id,approval_request_digest,request_id` 等 disaster 审批绑定字段；最长 10 分钟。 |
| 灾难 active result | `aikayun-license-disaster-transfer+jwt` / `aikayun-commerce` | 明确 `result_mode=active_lease`、`license_status=active`、source/target/binding/revision 绑定和嵌套 lease。 |
| 灾难 binding-only result | `aikayun-license-disaster-binding+jwt` / `aikayun-commerce` | 明确 `result_mode=binding_only`、`purpose=historical_obligations_identity_rebinding`、`entitlement_state=expired|revoked`；**没有 lease/grants**，只证明灾难身份重绑。 |
| 时间锚 | `aikayun-time-anchor+jwt` / `aikayun-time-bootstrap` | `v,iss,aud,sub,jti,iat,nbf,exp,server_time,client_nonce`；`iat=nbf=server_time`，`exp=server_time+30`，精确匹配客户端 nonce。 |
| time-reset receipt | `aikayun-time-reset+jwt` / `aikayun-time-recovery` | `src/crypto/time-reset.ts` 的精确 claims：license/database/instance/JKT、generation、management/entitlement revision、old/new epoch、水位摘要、operation/intent/request nonce/client nonce/digest、管理员审批/审计身份；10 分钟新鲜窗口，new epoch 必须 old+1。不是经营许可。 |
| Offline trust bundle | `aikayun-license-trust-bundle+jwt` / `aikayun-license-signing-keys` | 由预置离线 Ed25519 root 签；`iss=urn:aikayun:license:offline-release-root:v1`，`sub` 精确为中心 issuer；bundle schema/version/time window/key lifecycle 按 `src/trust/trust-bundle.ts` 精确验证。 |

`src/receipts.ts` 中的精确 ticket/result claims、`src/services/common.ts` 的 challenge claims、`src/crypto/time-reset.ts` 的时间 claims、`src/trust/trust-bundle.ts` 的 bundle claims 是 schema 权威。这里的列表用于客户端交接，不取代代码的严格验证器。

## 2. Root pin 与 bundle 版本

客户端发行工件必须预置**生产离线 root 的公钥 JWK**、预期 center issuer 和最低 bundle 版本。root private key 永远不进中心服务、商城或 Docker 镜像。授权中心配置名为 `LICENSE_OFFLINE_ROOT_JWK_FILE` 与 `LICENSE_TRUST_BUNDLE_MIN_VERSION`；`.env.example` 的 `license.example.test` 和 minimum `1` 只是开发示例。生产 root、JWK/JKT、最低版本、正式 bundle 和客户端下发 artifact **尚未创建/验收**，不可照抄示例值。

每个生产发行版本都要把 minimum version 做成可信发行配置，而不是以“下载到的第一个包”作为 root 或版本锚。TrustBundleStore 的 root-signed package 接受后保存当前 JWS、bundle version、SHA-256、`revoked_kids`/`retired_kids` 及单独 checkpoint；版本只增，state/checkpoint 分叉或损坏即 fail closed。保留每个受支持版本可验证历史正常退休 key 到 `verify_until`；`retire_after` 与 `verify_until` 都是排除边界。紧急吊销在接受新 bundle 后立即拒绝该 kid；本地完全离线实例无法即时知道吊销。

## 3. 客户端启动、校时、信任包、lease 的顺序

以下顺序用于未来实现。每一步失败时保持现有 last-good 和历史义务，未验签数据不得进入投影或准入状态。

1. 从受信发行工件读取 root JWK、issuer 与最低 bundle version；加载原子持久化的 `TrustBundleStore` 状态和 checkpoint。状态文件、checkpoint、schema 或权限异常即 fail closed；不把网络候选包当作首次 root。
2. 先校验新候选 bundle 的 compact JWS、严格 header/claims、离线 root 签名、center issuer、root kid、schema 和最低/现有版本/墓碑连续性，形成尚未持久接受的 candidate。
3. 保持真实 TLS 证书验证开启，向候选中心发 nonce 绑定的 HTTPS `/v1/time-anchor` 请求；记录单调时钟发出/收到时间和 RTT，要求不超过 5000ms。用 candidate 中对应的受信 center key 验签 anchor，验证 `client_nonce`、`iss/aud/typ/kid`、`iat=nbf=server_time`、`exp=server_time+30` 和 key 生命周期；再以 anchor 的 `server_time` 验 candidate bundle 时间窗及所有 key。**时间锚不授予经营 grants。**
4. 所有检查通过后调用 TrustBundleStore 的原子接受流程；先处理/恢复明确的 pending/checkpoint 写入，再确认 state 与 checkpoint 一致和 version 只增。不可先用未接受 candidate 的 resolver 验 lease。
5. 以 `getAccepted(trustedTime)` 建立 resolver。对 lease 按精确 typ/aud/issuer/schema 和 bundle 中 `kid`、时间窗验签；核对 `instance_id,database_id,identity_jkt` 与本机持久绑定；比较 generation、entitlement revision、拒新事实、subscription_end 和 time_epoch；事务内重读水位后才更新投影。
6. **TLS 校时边界：** HTTPS 底层证书验证通常依赖系统时间。系统时间严重错误到无法验证 TLS 时，代码层面的 root-signed anchor 不能安全绕过证书校验。本轮没有关闭 TLS 验证，也没有声称解决启动 TLS 校时；需在后续商城客户端/发行设计中单独给出安全可验收的 TLS 引导方案。

## 4. 商城端 durable pending operation 与证据投影

商城 ⑦-1A 指定唯一 pending 权威为 `local_license_operations`；不是另建一张 pending 表，也不是把文件 journal 做成第二套业务状态。建议投影结构及字段见只读契约 `/Users/muchen/Documents/ChatGPT/AiKayun/docs/license-protocol-7-1a.md` §5.1。

新业务意图在任何网络发送前固定 `operation_id`、JCS `intent_digest`、身份/database/license 绑定和加密 pending payload。父 operation 的 intent 不变；每个 attempt append-only 递增 `attempt_no`，保存该次 client/server nonce 的 hash、原始 body `request_digest`、身份 JKT、签名 kid/created/expires、结果/可重试原因。attempt_no 在同一 operation 中不可复用，包括 query/continue；每次取新 challenge 都用新 attempt number。

超时、断连、5xx、COMMIT 确认未知和单次 query `not_found` 都不产生可重试的新 operation，也不证明原请求未提交。保留 pending，以新 challenge、nonce、attempt 继续/查询同一个 operation；query 的 `not_found` 只说明那次查询线性化时未见操作，迟到原事务仍可能提交。未认证请求不得写业务操作历史。

收到已签名响应后，先把原始 JWS bytes 加密持久化并 fsync，再验证 outer operation receipt 与本地固定 intent/attempt/actor/nonce hash/request digest；如有内嵌 result，保留中心提交的原 JWS bytes/kid，不重签或更新成新 kid。验证 lease/receipt 后才在授权 projection 事务中锁定并重读当前身份、generation、entitlement revision、状态及 time epoch；投影完成后读回 `jti`/generation/revision/operation ID 核对，再清理仅可清理的敏感 pending payload。数据库 commit 确认未知时按持久 operation 查询投影，不重复业务提交。文件与数据库的跨介质恢复使用引用 operation ID 的可重建 journal，stage/fsync/原子指针切换/最终 ready 阶段都必须可幂等恢复；`ready` 前拒绝新经营。

普通 `renew` 不得因收到更高 generation 而自动迁移。更高 generation 只接受预先持久化的迁移 pending 与匹配的已验签迁移提交 receipt。`raw_evidence` 保存原签名，服务启动重新验签；未经验证的 JSON 不得映射成 `allow=true`。撤销、superseded、identity mismatch 和 clock suspect 的拒新事实不能被旧 lease 或更高 `iat` 抹除。

## 5. 单调值各自的含义

| 值 | 权威/递增条件 | 不能用来替代 |
| --- | --- | --- |
| `activation_generation` | 中心 license 的 active activation 代次；迁移/灾难重绑成功才增加 | entitlement revision、管理 revision、time_epoch、signer revision |
| `entitlement_revision` | 当前签名权益/续费/撤销/显式恢复状态的水位；中心确认权益状态变化时推进 | activation generation；升 revision 不等于换实例 |
| `time_epoch` | 每条 activation 上的时钟恢复 epoch；仅已审批、绑定 generation 的 reset 一次加一 | generation/权益授权；reset 不恢复 revoked/expired grants |
| `bundle_version` | 离线 root 签名 trust bundle 的接受版本，由客户端 store 保持单调 | center signer key 切换序号；bundle 版本变化不必然切 signer |
| `signer_revision` | 中心 PostgreSQL signer authority 的 active kid 身份代次；初始化/受控轮换推进 | bundle version；接收 bundle 不一定推进 signer revision |
| `revision` / `management_revision` | license 管理 CAS 与 time-reset 回执中的管理状态版本 | entitlement revision 或代次 |
| `binding_revision` / `expected_binding_revision` | 商城本机绑定恢复/迁移所依据的旧绑定版本 | 中心 generation 或业务数据库 UUID |
| `database_id` | 首次建立业务数据库时生成并在迁移中保留的稳定 ID | 容器、域名、实例身份或 generation |

所有 bigint 以规范十进制字符串通过 JSON 传递，不转成浮点 number。

## 6. 经营准入、恢复和历史义务

- 激活必须用已持久化的 activation operation/attempt 和短期 activation code。已提交重试取原签名响应，不再次消费 code 或增加 generation。
- 周期续签每约 6 小时（R3 建议带 ±10% 抖动）检查；中心仅在当前 activation、database_id、JKT、generation、权益仍 active 且 `now < subscription_end` 时签发。正常 lease 最长 7 天，不能超订阅截止。网络故障只允许现有 lease 到原 `min(exp,subscription_end)`；不自创宽限期。
- 原激活 operation 已提交而本地没有完成投影：先用当前实例 PoP query 原 operation、核对原 nonce hash/request digest/JKT/kid 和中心原 response，再创建新的持久 recovery operation 引用原 activation operation。原 lease 过期时只作历史签名证据；center 按当前权威状态签一个新的短期 lease，不重激活、不消耗 code、不升 generation。撤销、到期、superseded 不得签出经营 lease。
- 正常迁移需要原实例 PoP 与管理员审批；灾难迁移需要独立审批/身份核验和 target PoP。两者均以 center 提交回执、generation +1 与单一 active activation 作为中心线性化结果。本地必须有预先持久化的 pending binding change；先恢复同一 database_id、原业务 UUID/key 与支付/供应商在途事实，应用跨 DB/文件 journal，读回成功后才恢复新经营。
- 灾难迁移在仍 active 时可返回带新 lease 的 `aikayun-license-disaster-transfer+jwt`；对 expired/revoked license 返回的 `aikayun-license-disaster-binding+jwt` 只处理历史义务所需的身份重绑，**不授权新订单/充值**。普通 lease、status、operation receipt、binding receipt 互相不能替代。
- time-reset 回执只能为匹配的 activation generation 在本地开启更高 time_epoch，并绑定审批、原水位摘要、nonce、request digest。随后仍需有效的、符合当前状态的 lease；它不变更 subscription_end、generation、entitlement revision 或 revoked 状态。
- 商城最终订单/充值授权门禁和旧义务保护尚未实现。R3 要求只在新订单和新充值的最终数据库事务边界作许可判断；旧订单付款/支付重试、退款、提现、履约、业务文件下载、对账与历史查询不能因 lease 到期/撤销而停止。每个具体业务入口仍需商城端真实 DB/worker 故障验收，授权中心测试不能证明其已完成。
- 中心的 generation 只保证逻辑唯一 activation；不能证明旧服务器已物理关机，也不能阻止完整复制且持有身份 key 的离线系统继续持有旧 lease。紧急吊销不能瞬时传达到完全离线实例。

## 7. ⑦-1A R3 差异、现状及后续门禁

| ⑦-1A R3 项 | 当前中心 / 本轮审查结论 | 商城端/发行状态 |
| --- | --- | --- |
| Ed25519 JWS、RFC9421/9530、严格 issuer/audience/typ、精确原始 digest | 中心实现并与 R3 lease/challenge/operation 基本契约核对；A/B lifecycle、历史操作与真实 TLS/PG 请求有测试 | 商城客户端新的 trust resolver 和 HTTP 实现尚未实现。不得为模拟旧实现放宽 typ/权限。 |
| activation、renewal/recovery、operation query/continue、normal transfer、灾难迁移、time-reset | 中心端点与服务/DB operation 已实现；本轮针对跨轮换/并发路径验收 | 商城 pending、projection、持久 journal、两项业务准入仍未实现。 |
| Trust bundle / online-key rotation | 中心有 007 数据库 signer authority、受控开发/测试轮换；独立客户端 TrustBundleStore 提供文件状态/checkpoint 组件 | 正式 root、客户预置 pin/minimum、bundle 发布/传播/客户接受证明未实现。 |
| R3 `/v1/origin` | 当前中心源码无该 endpoint；仅 R3 设计条目 | 若仍需要，需单独定义/授权；客户端不能假设存在。 |
| R3 将 normal/disaster receipt 合并描述为 `aikayun-license-transfer+jwt` + lease | normal transfer 仍为通用 transfer receipt。灾难路径已审查并细分为 active 带 lease 与 expired/revoked binding-only 两种专属 typ/schema；binding-only 用于历史义务身份恢复 | 商城客户端需要两个独立严格 schema；是否对 R3 文字作正式协议修订应由独立验收明确，不能把实现静默写回旧文档。 |
| 生产密钥与管理安全 | admin CLI 仍仅隔离开发/测试，`NODE_ENV=production` 禁用；没有公网管理 API | 生产 MFA/双人审批、KMS/HSM 或等效密钥托管、离线根异地备份/恢复、正式 bundle 发布批准、独立时间源监测、备份恢复和真实客户灾备演练均未验证。 |
| HTTPS 时间引导 | anchor 使用正确 TLS 与 root-authenticated key 的密码验证已测；候选 bundle 只在接受后成为客户端状态 | 系统时间错到 TLS 证书不能验证的启动情形没有解决。 |

中心仓库当前 GitHub 可见性为 **Public**，与 README 所述独立私有及正式闭源商业发行目标冲突。此次只记录为发行风险，没有改变仓库可见性。仓库可见性决策、许可证合规和正式代码交付控制必须在商业发行前单独处理。

生产 root/MFA、密钥托管与备份、正式 bundle 传播/客户确认、独立时间源监控、TLS 校时客户端和真实灾备核验均为独立评估与发行前门禁。本交接完成后停止；不得自动进入商城客户端开发、生产发行或部署。
