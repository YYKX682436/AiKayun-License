# 本机授权管理 CLI

## 适用范围

`npm run admin -- ...` 是独立的本机受控管理服务入口，不是 Fastify 路由。它只接受 loopback PostgreSQL URL，并在 `NODE_ENV=production` 下拒绝运行。当前没有管理员 MFA；本工具只适用于隔离测试和受控开发运维，不能用于正式生产或远程管理。

CLI 不接收 `actor` 参数。它从实际 POSIX effective UID/用户名取得操作系统身份，并从 PostgreSQL 连接读取 `session_user` 和 `current_user`。二者都必须匹配受保护策略文件。`--reason` 是审计说明，不能证明身份、付款或授权。

管理连接需要单独的数据库 URL 文件；CLI 不会回退使用服务端 `LICENSE_DATABASE_URL`。策略文件与 URL 文件必须是普通文件、禁止符号链接，POSIX 权限为 `0600` 或更严格。数据库地址必须为 `localhost`、`127.0.0.1` 或 `::1`。策略只允许 `isolated-development`，没有 production policy 值。

CLI 不执行数据库迁移。使用前由数据库所有者先审查并应用授权中心迁移，再为隔离数据库配置专用管理角色；不要让 CLI 自行以高权限升级数据库结构。

示例策略文件（路径由 `LICENSE_ADMIN_POLICY_FILE` 指定）：

```json
{
  "environment": "isolated-development",
  "allowed_os_uids": [501],
  "database_role": "aikayun_license_admin",
  "database_url_file": "/absolute/private/path/license-admin-database.url"
}
```

将 `501` 替换为受信运维账户的真实 UID。策略文件和数据库 URL 凭据应由同一受控运维流程放置并设为 `0600`；不要提交仓库、粘贴到工单或放进 CI。开发测试可以为专用 `_test` 数据库配置隔离账号；不要把商城业务数据库或生产授权数据库放进本轮 CLI 配置。

若需要给隔离环境创建较窄的数据库角色，应由数据库所有者在授权中心测试/开发数据库中单独配置。以下仅是权限边界样例，**不会由迁移自动执行**：

```sql
CREATE ROLE aikayun_license_admin LOGIN;

GRANT SELECT ON licenses, license_activations, activation_codes,
  entitlement_events, license_audit_events,
  license_admin_operations, license_admin_audit_events
  TO aikayun_license_admin;
GRANT INSERT (id, account_id, plan, billing_anchor_utc, anchor_day,
  confirmed_subscription_end, status, entitlement_revision, revision,
  created_at, updated_at) ON licenses TO aikayun_license_admin;
GRANT UPDATE (billing_anchor_utc, anchor_day, confirmed_subscription_end,
  status, entitlement_revision, revision, updated_at)
  ON licenses TO aikayun_license_admin;

GRANT INSERT (id, license_id, token_hash, expires_at, created_at)
  ON activation_codes TO aikayun_license_admin;
GRANT UPDATE (revoked_at) ON activation_codes TO aikayun_license_admin;
GRANT INSERT ON entitlement_events, license_audit_events,
  license_admin_operations, license_admin_audit_events
  TO aikayun_license_admin;
```

CLI 的 license 创建依赖数据库默认 `current_generation=0`；激活码的 `consumed_at`/`revoked_at` 初始为空。该角色不需要访问实例的 `license_operations`、nonce、实例私钥或商城订单/支付数据。表所有者和 PostgreSQL 超级用户仍能更改 DDL 或移除触发器；数据库触发器不是对所有者/超级用户的防护。本轮没有配置生产数据库角色或生产管理员凭据。

## 写操作确认

所有写操作都需要固定 UUID `--operation-id`、明确 license ID、预期管理 revision、原因和人工确认。先以完整参数执行一次，不带 `--confirm-digest`；CLI 输出规范化请求摘要且不写数据库。人工复核后以**相同全部参数**再次执行，并追加输出的 `--confirm-digest`。摘要绑定 action、目标、revision、reason 及其他业务字段；改动任何字段都必须重新预览。该双步摘要是误操作保护，不替代 OS 身份或数据库认证。

创建操作的预期 revision 固定为 `0`，用于确认该 UUID 尚不存在。许可证初始 `revision=1`、`entitlement_revision=1`、`current_generation=0`。首账期按数据库 UTC 时间和原始 UTC anchor day 按月/年日历计算。

示例先预览，再确认：

```sh
export LICENSE_ADMIN_POLICY_FILE=/absolute/private/path/license-admin-policy.json
npm run admin -- license create \
  --operation-id 88888888-8888-4888-8888-888888888888 \
  --license-id 77777777-7777-4777-8777-777777777777 \
  --expected-revision 0 --plan monthly \
  --account-id internal-account-reference \
  --reason '人工核实授权申请资料'

# 复核上述输出后，使用同一请求和输出摘要执行：
npm run admin -- license create \
  --operation-id 88888888-8888-4888-8888-888888888888 \
  --license-id 77777777-7777-4777-8777-777777777777 \
  --expected-revision 0 --plan monthly \
  --account-id internal-account-reference \
  --reason '人工核实授权申请资料' \
  --confirm-digest '<上一步输出的请求摘要>'
```

其他写操作：

```sh
npm run admin -- license issue-code --operation-id <UUID> --license-id <UUID> \
  --expected-revision <N> --reason '<原因>' [--expires-in-hours 24] \
  [--replace-code-id <当前未消费码ID>] [--confirm-digest <摘要>]

npm run admin -- license renew --operation-id <UUID> --license-id <UUID> \
  --expected-revision <N> --business-reference '<已人工核实的内部业务引用>' \
  --reason '<原因>' [--confirm-digest <摘要>]

npm run admin -- license revoke --operation-id <UUID> --license-id <UUID> \
  --expected-revision <N> --reason '<原因>' [--confirm-digest <摘要>]

npm run admin -- license restore --operation-id <UUID> --license-id <UUID> \
  --expected-revision <N> --reason '<原因>' [--confirm-digest <摘要>]
```

年付许可证由建档时的 `plan=yearly` 决定；续费沿用许可证原月/年计划。续费命令仅表示授权管理员已人工确认业务事实：它不接收付款凭据、不连接收款渠道，也不会独立证明收款。续费复用既有 `applyConfirmedRenewal` UTC 账期算法与 `entitlement_events`，普通续费不会清除 `revoked` 状态。

签发、作废并重发激活码会递增管理 `revision`，但不递增权益 `entitlement_revision`。这让发码与同版本的续费、撤销或恢复共享 compare-and-swap 边界；并发操作中先提交的一方推进 revision，其他操作必须查询并按新版本重新确认。

撤销和恢复只切换 `active ↔ revoked`，并在事务中递增 `entitlement_revision` 与管理 `revision`。它们不改订阅截止时间、activation 行、`database_id`、`identity_jkt` 或 generation，也不伪造权益续费事件。恢复后的续签仍受原订阅截止时间限制；到期恢复不会产生有效 lease。身份私钥泄露不能通过恢复解决，迁移/换钥不在本轮范围。

## 一次性激活码

激活码使用 Node.js `crypto.randomBytes(32)` 生成；中心只保存 SHA-256/base64url 摘要。数据库有唯一摘要和每许可证单个未消费/未作废码的部分唯一索引。已消费/已作废行不可重写或删除；续签激活时还会检查未作废、未过期和未消费状态。

激活码只允许首次成功发码时从交互式 TTY 显示；CLI 会拒绝在 stdout 非 TTY 时执行发码。操作记录、授权审计、管理审计、查询命令和重放结果都不保存或回显明文。若提交已成功但终端输出丢失，按 operation ID 查询只能看到 code ID/到期时间，不能恢复旧明文。需要重发时，先读当前 license 和 code 状态，再以新 operation ID、当前 expected revision、原因及 `--replace-code-id` 明确作废当前码并重发。已激活许可证不能再发激活码。

## 查询与未知提交结果

```sh
npm run admin -- license get --license-id <UUID>
npm run admin -- operation get --operation-id <UUID>
npm run admin -- audit list --license-id <UUID> --limit 50
```

查询展示 UTC 截止时间、月/年计划、revision、当前/历史 activation 状态和 activation code 状态；不返回 code 摘要、JWK 公钥正文或任何私钥。`operation get` 返回稳定操作结果、真实 OS UID/用户名、数据库 role、原因、管理追加审计、授权审计及续费权益事件。

每个 operation ID 在 PostgreSQL advisory lock 下串行化。相同 ID + 相同摘要 + 同一 OS UID/数据库 role 会读取原终态；相同 ID 不同请求或不同执行身份会拒绝。COMMIT 确认丢失时，CLI 会用原 ID 查已提交结果；若无法确认，它报告未知状态。此时先查询原 operation ID，再决定是否以同一 ID、同一请求重试；不能生成新 ID 猜测结果。发码结果一旦进入重放路径，CLI 不会再次显示明文。

所有管理员操作和审计状态在同一 PostgreSQL 事务中提交。`license_admin_operations` 和 `license_admin_audit_events` 只追加；状态变化也追加到现有 `license_audit_events`；确认续费继续写入 `entitlement_events`。迁移增加 TRUNCATE 拒绝触发器。数据库所有者/超级用户可以改 DDL，这仍是后续数据库权限与生产安全审查边界。
