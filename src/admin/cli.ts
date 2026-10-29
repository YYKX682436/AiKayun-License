import { AdminOperationError, createAdminService, createLicenseRequestDigest, issueActivationCodeRequestDigest,
  renewLicenseRequestDigest, changeLicenseStatusRequestDigest, approveTransferRequestDigest,
  revokeTransferApprovalRequestDigest,
  approveDisasterTransferRequestDigest, revokeDisasterTransferApprovalRequestDigest,
  approveTimeResetRequestDigest, revokeTimeResetApprovalRequestDigest,
  type AdminOperationResult } from './service.js';
import { AdminAccessError } from './policy.js';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

type OutputStream = NodeJS.WriteStream & { isTTY?: boolean };

const helpText = `艾卡云授权中心本机管理 CLI（仅隔离测试/受控开发）

写操作使用两步确认：先运行不带 --confirm-digest 的命令，复核输出摘要；再用同一参数追加 --confirm-digest <请求摘要> 执行。
所有写命令必须提供稳定 --operation-id、明确目标、expected revision 和 --reason。

命令：
  license create --operation-id UUID --license-id UUID --expected-revision 0 --plan monthly|yearly --account-id REF --reason TEXT [--confirm-digest DIGEST]
  license issue-code --operation-id UUID --license-id UUID --expected-revision N --reason TEXT [--expires-in-hours 24] [--replace-code-id UUID] [--confirm-digest DIGEST]
  license renew --operation-id UUID --license-id UUID --expected-revision N --business-reference REF --reason TEXT [--confirm-digest DIGEST]
  license revoke --operation-id UUID --license-id UUID --expected-revision N --reason TEXT [--confirm-digest DIGEST]
  license restore --operation-id UUID --license-id UUID --expected-revision N --reason TEXT [--confirm-digest DIGEST]
  license approve-transfer --operation-id UUID --license-id UUID --expected-revision N --database-id UUID --source-instance-id UUID --source-identity-jkt JKT --target-instance-id UUID --target-identity-jkt JKT --source-generation N --expected-binding-revision N --reason TEXT [--confirm-digest DIGEST]
  license revoke-transfer-approval --operation-id UUID --license-id UUID --approval-id UUID --expected-revision N --reason TEXT [--confirm-digest DIGEST]
  license approve-disaster-transfer --operation-id UUID --license-id UUID --expected-revision N --account-reference REF --source-activation-id UUID --database-id UUID --source-instance-id UUID --source-identity-jkt JKT --source-generation N --target-instance-id UUID --target-instance-mode preserve|replace --target-identity-jkt JKT --expected-binding-revision N --incident-type TYPE --recovery-reason TEXT --verification-record-ref case:REF --backup-check-result VALUE --old-server-isolation VALUE --reason TEXT [--expires-in-hours 24] [--confirm-digest DIGEST]
  license revoke-disaster-transfer-approval --operation-id UUID --license-id UUID --approval-id UUID --expected-revision N --reason TEXT [--confirm-digest DIGEST]
  license approve-time-reset --operation-id UUID --license-id UUID --expected-revision N --activation-id UUID --database-id UUID --instance-id UUID --identity-jkt JKT --activation-generation N --entitlement-revision N --expected-time-epoch N --reset-operation-id UUID --intent-digest DIGEST --old-watermark-digest DIGEST --reason TEXT [--expires-in-hours 24] [--confirm-digest DIGEST]
  license revoke-time-reset-approval --operation-id UUID --license-id UUID --approval-id UUID --expected-revision N --reason TEXT [--confirm-digest DIGEST]
  license get --license-id UUID
  operation get --operation-id UUID
  audit list --license-id UUID [--limit 50]

CLI 不提供 actor 参数。执行身份来自 allowlisted OS UID 与已认证的独立 PostgreSQL session_user；reason 只是审计备注。
`;

function fail(code: string): never {
  throw new AdminOperationError(code);
}

function parseFlags(args: string[]): Map<string, string> {
  const options = new Map<string, string>();
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    if (!flag || !flag.startsWith('--') || flag === '--') fail('ADMIN_ARGUMENT_INVALID');
    if (options.has(flag)) fail('ADMIN_ARGUMENT_DUPLICATE');
    const value = args[index + 1];
    if (!value || value.startsWith('--')) fail('ADMIN_ARGUMENT_VALUE_REQUIRED');
    options.set(flag, value);
    index += 1;
  }
  return options;
}

function option(options: Map<string, string>, name: string): string {
  const value = options.get(`--${name}`);
  if (value === undefined) fail(`ADMIN_ARGUMENT_${name.toUpperCase().replaceAll('-', '_')}_REQUIRED`);
  return value;
}

function optionalOption(options: Map<string, string>, name: string): string | undefined {
  return options.get(`--${name}`);
}

function assertAllowedOptions(options: Map<string, string>, names: string[]): void {
  const allowed = new Set(names.map((name) => `--${name}`));
  for (const name of options.keys()) if (!allowed.has(name)) fail('ADMIN_ARGUMENT_UNKNOWN');
}

function printJson(stream: OutputStream, value: unknown): void {
  stream.write(`${JSON.stringify(value, null, 2)}\n`);
}

function writeReview(stream: OutputStream, action: string, requestDigest: string, fields: Record<string, unknown>): void {
  printJson(stream, {
    review_required: true,
    action,
    fields,
    request_digest: requestDigest,
    instruction: '复核字段后以完全相同的请求追加 --confirm-digest <request_digest> 执行；本次没有写入数据库。',
  });
}

function withoutSecret(result: AdminOperationResult): Omit<AdminOperationResult, 'activationCode'> {
  const { activationCode: _activationCode, ...safe } = result;
  return safe;
}

async function runMutation(argv: string[], stdout: OutputStream): Promise<number> {
  const [domain, verb, ...flagArgs] = argv;
  if (domain !== 'license' || !verb) fail('ADMIN_COMMAND_INVALID');
  const options = parseFlags(flagArgs);
  const confirm = optionalOption(options, 'confirm-digest');

  let action = '';
  let digest = '';
  let fields: Record<string, unknown> = {};
  let invoke: (service: Awaited<ReturnType<typeof createAdminService>>) => Promise<AdminOperationResult>;

  if (verb === 'create') {
    assertAllowedOptions(options, ['operation-id', 'license-id', 'expected-revision', 'plan', 'account-id', 'reason', 'confirm-digest']);
    const request = {
      operationId: option(options, 'operation-id'),
      licenseId: option(options, 'license-id'),
      expectedRevision: option(options, 'expected-revision') as '0',
      plan: option(options, 'plan') as 'monthly' | 'yearly',
      accountId: option(options, 'account-id'),
      reason: option(options, 'reason'),
    };
    if (request.expectedRevision !== '0') fail('ADMIN_EXPECTED_REVISION_INVALID');
    action = 'license_create';
    digest = createLicenseRequestDigest(request);
    fields = request;
    invoke = (service) => service.createLicense({ ...request, confirmedRequestDigest: confirm ?? '' });
  } else if (verb === 'issue-code') {
    assertAllowedOptions(options, ['operation-id', 'license-id', 'expected-revision', 'reason', 'expires-in-hours', 'replace-code-id', 'confirm-digest']);
    const expiryText = optionalOption(options, 'expires-in-hours');
    const expiresInHours = expiryText === undefined ? 24 : Number(expiryText);
    if (!Number.isInteger(expiresInHours)) fail('ADMIN_CODE_EXPIRY_INVALID');
    const request = {
      operationId: option(options, 'operation-id'),
      licenseId: option(options, 'license-id'),
      expectedRevision: option(options, 'expected-revision'),
      reason: option(options, 'reason'),
      expiresInHours,
      ...(optionalOption(options, 'replace-code-id') ? { replaceCodeId: optionalOption(options, 'replace-code-id')! } : {}),
    };
    action = 'activation_code_issue';
    digest = issueActivationCodeRequestDigest(request);
    fields = request;
    invoke = (service) => service.issueActivationCode({ ...request, confirmedRequestDigest: confirm ?? '' });
  } else if (verb === 'renew') {
    assertAllowedOptions(options, ['operation-id', 'license-id', 'expected-revision', 'business-reference', 'reason', 'confirm-digest']);
    const request = {
      operationId: option(options, 'operation-id'),
      licenseId: option(options, 'license-id'),
      expectedRevision: option(options, 'expected-revision'),
      businessReference: option(options, 'business-reference'),
      reason: option(options, 'reason'),
    };
    action = 'license_renew';
    digest = renewLicenseRequestDigest(request);
    fields = request;
    invoke = (service) => service.renewLicense({ ...request, confirmedRequestDigest: confirm ?? '' });
  } else if (verb === 'revoke' || verb === 'restore') {
    assertAllowedOptions(options, ['operation-id', 'license-id', 'expected-revision', 'reason', 'confirm-digest']);
    const request = {
      operationId: option(options, 'operation-id'),
      licenseId: option(options, 'license-id'),
      expectedRevision: option(options, 'expected-revision'),
      reason: option(options, 'reason'),
    };
    const statusAction = verb === 'revoke' ? 'license_revoke' : 'license_restore';
    action = statusAction;
    digest = changeLicenseStatusRequestDigest(request, statusAction);
    fields = request;
    invoke = (service) => verb === 'revoke'
      ? service.revokeLicense({ ...request, confirmedRequestDigest: confirm ?? '' })
      : service.restoreLicense({ ...request, confirmedRequestDigest: confirm ?? '' });
  } else if (verb === 'approve-transfer') {
    assertAllowedOptions(options, [
      'operation-id', 'license-id', 'expected-revision', 'database-id', 'source-instance-id', 'source-identity-jkt',
      'target-instance-id', 'target-identity-jkt', 'source-generation', 'expected-binding-revision', 'reason', 'confirm-digest',
    ]);
    const request = {
      operationId: option(options, 'operation-id'),
      licenseId: option(options, 'license-id'),
      expectedRevision: option(options, 'expected-revision'),
      databaseId: option(options, 'database-id'),
      sourceInstanceId: option(options, 'source-instance-id'),
      sourceIdentityJkt: option(options, 'source-identity-jkt'),
      targetInstanceId: option(options, 'target-instance-id'),
      targetIdentityJkt: option(options, 'target-identity-jkt'),
      sourceGeneration: option(options, 'source-generation'),
      expectedBindingRevision: option(options, 'expected-binding-revision'),
      reason: option(options, 'reason'),
    };
    action = 'transfer_approve';
    digest = approveTransferRequestDigest(request);
    fields = request;
    invoke = (service) => service.approveTransfer({ ...request, confirmedRequestDigest: confirm ?? '' });
  } else if (verb === 'revoke-transfer-approval') {
    assertAllowedOptions(options, ['operation-id', 'license-id', 'approval-id', 'expected-revision', 'reason', 'confirm-digest']);
    const request = { operationId: option(options, 'operation-id'), licenseId: option(options, 'license-id'),
      approvalId: option(options, 'approval-id'), expectedRevision: option(options, 'expected-revision'), reason: option(options, 'reason') };
    action = 'transfer_revoke';
    digest = revokeTransferApprovalRequestDigest(request);
    fields = request;
    invoke = (service) => service.revokeTransferApproval({ ...request, confirmedRequestDigest: confirm ?? '' });
  } else if (verb === 'approve-disaster-transfer') {
    assertAllowedOptions(options, [
      'operation-id', 'license-id', 'expected-revision', 'account-reference', 'source-activation-id', 'database-id',
      'source-instance-id', 'source-identity-jkt', 'source-generation', 'target-instance-id', 'target-instance-mode',
      'target-identity-jkt', 'expected-binding-revision', 'incident-type', 'recovery-reason', 'verification-record-ref',
      'backup-check-result', 'old-server-isolation', 'reason', 'expires-in-hours', 'confirm-digest',
    ]);
    const expiryText = optionalOption(options, 'expires-in-hours');
    const expiresInHours = expiryText === undefined ? 24 : Number(expiryText);
    if (!Number.isInteger(expiresInHours)) fail('ADMIN_DISASTER_APPROVAL_EXPIRY_INVALID');
    const request = {
      operationId: option(options, 'operation-id'),
      licenseId: option(options, 'license-id'),
      expectedRevision: option(options, 'expected-revision'),
      accountReference: option(options, 'account-reference'),
      sourceActivationId: option(options, 'source-activation-id'),
      databaseId: option(options, 'database-id'),
      sourceInstanceId: option(options, 'source-instance-id'),
      sourceIdentityJkt: option(options, 'source-identity-jkt'),
      sourceGeneration: option(options, 'source-generation'),
      targetInstanceId: option(options, 'target-instance-id'),
      targetInstanceMode: option(options, 'target-instance-mode') as 'preserve' | 'replace',
      targetIdentityJkt: option(options, 'target-identity-jkt'),
      expectedBindingRevision: option(options, 'expected-binding-revision'),
      incidentType: option(options, 'incident-type') as 'private_key_lost' | 'instance_unavailable' | 'identity_material_lost' | 'other',
      recoveryReason: option(options, 'recovery-reason'),
      verificationRecordRef: option(options, 'verification-record-ref'),
      backupCheckResult: option(options, 'backup-check-result') as 'database_identity_and_history_reviewed' | 'identity_material_missing' | 'unable_to_verify',
      oldServerIsolation: option(options, 'old-server-isolation') as 'confirmed_isolated' | 'unknown' | 'not_confirmed',
      expiresInHours,
      reason: option(options, 'reason'),
    };
    action = 'disaster_transfer_approve';
    digest = approveDisasterTransferRequestDigest(request);
    fields = request;
    invoke = (service) => service.approveDisasterTransfer({ ...request, confirmedRequestDigest: confirm ?? '' });
  } else if (verb === 'revoke-disaster-transfer-approval') {
    assertAllowedOptions(options, ['operation-id', 'license-id', 'approval-id', 'expected-revision', 'reason', 'confirm-digest']);
    const request = {
      operationId: option(options, 'operation-id'),
      licenseId: option(options, 'license-id'),
      approvalId: option(options, 'approval-id'),
      expectedRevision: option(options, 'expected-revision'),
      reason: option(options, 'reason'),
    };
    action = 'disaster_transfer_revoke';
    digest = revokeDisasterTransferApprovalRequestDigest(request);
    fields = request;
    invoke = (service) => service.revokeDisasterTransferApproval({ ...request, confirmedRequestDigest: confirm ?? '' });
  } else if (verb === 'approve-time-reset') {
    assertAllowedOptions(options, [
      'operation-id', 'license-id', 'expected-revision', 'activation-id', 'database-id', 'instance-id', 'identity-jkt',
      'activation-generation', 'entitlement-revision', 'expected-time-epoch', 'reset-operation-id', 'intent-digest',
      'old-watermark-digest', 'reason', 'expires-in-hours', 'confirm-digest',
    ]);
    const expiryText = optionalOption(options, 'expires-in-hours');
    const expiresInHours = expiryText === undefined ? 24 : Number(expiryText);
    if (!Number.isInteger(expiresInHours)) fail('ADMIN_TIME_RESET_APPROVAL_EXPIRY_INVALID');
    const request = {
      operationId: option(options, 'operation-id'),
      licenseId: option(options, 'license-id'),
      expectedRevision: option(options, 'expected-revision'),
      activationId: option(options, 'activation-id'),
      databaseId: option(options, 'database-id'),
      instanceId: option(options, 'instance-id'),
      identityJkt: option(options, 'identity-jkt'),
      activationGeneration: option(options, 'activation-generation'),
      entitlementRevision: option(options, 'entitlement-revision'),
      expectedTimeEpoch: option(options, 'expected-time-epoch'),
      resetOperationId: option(options, 'reset-operation-id'),
      intentDigest: option(options, 'intent-digest'),
      oldWatermarkDigest: option(options, 'old-watermark-digest'),
      expiresInHours,
      reason: option(options, 'reason'),
    };
    action = 'time_reset_approve';
    digest = approveTimeResetRequestDigest(request);
    fields = request;
    invoke = (service) => service.approveTimeReset({ ...request, confirmedRequestDigest: confirm ?? '' });
  } else if (verb === 'revoke-time-reset-approval') {
    assertAllowedOptions(options, ['operation-id', 'license-id', 'approval-id', 'expected-revision', 'reason', 'confirm-digest']);
    const request = {
      operationId: option(options, 'operation-id'),
      licenseId: option(options, 'license-id'),
      approvalId: option(options, 'approval-id'),
      expectedRevision: option(options, 'expected-revision'),
      reason: option(options, 'reason'),
    };
    action = 'time_reset_revoke';
    digest = revokeTimeResetApprovalRequestDigest(request);
    fields = request;
    invoke = (service) => service.revokeTimeResetApproval({ ...request, confirmedRequestDigest: confirm ?? '' });
  } else {
    fail('ADMIN_COMMAND_INVALID');
  }

  if (!confirm) {
    writeReview(stdout, action, digest, fields);
    return 0;
  }
  if (confirm !== digest) fail('ADMIN_CONFIRMATION_DIGEST_MISMATCH');
  if (verb === 'issue-code' && !stdout.isTTY) fail('ADMIN_ACTIVATION_CODE_REQUIRES_TTY');
  const service = await createAdminService();
  try {
    const result = await invoke(service);
    printJson(stdout, withoutSecret(result));
    if (result.activationCode) stdout.write(`一次性激活码（仅本次显示）: ${result.activationCode}\n`);
    else if (verb === 'issue-code' && result.replayed) stdout.write('该操作已提交；原激活码明文不可恢复，请按审计结果受控作废并重发。\n');
    return result.state === 'succeeded' ? 0 : 2;
  } finally {
    await service.close();
  }
}

async function runRead(argv: string[], stdout: OutputStream): Promise<number> {
  const [domain, verb, ...flagArgs] = argv;
  const options = parseFlags(flagArgs);
  const service = await createAdminService();
  try {
    if (domain === 'license' && verb === 'get') {
      assertAllowedOptions(options, ['license-id']);
      const license = await service.getLicense(option(options, 'license-id'));
      if (!license) {
        printJson(stdout, { found: false });
        return 1;
      }
      printJson(stdout, license);
      return 0;
    }
    if (domain === 'operation' && verb === 'get') {
      assertAllowedOptions(options, ['operation-id']);
      const operation = await service.getOperation(option(options, 'operation-id'));
      if (!operation) {
        printJson(stdout, { found: false });
        return 1;
      }
      printJson(stdout, operation);
      return 0;
    }
    if (domain === 'audit' && verb === 'list') {
      assertAllowedOptions(options, ['license-id', 'limit']);
      const limitText = optionalOption(options, 'limit');
      const limit = limitText === undefined ? 50 : Number(limitText);
      printJson(stdout, await service.listAudit(option(options, 'license-id'), limit));
      return 0;
    }
    fail('ADMIN_COMMAND_INVALID');
  } finally {
    await service.close();
  }
}

export async function runAdminCli(
  argv = process.argv.slice(2),
  stdout: OutputStream = process.stdout,
  stderr: OutputStream = process.stderr,
): Promise<number> {
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    stdout.write(helpText);
    return 0;
  }
  try {
    if (['create', 'issue-code', 'renew', 'revoke', 'restore', 'approve-transfer', 'revoke-transfer-approval',
      'approve-disaster-transfer', 'revoke-disaster-transfer-approval', 'approve-time-reset',
      'revoke-time-reset-approval'].includes(argv[1] ?? '') && argv[0] === 'license') {
      return await runMutation(argv, stdout);
    }
    return await runRead(argv, stdout);
  } catch (error) {
    const code = error instanceof AdminOperationError || error instanceof AdminAccessError
      ? error.code
      : 'ADMIN_OPERATION_FAILED';
    stderr.write(`${code}\n`);
    return 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = await runAdminCli();
}
