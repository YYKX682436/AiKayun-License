import { randomBytes, randomUUID } from 'node:crypto';
import canonicalize from 'canonicalize';
import { sql, type Kysely, type Transaction } from 'kysely';
import type { LicenseAdminOperationRow, LicenseRow, Database } from '../db/types.js';
import { databaseNow } from '../services/common.js';
import { addCalendarPeriod, type BillingPlan } from '../entitlements/calendar.js';
import { sha256Base64url } from '../crypto/identity.js';
import { timeResetIntentDigest } from '../intent.js';
import { applyConfirmedRenewalToLockedLicense, lockEntitlementEvent } from '../services/entitlements.js';
import { AdminAccessError, openAdminSession, type AdminActor, type AdminSession } from './policy.js';

type AdminTransaction = Transaction<Database>;
type AdminAction = LicenseAdminOperationRow['action'];
type AdminState = LicenseAdminOperationRow['state'];

export class AdminOperationError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = 'AdminOperationError';
  }
}

export interface AdminOperationResult {
  operationId: string;
  requestDigest: string;
  action: AdminAction;
  licenseId: string;
  state: AdminState;
  outcomeCode: string;
  expectedRevision: string;
  resultRevision: string | null;
  result: Record<string, unknown>;
  replayed: boolean;
  activationCode?: string;
}

interface BaseRequest {
  operationId: string;
  licenseId: string;
  expectedRevision: string;
  reason: string;
  confirmedRequestDigest: string;
}

export interface CreateLicenseRequest {
  operationId: string;
  licenseId: string;
  expectedRevision: '0';
  plan: BillingPlan;
  accountId: string;
  reason: string;
  confirmedRequestDigest: string;
}

export interface IssueActivationCodeRequest extends BaseRequest {
  replaceCodeId?: string;
  expiresInHours?: number;
}

export interface RenewLicenseRequest extends BaseRequest {
  businessReference: string;
}

export interface ApproveTransferRequest extends BaseRequest {
  databaseId: string;
  sourceInstanceId: string;
  sourceIdentityJkt: string;
  targetInstanceId: string;
  targetIdentityJkt: string;
  sourceGeneration: string;
  expectedBindingRevision: string;
}

export type DisasterIncidentType = 'private_key_lost' | 'instance_unavailable' | 'identity_material_lost' | 'other';
export type DisasterBackupCheckResult = 'database_identity_and_history_reviewed' | 'identity_material_missing' | 'unable_to_verify';
export type DisasterOldServerIsolation = 'confirmed_isolated' | 'unknown' | 'not_confirmed';

export interface ApproveDisasterTransferRequest extends BaseRequest {
  accountReference: string;
  sourceActivationId: string;
  databaseId: string;
  sourceInstanceId: string;
  sourceIdentityJkt: string;
  targetInstanceId: string;
  targetInstanceMode: 'preserve' | 'replace';
  targetIdentityJkt: string;
  sourceGeneration: string;
  expectedBindingRevision: string;
  incidentType: DisasterIncidentType;
  recoveryReason: string;
  verificationRecordRef: string;
  backupCheckResult: DisasterBackupCheckResult;
  oldServerIsolation: DisasterOldServerIsolation;
  expiresInHours?: number;
}

export interface RevokeDisasterTransferApprovalRequest extends BaseRequest {
  approvalId: string;
}

export interface ApproveTimeResetRequest extends BaseRequest {
  activationId: string;
  databaseId: string;
  instanceId: string;
  identityJkt: string;
  activationGeneration: string;
  entitlementRevision: string;
  expectedTimeEpoch: string;
  resetOperationId: string;
  intentDigest: string;
  oldWatermarkDigest: string;
  expiresInHours?: number;
}

export interface RevokeTimeResetApprovalRequest extends BaseRequest {
  approvalId: string;
}

export type LicenseStatusView = {
  license: {
    id: string;
    account_id: string;
    plan: BillingPlan;
    billing_anchor_utc: string;
    anchor_day: number;
    confirmed_subscription_end: string;
    status: LicenseRow['status'];
    current_generation: string;
    entitlement_revision: string;
    revision: string;
    created_at: string;
    updated_at: string;
  };
  activations: Array<{
    id: string;
    generation: string;
    instance_id: string;
    database_id: string;
    identity_jkt: string;
    state: 'active' | 'retired';
    activated_at: string;
    retired_at: string | null;
    last_seen_at: string;
    origin_display: string | null;
    time_epoch: string;
  }>;
  activationCodes: Array<{
    id: string;
    created_at: string;
    expires_at: string;
    consumed_at: string | null;
    revoked_at: string | null;
    status: 'issued' | 'expired' | 'consumed' | 'revoked';
  }>;
  disasterTransferApprovals: Array<Record<string, unknown>>;
  timeResetApprovals: Array<Record<string, unknown>>;
};

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const revisionPattern = /^(0|[1-9][0-9]{0,18})$/;
const int64Max = 9_223_372_036_854_775_807n;
const controlledAdminClocks = new WeakMap<AdminSession, () => Promise<Date>>();

function adminNow(session: AdminSession, db: Kysely<Database> | AdminTransaction): Promise<Date> {
  const clock = controlledAdminClocks.get(session);
  return clock ? clock() : databaseNow(db);
}

function ensureUuid(value: string, code: string): void {
  if (!uuidPattern.test(value)) throw new AdminOperationError(code);
}

function ensureRevision(value: string, allowZero = false): void {
  if (!revisionPattern.test(value) || (!allowZero && value === '0') || BigInt(value) > int64Max) {
    throw new AdminOperationError('ADMIN_EXPECTED_REVISION_INVALID');
  }
}

function ensureReason(value: string): string {
  const reason = value.trim();
  if (reason.length < 5 || reason.length > 1000 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(reason)) {
    throw new AdminOperationError('ADMIN_REASON_REQUIRED');
  }
  return reason;
}

function ensureText(value: string, code: string, maxLength: number): string {
  const text = value.trim();
  if (text.length < 1 || text.length > maxLength || /[\u0000-\u001f\u007f]/.test(text)) throw new AdminOperationError(code);
  return text;
}

function isSha256Base64url(value: string): boolean {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.byteLength === 32 && bytes.toString('base64url') === value;
}

function digestRequest(action: AdminAction, request: Record<string, unknown>): string {
  const canonical = canonicalize({ v: 1, action, ...request });
  if (typeof canonical !== 'string') throw new AdminOperationError('ADMIN_REQUEST_INVALID');
  return sha256Base64url(canonical);
}

function actorLabel(actor: AdminActor): string {
  return `os_uid:${actor.osUid};os_user:${actor.osUsername};db_role:${actor.databaseRole}`;
}

function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function mapOperation(row: LicenseAdminOperationRow, replayed: boolean): AdminOperationResult {
  return {
    operationId: row.operation_id,
    requestDigest: row.request_digest,
    action: row.action,
    licenseId: row.license_id,
    state: row.state,
    outcomeCode: row.outcome_code,
    expectedRevision: row.expected_revision.toString(),
    resultRevision: row.result_revision?.toString() ?? null,
    result: asObject(row.result),
    replayed,
  };
}

function assertReplay(row: LicenseAdminOperationRow, input: {
  requestDigest: string;
  action: AdminAction;
  actor: AdminActor;
}): AdminOperationResult {
  if (row.actor_os_uid !== input.actor.osUid || row.actor_database_role !== input.actor.databaseRole) {
    throw new AdminOperationError('ADMIN_OPERATION_ACTOR_MISMATCH');
  }
  if (row.request_digest !== input.requestDigest || row.action !== input.action) {
    throw new AdminOperationError('ADMIN_OPERATION_ID_CONFLICT');
  }
  return mapOperation(row, true);
}

async function lockAdminOperation(trx: AdminTransaction, operationId: string): Promise<void> {
  await sql`SELECT pg_advisory_xact_lock(hashtextextended(${'license-admin-operation:' + operationId}, 0))`.execute(trx);
}

async function lockLicense(trx: AdminTransaction, licenseId: string): Promise<LicenseRow | undefined> {
  return trx.selectFrom('licenses').selectAll().where('id', '=', licenseId).forUpdate().executeTakeFirst();
}

async function lockActivationInstance(trx: AdminTransaction, instanceId: string): Promise<void> {
  await sql`SELECT pg_advisory_xact_lock(hashtextextended(${'activation-instance:' + instanceId}, 0))`.execute(trx);
}

async function hasCurrentNormalTransfer(trx: AdminTransaction, licenseId: string, revision: string, generation: string, now: Date): Promise<boolean> {
  const approval = await sql<{ present: boolean }>`
    SELECT EXISTS (
      SELECT 1 FROM license_transfer_approvals a
      LEFT JOIN license_transfer_revocations r ON r.approval_id = a.approval_id
      WHERE a.license_id = ${licenseId} AND a.expected_revision = ${revision}
        AND a.source_generation = ${generation} AND a.expires_at > ${now} AND r.approval_id IS NULL
    ) AS present
  `.execute(trx);
  if (approval.rows[0]?.present) return true;
  const plan = await trx.selectFrom('license_transfer_plans').select('plan_id')
    .where('license_id', '=', licenseId).where('state', '=', 'prepared').executeTakeFirst();
  return plan !== undefined;
}

async function hasCurrentDisasterTransfer(trx: AdminTransaction, licenseId: string, revision: string, generation: string, now: Date): Promise<boolean> {
  const approval = await sql<{ present: boolean }>`
    SELECT EXISTS (
      SELECT 1 FROM license_disaster_transfer_approvals a
      LEFT JOIN license_disaster_transfer_revocations r ON r.approval_id = a.approval_id
      WHERE a.license_id = ${licenseId} AND a.expected_revision = ${revision}
        AND a.source_generation = ${generation} AND a.expires_at > ${now} AND r.approval_id IS NULL
    ) AS present
  `.execute(trx);
  if (approval.rows[0]?.present) return true;
  const plan = await trx.selectFrom('license_disaster_transfer_plans').select('plan_id')
    .where('license_id', '=', licenseId).where('state', '=', 'prepared').executeTakeFirst();
  return plan !== undefined;
}

async function appendCoreAudit(
  trx: AdminTransaction,
  actor: AdminActor,
  input: { licenseId: string; operationId: string; kind: string; reason: string; details: Record<string, unknown>; now: Date },
): Promise<void> {
  await trx.insertInto('license_audit_events').values({
    id: randomUUID(),
    license_id: input.licenseId,
    operation_id: input.operationId,
    kind: input.kind,
    actor: actorLabel(actor),
    safe_details: { reason: input.reason, ...input.details },
    created_at: input.now,
  }).execute();
}

interface FinalOutcome {
  state: AdminState;
  outcomeCode: string;
  result: Record<string, unknown>;
  resultRevision: string | null;
  now: Date;
  activationCode?: string;
}

async function writeFinalOperation(trx: AdminTransaction, actor: AdminActor, input: {
  operationId: string;
  requestDigest: string;
  action: AdminAction;
  licenseId: string;
  expectedRevision: string;
  reason: string;
}, outcome: FinalOutcome): Promise<void> {
  await trx.insertInto('license_admin_operations').values({
    operation_id: input.operationId,
    request_digest: input.requestDigest,
    action: input.action,
    license_id: input.licenseId,
    expected_revision: input.expectedRevision,
    actor_os_uid: actor.osUid,
    actor_os_username: actor.osUsername,
    actor_database_role: actor.databaseRole,
    reason: input.reason,
    state: outcome.state,
    outcome_code: outcome.outcomeCode,
    result: outcome.result,
    result_revision: outcome.resultRevision,
    created_at: outcome.now,
    finalized_at: outcome.now,
  }).execute();
  await trx.insertInto('license_admin_audit_events').values({
    event_id: randomUUID(),
    operation_id: input.operationId,
    license_id: input.licenseId,
    action: input.action,
    request_digest: input.requestDigest,
    actor_os_uid: actor.osUid,
    actor_os_username: actor.osUsername,
    actor_database_role: actor.databaseRole,
    expected_revision: input.expectedRevision,
    reason: input.reason,
    state: outcome.state,
    outcome_code: outcome.outcomeCode,
    result: outcome.result,
    created_at: outcome.now,
  }).execute();
}

async function executeMutation(
  session: AdminSession,
  input: {
    operationId: string;
    requestDigest: string;
    action: AdminAction;
    licenseId: string;
    expectedRevision: string;
    reason: string;
    confirmedRequestDigest: string;
  },
  perform: (trx: AdminTransaction) => Promise<FinalOutcome>,
): Promise<AdminOperationResult> {
  ensureUuid(input.operationId, 'ADMIN_OPERATION_ID_INVALID');
  ensureUuid(input.licenseId, 'ADMIN_LICENSE_ID_INVALID');
  ensureRevision(input.expectedRevision, input.expectedRevision === '0');
  if (input.confirmedRequestDigest !== input.requestDigest) throw new AdminOperationError('ADMIN_CONFIRMATION_DIGEST_MISMATCH');
  try {
    return await session.db.transaction().execute(async (trx) => {
      await lockAdminOperation(trx, input.operationId);
      const existing = await trx.selectFrom('license_admin_operations').selectAll()
        .where('operation_id', '=', input.operationId).executeTakeFirst();
      if (existing) return assertReplay(existing, { requestDigest: input.requestDigest, action: input.action, actor: session.actor });
      const outcome = await perform(trx);
      await writeFinalOperation(trx, session.actor, input, outcome);
      return {
        operationId: input.operationId,
        requestDigest: input.requestDigest,
        action: input.action,
        licenseId: input.licenseId,
        state: outcome.state,
        outcomeCode: outcome.outcomeCode,
        expectedRevision: input.expectedRevision,
        resultRevision: outcome.resultRevision,
        result: outcome.result,
        replayed: false,
        ...(outcome.activationCode ? { activationCode: outcome.activationCode } : {}),
      };
    });
  } catch (error) {
    if (error instanceof AdminOperationError || error instanceof AdminAccessError) throw error;
    let committed: LicenseAdminOperationRow | undefined;
    try {
      committed = await session.db.selectFrom('license_admin_operations').selectAll()
        .where('operation_id', '=', input.operationId).executeTakeFirst();
    } catch {
      throw new AdminOperationError('ADMIN_COMMIT_OUTCOME_UNKNOWN');
    }
    if (committed) return assertReplay(committed, { requestDigest: input.requestDigest, action: input.action, actor: session.actor });
    throw new AdminOperationError('ADMIN_COMMIT_OUTCOME_UNKNOWN');
  }
}

export function createLicenseRequestDigest(input: Omit<CreateLicenseRequest, 'confirmedRequestDigest'>): string {
  ensureUuid(input.operationId, 'ADMIN_OPERATION_ID_INVALID');
  ensureUuid(input.licenseId, 'ADMIN_LICENSE_ID_INVALID');
  if (input.expectedRevision !== '0') throw new AdminOperationError('ADMIN_EXPECTED_REVISION_INVALID');
  if (input.plan !== 'monthly' && input.plan !== 'yearly') throw new AdminOperationError('ADMIN_PLAN_INVALID');
  const accountId = ensureText(input.accountId, 'ADMIN_ACCOUNT_ID_INVALID', 200);
  const reason = ensureReason(input.reason);
  return digestRequest('license_create', {
    operation_id: input.operationId, license_id: input.licenseId, expected_revision: '0',
    plan: input.plan, account_id: accountId, reason,
  });
}

export function issueActivationCodeRequestDigest(input: Omit<IssueActivationCodeRequest, 'confirmedRequestDigest'>): string {
  ensureUuid(input.operationId, 'ADMIN_OPERATION_ID_INVALID');
  ensureUuid(input.licenseId, 'ADMIN_LICENSE_ID_INVALID');
  ensureRevision(input.expectedRevision);
  const reason = ensureReason(input.reason);
  const expiresInHours = input.expiresInHours ?? 24;
  if (!Number.isInteger(expiresInHours) || expiresInHours < 1 || expiresInHours > 72) throw new AdminOperationError('ADMIN_CODE_EXPIRY_INVALID');
  if (input.replaceCodeId) ensureUuid(input.replaceCodeId, 'ADMIN_ACTIVATION_CODE_ID_INVALID');
  return digestRequest('activation_code_issue', {
    operation_id: input.operationId,
    license_id: input.licenseId,
    expected_revision: input.expectedRevision,
    reason,
    expires_in_hours: expiresInHours,
    ...(input.replaceCodeId ? { replace_code_id: input.replaceCodeId } : {}),
  });
}

export function renewLicenseRequestDigest(input: Omit<RenewLicenseRequest, 'confirmedRequestDigest'>): string {
  ensureUuid(input.operationId, 'ADMIN_OPERATION_ID_INVALID');
  ensureUuid(input.licenseId, 'ADMIN_LICENSE_ID_INVALID');
  ensureRevision(input.expectedRevision);
  const reason = ensureReason(input.reason);
  const businessReference = ensureText(input.businessReference, 'ADMIN_BUSINESS_REFERENCE_REQUIRED', 200);
  return digestRequest('license_renew', {
    operation_id: input.operationId,
    license_id: input.licenseId,
    expected_revision: input.expectedRevision,
    business_reference: businessReference,
    reason,
  });
}

export function changeLicenseStatusRequestDigest(input: Omit<BaseRequest, 'confirmedRequestDigest'>, action: 'license_revoke' | 'license_restore'): string {
  ensureUuid(input.operationId, 'ADMIN_OPERATION_ID_INVALID');
  ensureUuid(input.licenseId, 'ADMIN_LICENSE_ID_INVALID');
  ensureRevision(input.expectedRevision);
  const reason = ensureReason(input.reason);
  return digestRequest(action, {
    operation_id: input.operationId,
    license_id: input.licenseId,
    expected_revision: input.expectedRevision,
    reason,
  });
}

export function approveTransferRequestDigest(input: Omit<ApproveTransferRequest, 'confirmedRequestDigest'>): string {
  ensureUuid(input.operationId, 'ADMIN_OPERATION_ID_INVALID');
  ensureUuid(input.licenseId, 'ADMIN_LICENSE_ID_INVALID');
  ensureUuid(input.databaseId, 'ADMIN_DATABASE_ID_INVALID');
  ensureUuid(input.sourceInstanceId, 'ADMIN_INSTANCE_ID_INVALID');
  ensureUuid(input.targetInstanceId, 'ADMIN_INSTANCE_ID_INVALID');
  ensureRevision(input.expectedRevision);
  ensureRevision(input.sourceGeneration);
  ensureRevision(input.expectedBindingRevision, true);
  const reason = ensureReason(input.reason);
  if (input.sourceInstanceId !== input.targetInstanceId) throw new AdminOperationError('ADMIN_TRANSFER_INSTANCE_MISMATCH');
  if (!/^[A-Za-z0-9_-]{43}$/.test(input.sourceIdentityJkt) || !/^[A-Za-z0-9_-]{43}$/.test(input.targetIdentityJkt) ||
    input.sourceIdentityJkt === input.targetIdentityJkt) throw new AdminOperationError('ADMIN_TRANSFER_IDENTITY_INVALID');
  return digestRequest('transfer_approve', {
    operation_id: input.operationId,
    license_id: input.licenseId,
    expected_revision: input.expectedRevision,
    database_id: input.databaseId,
    source_instance_id: input.sourceInstanceId,
    source_identity_jkt: input.sourceIdentityJkt,
    target_instance_id: input.targetInstanceId,
    target_identity_jkt: input.targetIdentityJkt,
    source_generation: input.sourceGeneration,
    expected_binding_revision: input.expectedBindingRevision,
    reason,
  });
}

export function revokeTransferApprovalRequestDigest(input: Omit<RevokeTransferApprovalRequest, 'confirmedRequestDigest'>): string {
  ensureUuid(input.operationId, 'ADMIN_OPERATION_ID_INVALID');
  ensureUuid(input.licenseId, 'ADMIN_LICENSE_ID_INVALID');
  ensureUuid(input.approvalId, 'ADMIN_TRANSFER_APPROVAL_ID_INVALID');
  ensureRevision(input.expectedRevision);
  const reason = ensureReason(input.reason);
  return digestRequest('transfer_revoke', {
    operation_id: input.operationId, license_id: input.licenseId,
    expected_revision: input.expectedRevision, approval_id: input.approvalId, reason,
  });
}

export function approveDisasterTransferRequestDigest(input: Omit<ApproveDisasterTransferRequest, 'confirmedRequestDigest'>): string {
  ensureUuid(input.operationId, 'ADMIN_OPERATION_ID_INVALID');
  ensureUuid(input.licenseId, 'ADMIN_LICENSE_ID_INVALID');
  ensureUuid(input.sourceActivationId, 'ADMIN_DISASTER_SOURCE_ACTIVATION_INVALID');
  ensureUuid(input.databaseId, 'ADMIN_DATABASE_ID_INVALID');
  ensureUuid(input.sourceInstanceId, 'ADMIN_INSTANCE_ID_INVALID');
  ensureUuid(input.targetInstanceId, 'ADMIN_INSTANCE_ID_INVALID');
  ensureRevision(input.expectedRevision);
  ensureRevision(input.sourceGeneration);
  ensureRevision(input.expectedBindingRevision, true);
  const accountReference = ensureText(input.accountReference, 'ADMIN_ACCOUNT_REFERENCE_INVALID', 200);
  const reason = ensureReason(input.reason);
  const recoveryReason = ensureReason(input.recoveryReason);
  const verificationRecordRef = ensureText(input.verificationRecordRef, 'ADMIN_VERIFICATION_REFERENCE_INVALID', 300);
  if (!/^(case|ticket|audit):[A-Za-z0-9][A-Za-z0-9._/-]{0,260}$/i.test(verificationRecordRef)) {
    throw new AdminOperationError('ADMIN_VERIFICATION_REFERENCE_INVALID');
  }
  if (!['preserve', 'replace'].includes(input.targetInstanceMode) ||
    (input.targetInstanceMode === 'preserve' && input.sourceInstanceId !== input.targetInstanceId) ||
    (input.targetInstanceMode === 'replace' && input.sourceInstanceId === input.targetInstanceId)) {
    throw new AdminOperationError('ADMIN_DISASTER_INSTANCE_MODE_INVALID');
  }
  if (!['private_key_lost', 'instance_unavailable', 'identity_material_lost', 'other'].includes(input.incidentType) ||
    !['database_identity_and_history_reviewed', 'identity_material_missing', 'unable_to_verify'].includes(input.backupCheckResult) ||
    !['confirmed_isolated', 'unknown', 'not_confirmed'].includes(input.oldServerIsolation)) {
    throw new AdminOperationError('ADMIN_DISASTER_DECLARATION_INVALID');
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(input.sourceIdentityJkt) || !/^[A-Za-z0-9_-]{43}$/.test(input.targetIdentityJkt) ||
    input.sourceIdentityJkt === input.targetIdentityJkt) throw new AdminOperationError('ADMIN_DISASTER_IDENTITY_INVALID');
  const expiresInHours = input.expiresInHours ?? 24;
  if (!Number.isInteger(expiresInHours) || expiresInHours < 1 || expiresInHours > 72) {
    throw new AdminOperationError('ADMIN_DISASTER_APPROVAL_EXPIRY_INVALID');
  }
  return digestRequest('disaster_transfer_approve', {
    operation_id: input.operationId,
    license_id: input.licenseId,
    expected_revision: input.expectedRevision,
    account_reference: accountReference,
    source_activation_id: input.sourceActivationId,
    database_id: input.databaseId,
    source_instance_id: input.sourceInstanceId,
    source_identity_jkt: input.sourceIdentityJkt,
    target_instance_id: input.targetInstanceId,
    target_instance_mode: input.targetInstanceMode,
    target_identity_jkt: input.targetIdentityJkt,
    source_generation: input.sourceGeneration,
    expected_binding_revision: input.expectedBindingRevision,
    incident_type: input.incidentType,
    recovery_reason: recoveryReason,
    verification_record_ref: verificationRecordRef,
    backup_check_result: input.backupCheckResult,
    old_server_isolation: input.oldServerIsolation,
    expires_in_hours: expiresInHours,
    reason,
  });
}

export function revokeDisasterTransferApprovalRequestDigest(input: Omit<RevokeDisasterTransferApprovalRequest, 'confirmedRequestDigest'>): string {
  ensureUuid(input.operationId, 'ADMIN_OPERATION_ID_INVALID');
  ensureUuid(input.licenseId, 'ADMIN_LICENSE_ID_INVALID');
  ensureUuid(input.approvalId, 'ADMIN_DISASTER_APPROVAL_ID_INVALID');
  ensureRevision(input.expectedRevision);
  const reason = ensureReason(input.reason);
  return digestRequest('disaster_transfer_revoke', {
    operation_id: input.operationId, license_id: input.licenseId,
    expected_revision: input.expectedRevision, approval_id: input.approvalId, reason,
  });
}

export function approveTimeResetRequestDigest(input: Omit<ApproveTimeResetRequest, 'confirmedRequestDigest'>): string {
  ensureUuid(input.operationId, 'ADMIN_OPERATION_ID_INVALID');
  ensureUuid(input.licenseId, 'ADMIN_LICENSE_ID_INVALID');
  ensureUuid(input.activationId, 'ADMIN_TIME_RESET_ACTIVATION_INVALID');
  ensureUuid(input.databaseId, 'ADMIN_DATABASE_ID_INVALID');
  ensureUuid(input.instanceId, 'ADMIN_INSTANCE_ID_INVALID');
  ensureUuid(input.resetOperationId, 'ADMIN_TIME_RESET_OPERATION_ID_INVALID');
  if (input.operationId === input.resetOperationId) throw new AdminOperationError('ADMIN_TIME_RESET_OPERATION_ID_INVALID');
  ensureRevision(input.expectedRevision);
  ensureRevision(input.activationGeneration);
  ensureRevision(input.entitlementRevision);
  ensureRevision(input.expectedTimeEpoch, true);
  if (!isSha256Base64url(input.identityJkt) || !isSha256Base64url(input.intentDigest) ||
    !isSha256Base64url(input.oldWatermarkDigest)) throw new AdminOperationError('ADMIN_TIME_RESET_BINDING_INVALID');
  const expiresInHours = input.expiresInHours ?? 24;
  if (!Number.isInteger(expiresInHours) || expiresInHours < 1 || expiresInHours > 72) {
    throw new AdminOperationError('ADMIN_TIME_RESET_APPROVAL_EXPIRY_INVALID');
  }
  const expectedIntent = timeResetIntentDigest({
    operationId: input.resetOperationId,
    approvalId: input.operationId,
    licenseId: input.licenseId,
    databaseId: input.databaseId,
    instanceId: input.instanceId,
    identityJkt: input.identityJkt,
    activationId: input.activationId,
    activationGeneration: input.activationGeneration,
    expectedRevision: input.expectedRevision,
    entitlementRevision: input.entitlementRevision,
    expectedTimeEpoch: input.expectedTimeEpoch,
    oldWatermarkDigest: input.oldWatermarkDigest,
  });
  if (expectedIntent !== input.intentDigest) throw new AdminOperationError('ADMIN_TIME_RESET_INTENT_MISMATCH');
  return digestRequest('time_reset_approve', {
    operation_id: input.operationId,
    license_id: input.licenseId,
    expected_revision: input.expectedRevision,
    activation_id: input.activationId,
    database_id: input.databaseId,
    instance_id: input.instanceId,
    identity_jkt: input.identityJkt,
    activation_generation: input.activationGeneration,
    entitlement_revision: input.entitlementRevision,
    expected_time_epoch: input.expectedTimeEpoch,
    new_time_epoch: (BigInt(input.expectedTimeEpoch) + 1n).toString(),
    reset_operation_id: input.resetOperationId,
    intent_digest: input.intentDigest,
    old_watermark_digest: input.oldWatermarkDigest,
    expires_in_hours: expiresInHours,
    reason: ensureReason(input.reason),
  });
}

export function revokeTimeResetApprovalRequestDigest(input: Omit<RevokeTimeResetApprovalRequest, 'confirmedRequestDigest'>): string {
  ensureUuid(input.operationId, 'ADMIN_OPERATION_ID_INVALID');
  ensureUuid(input.licenseId, 'ADMIN_LICENSE_ID_INVALID');
  ensureUuid(input.approvalId, 'ADMIN_TIME_RESET_APPROVAL_ID_INVALID');
  if (input.operationId === input.approvalId) throw new AdminOperationError('ADMIN_OPERATION_ID_INVALID');
  ensureRevision(input.expectedRevision);
  return digestRequest('time_reset_revoke', {
    operation_id: input.operationId,
    license_id: input.licenseId,
    expected_revision: input.expectedRevision,
    approval_id: input.approvalId,
    reason: ensureReason(input.reason),
  });
}

async function revokeTransferApproval(session: AdminSession, input: RevokeTransferApprovalRequest): Promise<AdminOperationResult> {
  const reason = ensureReason(input.reason);
  const requestDigest = revokeTransferApprovalRequestDigest({ ...input, reason });
  return executeMutation(session, {
    operationId: input.operationId, requestDigest, action: 'transfer_revoke', licenseId: input.licenseId,
    expectedRevision: input.expectedRevision, reason, confirmedRequestDigest: input.confirmedRequestDigest,
  }, async (trx) => {
    const license = await lockLicense(trx, input.licenseId);
    const now = await databaseNow(trx);
    if (!license) return { state: 'rejected', outcomeCode: 'LICENSE_NOT_FOUND', resultRevision: null, now, result: { license_id: input.licenseId } };
    const revision = license.revision.toString();
    if (revision !== input.expectedRevision) return { state: 'rejected', outcomeCode: 'EXPECTED_REVISION_MISMATCH', resultRevision: revision, now, result: { expected_revision: input.expectedRevision, observed_revision: revision } };
    const approval = await trx.selectFrom('license_transfer_approvals').selectAll().where('approval_id', '=', input.approvalId).forUpdate().executeTakeFirst();
    const adminApproval = await trx.selectFrom('license_admin_operations').selectAll().where('operation_id', '=', input.approvalId).executeTakeFirst();
    if (!approval || !adminApproval || approval.license_id !== input.licenseId || adminApproval.action !== 'transfer_approve' || adminApproval.state !== 'succeeded') {
      return { state: 'rejected', outcomeCode: 'TRANSFER_APPROVAL_NOT_FOUND', resultRevision: revision, now, result: { approval_id: input.approvalId } };
    }
    const existing = await trx.selectFrom('license_transfer_revocations').selectAll().where('approval_id', '=', input.approvalId).executeTakeFirst();
    if (existing) return { state: 'rejected', outcomeCode: 'TRANSFER_APPROVAL_ALREADY_REVOKED', resultRevision: revision, now, result: { approval_id: input.approvalId, revocation_operation_id: existing.revocation_operation_id } };
    const committed = await trx.selectFrom('license_transfer_plans').select('plan_id').where('approval_id', '=', input.approvalId).where('state', '=', 'committed').executeTakeFirst();
    if (committed) return { state: 'rejected', outcomeCode: 'TRANSFER_ALREADY_COMMITTED', resultRevision: revision, now, result: { approval_id: input.approvalId, plan_id: committed.plan_id } };
    const preparedPlan = await trx.selectFrom('license_transfer_plans').selectAll().where('approval_id', '=', input.approvalId)
      .where('state', '=', 'prepared').forUpdate().executeTakeFirst();
    if (preparedPlan) {
      await trx.updateTable('license_transfer_plans').set({ state: 'invalidated' }).where('plan_id', '=', preparedPlan.plan_id).where('state', '=', 'prepared').execute();
      await trx.insertInto('license_transfer_events').values({
        event_id: randomUUID(), license_id: input.licenseId, approval_id: input.approvalId,
        prepare_operation_id: preparedPlan.prepare_operation_id, commit_operation_id: null, plan_id: preparedPlan.plan_id,
        kind: 'invalidated', actor: actorLabel(session.actor), safe_details: { reason: 'approval_revoked' }, created_at: now,
      }).execute();
    }
    await trx.insertInto('license_transfer_revocations').values({
      revocation_operation_id: input.operationId, approval_id: input.approvalId, license_id: input.licenseId,
      request_digest: requestDigest, expected_revision: input.expectedRevision,
      actor_os_uid: session.actor.osUid, actor_os_username: session.actor.osUsername,
      actor_database_role: session.actor.databaseRole, reason, revoked_at: now,
    }).execute();
    await appendCoreAudit(trx, session.actor, { licenseId: input.licenseId, operationId: input.operationId,
      kind: 'admin_transfer_approval_revoked', reason, details: { approval_id: input.approvalId }, now });
    await trx.insertInto('license_transfer_events').values({
      event_id: randomUUID(), license_id: input.licenseId, approval_id: input.approvalId,
      prepare_operation_id: null, commit_operation_id: null, plan_id: null, kind: 'approval_revoked',
      actor: actorLabel(session.actor), safe_details: { revocation_operation_id: input.operationId, reason }, created_at: now,
    }).execute();
    return { state: 'succeeded', outcomeCode: 'TRANSFER_APPROVAL_REVOKED', resultRevision: revision, now,
      result: { approval_id: input.approvalId, license_id: input.licenseId, revoked_at: now.toISOString() } };
  });
}

async function approveTransfer(session: AdminSession, input: ApproveTransferRequest): Promise<AdminOperationResult> {
  const reason = ensureReason(input.reason);
  const requestDigest = approveTransferRequestDigest({ ...input, reason });
  return executeMutation(session, {
    operationId: input.operationId,
    requestDigest,
    action: 'transfer_approve',
    licenseId: input.licenseId,
    expectedRevision: input.expectedRevision,
    reason,
    confirmedRequestDigest: input.confirmedRequestDigest,
  }, async (trx) => {
    const license = await lockLicense(trx, input.licenseId);
    const now = await adminNow(session, trx);
    if (!license) return {
      state: 'rejected', outcomeCode: 'LICENSE_NOT_FOUND', resultRevision: null, now,
      result: { license_id: input.licenseId },
    };
    const revision = license.revision.toString();
    if (revision !== input.expectedRevision) return {
      state: 'rejected', outcomeCode: 'EXPECTED_REVISION_MISMATCH', resultRevision: revision, now,
      result: { license_id: license.id, expected_revision: input.expectedRevision, observed_revision: revision },
    };
    if (license.status !== 'active') return {
      state: 'rejected', outcomeCode: 'LICENSE_REVOKED', resultRevision: revision, now,
      result: { license_id: license.id, status: license.status, revision },
    };
    if (license.confirmed_subscription_end.getTime() <= now.getTime()) return {
      state: 'rejected', outcomeCode: 'SUBSCRIPTION_EXPIRED', resultRevision: revision, now,
      result: { license_id: license.id, subscription_end: license.confirmed_subscription_end.toISOString(), revision },
    };
    if (license.current_generation.toString() !== input.sourceGeneration) return {
      state: 'rejected', outcomeCode: 'TRANSFER_SOURCE_GENERATION_MISMATCH', resultRevision: revision, now,
      result: { license_id: license.id, expected_generation: input.sourceGeneration, current_generation: license.current_generation.toString() },
    };
    const source = await trx.selectFrom('license_activations').selectAll()
      .where('license_id', '=', input.licenseId).where('state', '=', 'active').forUpdate().executeTakeFirst();
    if (!source || source.database_id !== input.databaseId || source.instance_id !== input.sourceInstanceId ||
      source.identity_jkt !== input.sourceIdentityJkt || source.generation.toString() !== input.sourceGeneration) return {
      state: 'rejected', outcomeCode: 'TRANSFER_SOURCE_BINDING_MISMATCH', resultRevision: revision, now,
      result: { license_id: input.licenseId, active_generation: source?.generation.toString() ?? null },
    };
    const targetWasUsed = await trx.selectFrom('license_activations').select('id')
      .where('license_id', '=', input.licenseId).where('identity_jkt', '=', input.targetIdentityJkt).executeTakeFirst();
    if (targetWasUsed) return {
      state: 'rejected', outcomeCode: 'TRANSFER_TARGET_IDENTITY_WAS_USED', resultRevision: revision, now,
      result: { license_id: input.licenseId, target_identity_jkt: input.targetIdentityJkt },
    };
    const pendingApprovals = await trx.selectFrom('license_transfer_approvals').select('approval_id')
      .where('license_id', '=', input.licenseId).where('expires_at', '>', now)
      .where('expected_revision', '=', revision).where('source_generation', '=', license.current_generation.toString()).execute();
    const validApprovals = await Promise.all(pendingApprovals.map(async ({ approval_id }) =>
      (await trx.selectFrom('license_transfer_revocations').select('approval_id').where('approval_id', '=', approval_id).executeTakeFirst()) ? null : approval_id));
    if (validApprovals.filter(Boolean).length > 0) return {
      state: 'rejected', outcomeCode: 'TRANSFER_APPROVAL_ALREADY_VALID', resultRevision: revision, now,
      result: { license_id: input.licenseId, valid_approval_count: validApprovals.filter(Boolean).length },
    };
    if (await hasCurrentDisasterTransfer(trx, input.licenseId, revision, license.current_generation.toString(), now)) return {
      state: 'rejected', outcomeCode: 'DISASTER_TRANSFER_REQUIRES_EXPLICIT_REVOCATION', resultRevision: revision, now,
      result: { license_id: input.licenseId },
    };
    const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    await trx.insertInto('license_transfer_approvals').values({
      approval_id: input.operationId,
      request_digest: requestDigest,
      license_id: input.licenseId,
      database_id: input.databaseId,
      source_instance_id: input.sourceInstanceId,
      source_identity_jkt: input.sourceIdentityJkt,
      target_instance_id: input.targetInstanceId,
      target_identity_jkt: input.targetIdentityJkt,
      source_generation: input.sourceGeneration,
      expected_binding_revision: input.expectedBindingRevision,
      expected_revision: input.expectedRevision,
      actor_os_uid: session.actor.osUid,
      actor_os_username: session.actor.osUsername,
      actor_database_role: session.actor.databaseRole,
      reason,
      approved_at: now,
      expires_at: expiresAt,
    }).execute();
    const result = {
      approval_id: input.operationId,
      license_id: input.licenseId,
      database_id: input.databaseId,
      source_instance_id: input.sourceInstanceId,
      source_identity_jkt: input.sourceIdentityJkt,
      target_instance_id: input.targetInstanceId,
      target_identity_jkt: input.targetIdentityJkt,
      source_generation: input.sourceGeneration,
      expected_binding_revision: input.expectedBindingRevision,
      expected_revision: revision,
      approved_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    };
    await appendCoreAudit(trx, session.actor, {
      licenseId: input.licenseId,
      operationId: input.operationId,
      kind: 'admin_transfer_approved',
      reason,
      details: result,
      now,
    });
    await trx.insertInto('license_transfer_events').values({
      event_id: randomUUID(), license_id: input.licenseId, approval_id: input.operationId,
      prepare_operation_id: null, commit_operation_id: null, plan_id: null, kind: 'approved',
      actor: actorLabel(session.actor), safe_details: result, created_at: now,
    }).execute();
    return { state: 'succeeded', outcomeCode: 'TRANSFER_APPROVED', result, resultRevision: revision, now };
  });
}

export interface RevokeTransferApprovalRequest extends BaseRequest {
  approvalId: string;
}

async function approveDisasterTransfer(session: AdminSession, input: ApproveDisasterTransferRequest): Promise<AdminOperationResult> {
  const reason = ensureReason(input.reason);
  const normalized = {
    ...input,
    reason,
    recoveryReason: ensureReason(input.recoveryReason),
    accountReference: ensureText(input.accountReference, 'ADMIN_ACCOUNT_REFERENCE_INVALID', 200),
    verificationRecordRef: ensureText(input.verificationRecordRef, 'ADMIN_VERIFICATION_REFERENCE_INVALID', 300),
    expiresInHours: input.expiresInHours ?? 24,
  };
  const requestDigest = approveDisasterTransferRequestDigest(normalized);
  return executeMutation(session, {
    operationId: input.operationId, requestDigest, action: 'disaster_transfer_approve', licenseId: input.licenseId,
    expectedRevision: input.expectedRevision, reason, confirmedRequestDigest: input.confirmedRequestDigest,
  }, async (trx) => {
    const license = await lockLicense(trx, input.licenseId);
    const now = await adminNow(session, trx);
    if (!license) return { state: 'rejected', outcomeCode: 'LICENSE_NOT_FOUND', resultRevision: null, now, result: { license_id: input.licenseId } };
    const revision = license.revision.toString();
    if (revision !== input.expectedRevision) return { state: 'rejected', outcomeCode: 'EXPECTED_REVISION_MISMATCH', resultRevision: revision, now,
      result: { expected_revision: input.expectedRevision, observed_revision: revision } };
    if (license.account_id !== normalized.accountReference) return { state: 'rejected', outcomeCode: 'DISASTER_ACCOUNT_REFERENCE_MISMATCH',
      resultRevision: revision, now, result: { license_id: license.id } };
    if (normalized.backupCheckResult === 'unable_to_verify') return { state: 'rejected', outcomeCode: 'DISASTER_BACKUP_NOT_VERIFIED',
      resultRevision: revision, now, result: { license_id: license.id } };
    const source = await trx.selectFrom('license_activations').selectAll()
      .where('license_id', '=', license.id).where('state', '=', 'active').forUpdate().executeTakeFirst();
    if (!source || source.id !== input.sourceActivationId || source.database_id !== input.databaseId ||
      source.instance_id !== input.sourceInstanceId || source.identity_jkt !== input.sourceIdentityJkt ||
      source.generation.toString() !== input.sourceGeneration || license.current_generation.toString() !== input.sourceGeneration) {
      return { state: 'rejected', outcomeCode: 'DISASTER_SOURCE_BINDING_MISMATCH', resultRevision: revision, now,
        result: { license_id: license.id, active_activation_id: source?.id ?? null, current_generation: license.current_generation.toString() } };
    }
    if (await hasCurrentNormalTransfer(trx, license.id, revision, license.current_generation.toString(), now)) return {
      state: 'rejected', outcomeCode: 'NORMAL_TRANSFER_REQUIRES_EXPLICIT_REVOCATION', resultRevision: revision, now,
      result: { license_id: license.id },
    };
    if (await hasCurrentDisasterTransfer(trx, license.id, revision, license.current_generation.toString(), now)) return {
      state: 'rejected', outcomeCode: 'DISASTER_TRANSFER_APPROVAL_ALREADY_ACTIVE', resultRevision: revision, now,
      result: { license_id: license.id },
    };
    const targetWasUsed = await trx.selectFrom('license_activations').select('id')
      .where('license_id', '=', license.id).where('identity_jkt', '=', input.targetIdentityJkt).executeTakeFirst();
    if (targetWasUsed) return { state: 'rejected', outcomeCode: 'DISASTER_TARGET_IDENTITY_WAS_USED', resultRevision: revision, now,
      result: { license_id: license.id, target_identity_jkt: input.targetIdentityJkt } };
    if (input.targetInstanceMode === 'replace') {
      await lockActivationInstance(trx, input.targetInstanceId);
      const collision = await trx.selectFrom('license_activations').select(['license_id', 'id'])
        .where('instance_id', '=', input.targetInstanceId).where('state', '=', 'active').executeTakeFirst();
      if (collision) return { state: 'rejected', outcomeCode: 'DISASTER_TARGET_INSTANCE_ALREADY_ACTIVE', resultRevision: revision, now,
        result: { target_instance_id: input.targetInstanceId, active_license_id: collision.license_id } };
    }

    const expiresAt = new Date(now.getTime() + normalized.expiresInHours! * 60 * 60 * 1000);
    const snapshot = {
      request_id: input.operationId, approval_id: input.operationId, license_id: license.id, account_reference: license.account_id,
      source_activation_id: source.id, database_id: source.database_id, source_instance_id: source.instance_id,
      source_identity_jkt: source.identity_jkt, target_instance_id: input.targetInstanceId,
      target_instance_mode: input.targetInstanceMode, target_identity_jkt: input.targetIdentityJkt,
      source_generation: source.generation.toString(), expected_binding_revision: input.expectedBindingRevision,
      expected_revision: revision, entitlement_revision: license.entitlement_revision.toString(),
      incident_type: input.incidentType, recovery_reason: normalized.recoveryReason,
      verification_record_ref: normalized.verificationRecordRef, backup_check_result: input.backupCheckResult,
      old_server_isolation: input.oldServerIsolation, approved_at: now.toISOString(), expires_at: expiresAt.toISOString(),
    };
    const common = {
      request_id: input.operationId, request_digest: requestDigest, license_id: license.id, account_reference: license.account_id,
      source_activation_id: source.id, database_id: source.database_id, source_instance_id: source.instance_id,
      source_identity_jkt: source.identity_jkt, target_instance_id: input.targetInstanceId,
      target_instance_mode: input.targetInstanceMode, target_identity_jkt: input.targetIdentityJkt,
      source_generation: source.generation.toString(), expected_binding_revision: input.expectedBindingRevision,
      expected_revision: revision, entitlement_revision: license.entitlement_revision.toString(),
    };
    await trx.insertInto('license_disaster_recovery_requests').values({
      ...common, incident_type: input.incidentType, recovery_reason: normalized.recoveryReason,
      verification_record_ref: normalized.verificationRecordRef, backup_check_result: input.backupCheckResult,
      old_server_isolation: input.oldServerIsolation, actor_os_uid: session.actor.osUid,
      actor_os_username: session.actor.osUsername, actor_database_role: session.actor.databaseRole, created_at: now,
    }).execute();
    await trx.insertInto('license_disaster_transfer_approvals').values({
      approval_id: input.operationId, request_id: input.operationId, request_digest: requestDigest,
      license_id: license.id, account_reference: license.account_id, source_activation_id: source.id,
      database_id: source.database_id, source_instance_id: source.instance_id, source_identity_jkt: source.identity_jkt,
      target_instance_id: input.targetInstanceId, target_instance_mode: input.targetInstanceMode,
      target_identity_jkt: input.targetIdentityJkt, source_generation: source.generation.toString(),
      expected_binding_revision: input.expectedBindingRevision, expected_revision: revision,
      entitlement_revision: license.entitlement_revision.toString(), actor_os_uid: session.actor.osUid,
      actor_os_username: session.actor.osUsername, actor_database_role: session.actor.databaseRole,
      recovery_reason: normalized.recoveryReason, approved_at: now, expires_at: expiresAt,
    }).execute();
    await appendCoreAudit(trx, session.actor, { licenseId: license.id, operationId: input.operationId,
      kind: 'admin_disaster_transfer_approved', reason, details: { ...snapshot, request_digest: requestDigest }, now });
    await trx.insertInto('license_disaster_transfer_events').values({
      event_id: randomUUID(), license_id: license.id, request_id: input.operationId, approval_id: input.operationId,
      prepare_operation_id: null, commit_operation_id: null, plan_id: null, kind: 'requested',
      actor: actorLabel(session.actor), safe_details: { request_digest: requestDigest, verification_record_ref: normalized.verificationRecordRef }, created_at: now,
    }).execute();
    await trx.insertInto('license_disaster_transfer_events').values({
      event_id: randomUUID(), license_id: license.id, request_id: input.operationId, approval_id: input.operationId,
      prepare_operation_id: null, commit_operation_id: null, plan_id: null, kind: 'approved',
      actor: actorLabel(session.actor), safe_details: snapshot, created_at: now,
    }).execute();
    return { state: 'succeeded', outcomeCode: 'DISASTER_TRANSFER_APPROVED', result: snapshot, resultRevision: revision, now };
  });
}

async function revokeDisasterTransferApproval(session: AdminSession, input: RevokeDisasterTransferApprovalRequest): Promise<AdminOperationResult> {
  const reason = ensureReason(input.reason);
  const requestDigest = revokeDisasterTransferApprovalRequestDigest({ ...input, reason });
  return executeMutation(session, {
    operationId: input.operationId, requestDigest, action: 'disaster_transfer_revoke', licenseId: input.licenseId,
    expectedRevision: input.expectedRevision, reason, confirmedRequestDigest: input.confirmedRequestDigest,
  }, async (trx) => {
    const license = await lockLicense(trx, input.licenseId);
    const now = await databaseNow(trx);
    if (!license) return { state: 'rejected', outcomeCode: 'LICENSE_NOT_FOUND', resultRevision: null, now, result: { license_id: input.licenseId } };
    const revision = license.revision.toString();
    if (revision !== input.expectedRevision) return { state: 'rejected', outcomeCode: 'EXPECTED_REVISION_MISMATCH', resultRevision: revision, now,
      result: { expected_revision: input.expectedRevision, observed_revision: revision } };
    const approval = await trx.selectFrom('license_disaster_transfer_approvals').selectAll()
      .where('approval_id', '=', input.approvalId).forUpdate().executeTakeFirst();
    const adminApproval = await trx.selectFrom('license_admin_operations').selectAll()
      .where('operation_id', '=', input.approvalId).executeTakeFirst();
    if (!approval || !adminApproval || approval.license_id !== input.licenseId ||
      adminApproval.action !== 'disaster_transfer_approve' || adminApproval.state !== 'succeeded' ||
      adminApproval.request_digest !== approval.request_digest) return { state: 'rejected', outcomeCode: 'DISASTER_APPROVAL_NOT_FOUND',
      resultRevision: revision, now, result: { approval_id: input.approvalId } };
    const existing = await trx.selectFrom('license_disaster_transfer_revocations').selectAll()
      .where('approval_id', '=', input.approvalId).executeTakeFirst();
    if (existing) return { state: 'rejected', outcomeCode: 'DISASTER_APPROVAL_ALREADY_REVOKED', resultRevision: revision, now,
      result: { approval_id: input.approvalId, revocation_operation_id: existing.revocation_operation_id } };
    const committed = await trx.selectFrom('license_disaster_transfer_plans').select('plan_id')
      .where('approval_id', '=', input.approvalId).where('state', '=', 'committed').executeTakeFirst();
    if (committed) return { state: 'rejected', outcomeCode: 'DISASTER_TRANSFER_ALREADY_COMMITTED', resultRevision: revision, now,
      result: { approval_id: input.approvalId, plan_id: committed.plan_id } };
    const prepared = await trx.selectFrom('license_disaster_transfer_plans').selectAll()
      .where('approval_id', '=', input.approvalId).where('state', '=', 'prepared').forUpdate().executeTakeFirst();
    if (prepared) {
      await trx.updateTable('license_disaster_transfer_plans').set({ state: 'invalidated' })
        .where('plan_id', '=', prepared.plan_id).where('state', '=', 'prepared').execute();
      await trx.insertInto('license_disaster_transfer_events').values({
        event_id: randomUUID(), license_id: input.licenseId, request_id: approval.request_id, approval_id: input.approvalId,
        prepare_operation_id: prepared.prepare_operation_id, commit_operation_id: null, plan_id: prepared.plan_id,
        kind: 'invalidated', actor: actorLabel(session.actor), safe_details: { reason: 'approval_revoked' }, created_at: now,
      }).execute();
    }
    await trx.insertInto('license_disaster_transfer_revocations').values({
      revocation_operation_id: input.operationId, approval_id: input.approvalId, license_id: input.licenseId,
      request_digest: requestDigest, expected_revision: revision,
      actor_os_uid: session.actor.osUid, actor_os_username: session.actor.osUsername,
      actor_database_role: session.actor.databaseRole, reason, revoked_at: now,
    }).execute();
    const result = { approval_id: input.approvalId, request_id: approval.request_id, license_id: input.licenseId,
      revoked_at: now.toISOString(), invalidated_plan_id: prepared?.plan_id ?? null };
    await appendCoreAudit(trx, session.actor, { licenseId: input.licenseId, operationId: input.operationId,
      kind: 'admin_disaster_transfer_approval_revoked', reason, details: result, now });
    await trx.insertInto('license_disaster_transfer_events').values({
      event_id: randomUUID(), license_id: input.licenseId, request_id: approval.request_id, approval_id: input.approvalId,
      prepare_operation_id: null, commit_operation_id: null, plan_id: null, kind: 'approval_revoked',
      actor: actorLabel(session.actor), safe_details: { revocation_operation_id: input.operationId, reason }, created_at: now,
    }).execute();
    return { state: 'succeeded', outcomeCode: 'DISASTER_TRANSFER_APPROVAL_REVOKED', resultRevision: revision, now, result };
  });
}

async function approveTimeReset(session: AdminSession, input: ApproveTimeResetRequest): Promise<AdminOperationResult> {
  const reason = ensureReason(input.reason);
  const normalized = { ...input, reason, expiresInHours: input.expiresInHours ?? 24 };
  const requestDigest = approveTimeResetRequestDigest(normalized);
  return executeMutation(session, {
    operationId: input.operationId, requestDigest, action: 'time_reset_approve', licenseId: input.licenseId,
    expectedRevision: input.expectedRevision, reason, confirmedRequestDigest: input.confirmedRequestDigest,
  }, async (trx) => {
    const license = await lockLicense(trx, input.licenseId);
    const now = await adminNow(session, trx);
    if (!license) return { state: 'rejected', outcomeCode: 'LICENSE_NOT_FOUND', resultRevision: null, now, result: { license_id: input.licenseId } };
    const revision = license.revision.toString();
    if (revision !== input.expectedRevision) return { state: 'rejected', outcomeCode: 'EXPECTED_REVISION_MISMATCH', resultRevision: revision, now,
      result: { expected_revision: input.expectedRevision, observed_revision: revision } };
    const activation = await trx.selectFrom('license_activations').selectAll()
      .where('id', '=', input.activationId).where('license_id', '=', license.id).where('state', '=', 'active')
      .forUpdate().executeTakeFirst();
    if (!activation || activation.database_id !== input.databaseId || activation.instance_id !== input.instanceId ||
      activation.identity_jkt !== input.identityJkt || activation.generation.toString() !== input.activationGeneration ||
      activation.generation.toString() !== license.current_generation.toString()) {
      return { state: 'rejected', outcomeCode: 'TIME_RESET_ACTIVATION_BINDING_MISMATCH', resultRevision: revision, now,
        result: { activation_id: input.activationId, current_generation: license.current_generation.toString() } };
    }
    if (license.entitlement_revision.toString() !== input.entitlementRevision ||
      activation.time_epoch.toString() !== input.expectedTimeEpoch) {
      return { state: 'rejected', outcomeCode: 'TIME_RESET_WATERMARK_CONFLICT', resultRevision: revision, now,
        result: { expected_time_epoch: input.expectedTimeEpoch, observed_time_epoch: activation.time_epoch.toString(),
          expected_entitlement_revision: input.entitlementRevision, observed_entitlement_revision: license.entitlement_revision.toString() } };
    }
    const existingReset = await trx.selectFrom('license_time_reset_approvals').select('approval_id')
      .where('reset_operation_id', '=', input.resetOperationId).executeTakeFirst();
    if (existingReset) return { state: 'rejected', outcomeCode: 'TIME_RESET_OPERATION_ALREADY_APPROVED', resultRevision: revision, now,
      result: { reset_operation_id: input.resetOperationId, approval_id: existingReset.approval_id } };
    const newTimeEpoch = (BigInt(input.expectedTimeEpoch) + 1n).toString();
    if (BigInt(newTimeEpoch) > int64Max) return { state: 'rejected', outcomeCode: 'TIME_RESET_EPOCH_EXHAUSTED', resultRevision: revision, now,
      result: { expected_time_epoch: input.expectedTimeEpoch } };
    const expiresAt = new Date(now.getTime() + normalized.expiresInHours * 60 * 60 * 1000);
    const snapshot = {
      approval_id: input.operationId, license_id: license.id, activation_id: activation.id,
      database_id: activation.database_id, instance_id: activation.instance_id, identity_jkt: activation.identity_jkt,
      activation_generation: activation.generation.toString(), expected_revision: revision,
      entitlement_revision: license.entitlement_revision.toString(), expected_time_epoch: activation.time_epoch.toString(),
      new_time_epoch: newTimeEpoch, reset_operation_id: input.resetOperationId, intent_digest: input.intentDigest,
      old_watermark_digest: input.oldWatermarkDigest, approved_at: now.toISOString(), expires_at: expiresAt.toISOString(),
      actor_os_uid: session.actor.osUid, actor_os_username: session.actor.osUsername,
      actor_database_role: session.actor.databaseRole, reason,
    };
    await trx.insertInto('license_time_reset_approvals').values({
      approval_id: input.operationId, request_digest: requestDigest, license_id: license.id, activation_id: activation.id,
      database_id: activation.database_id, instance_id: activation.instance_id, identity_jkt: activation.identity_jkt,
      activation_generation: activation.generation.toString(), expected_revision: revision,
      entitlement_revision: license.entitlement_revision.toString(), expected_time_epoch: activation.time_epoch.toString(),
      new_time_epoch: newTimeEpoch, reset_operation_id: input.resetOperationId, intent_digest: input.intentDigest,
      old_watermark_digest: input.oldWatermarkDigest, actor_os_uid: session.actor.osUid,
      actor_os_username: session.actor.osUsername, actor_database_role: session.actor.databaseRole,
      reason, approved_at: now, expires_at: expiresAt,
    }).execute();
    await appendCoreAudit(trx, session.actor, {
      licenseId: license.id, operationId: input.operationId, kind: 'admin_time_reset_approved', reason,
      details: { ...snapshot, request_digest: requestDigest }, now,
    });
    await trx.insertInto('license_time_reset_events').values({
      event_id: randomUUID(), license_id: license.id, approval_id: input.operationId,
      operation_id: input.resetOperationId, kind: 'approved', actor: actorLabel(session.actor),
      safe_details: { request_digest: requestDigest, reset_operation_id: input.resetOperationId,
        expected_time_epoch: input.expectedTimeEpoch, new_time_epoch: newTimeEpoch, old_watermark_digest: input.oldWatermarkDigest },
      created_at: now,
    }).execute();
    return { state: 'succeeded', outcomeCode: 'TIME_RESET_APPROVED', result: snapshot, resultRevision: revision, now };
  });
}

async function revokeTimeResetApproval(session: AdminSession, input: RevokeTimeResetApprovalRequest): Promise<AdminOperationResult> {
  const reason = ensureReason(input.reason);
  const requestDigest = revokeTimeResetApprovalRequestDigest({ ...input, reason });
  return executeMutation(session, {
    operationId: input.operationId, requestDigest, action: 'time_reset_revoke', licenseId: input.licenseId,
    expectedRevision: input.expectedRevision, reason, confirmedRequestDigest: input.confirmedRequestDigest,
  }, async (trx) => {
    const license = await lockLicense(trx, input.licenseId);
    const now = await databaseNow(trx);
    if (!license) return { state: 'rejected', outcomeCode: 'LICENSE_NOT_FOUND', resultRevision: null, now, result: { license_id: input.licenseId } };
    const revision = license.revision.toString();
    if (revision !== input.expectedRevision) return { state: 'rejected', outcomeCode: 'EXPECTED_REVISION_MISMATCH', resultRevision: revision, now,
      result: { expected_revision: input.expectedRevision, observed_revision: revision } };
    const approval = await trx.selectFrom('license_time_reset_approvals').selectAll()
      .where('approval_id', '=', input.approvalId).forUpdate().executeTakeFirst();
    const adminApproval = await trx.selectFrom('license_admin_operations').selectAll()
      .where('operation_id', '=', input.approvalId).executeTakeFirst();
    if (!approval || !adminApproval || approval.license_id !== license.id ||
      adminApproval.action !== 'time_reset_approve' || adminApproval.state !== 'succeeded' ||
      adminApproval.request_digest !== approval.request_digest) {
      return { state: 'rejected', outcomeCode: 'TIME_RESET_APPROVAL_NOT_FOUND', resultRevision: revision, now,
        result: { approval_id: input.approvalId } };
    }
    const existing = await trx.selectFrom('license_time_reset_revocations').selectAll()
      .where('approval_id', '=', input.approvalId).executeTakeFirst();
    if (existing) return { state: 'rejected', outcomeCode: 'TIME_RESET_APPROVAL_ALREADY_REVOKED', resultRevision: revision, now,
      result: { approval_id: input.approvalId, revocation_operation_id: existing.revocation_operation_id } };
    const committed = await trx.selectFrom('license_operations').select('operation_id')
      .where('operation_id', '=', approval.reset_operation_id).where('kind', '=', 'time_reset')
      .where('state', '=', 'committed').executeTakeFirst();
    if (committed) return { state: 'rejected', outcomeCode: 'TIME_RESET_ALREADY_COMMITTED', resultRevision: revision, now,
      result: { approval_id: input.approvalId, reset_operation_id: approval.reset_operation_id } };
    await trx.insertInto('license_time_reset_revocations').values({
      revocation_operation_id: input.operationId, approval_id: input.approvalId, license_id: license.id,
      request_digest: requestDigest, expected_revision: revision, actor_os_uid: session.actor.osUid,
      actor_os_username: session.actor.osUsername, actor_database_role: session.actor.databaseRole,
      reason, revoked_at: now,
    }).execute();
    const result = { approval_id: input.approvalId, reset_operation_id: approval.reset_operation_id,
      revoked_at: now.toISOString(), old_time_epoch: approval.expected_time_epoch.toString() };
    await appendCoreAudit(trx, session.actor, {
      licenseId: license.id, operationId: input.operationId, kind: 'admin_time_reset_approval_revoked', reason, details: result, now,
    });
    await trx.insertInto('license_time_reset_events').values({
      event_id: randomUUID(), license_id: license.id, approval_id: input.approvalId,
      operation_id: approval.reset_operation_id, kind: 'approval_revoked', actor: actorLabel(session.actor),
      safe_details: { revocation_operation_id: input.operationId, reason }, created_at: now,
    }).execute();
    return { state: 'succeeded', outcomeCode: 'TIME_RESET_APPROVAL_REVOKED', resultRevision: revision, now, result };
  });
}

async function insertFinalLicenseOperation(
  session: AdminSession,
  input: CreateLicenseRequest,
): Promise<AdminOperationResult> {
  const reason = ensureReason(input.reason);
  const accountId = ensureText(input.accountId, 'ADMIN_ACCOUNT_ID_INVALID', 200);
  const requestDigest = createLicenseRequestDigest({ ...input, reason, accountId });
  return executeMutation(session, {
    operationId: input.operationId,
    requestDigest,
    action: 'license_create',
    licenseId: input.licenseId,
    expectedRevision: '0',
    reason,
    confirmedRequestDigest: input.confirmedRequestDigest,
  }, async (trx) => {
    await sql`SELECT pg_advisory_xact_lock(hashtextextended(${'license-admin-target:' + input.licenseId}, 0))`.execute(trx);
    const now = await databaseNow(trx);
    const exists = await trx.selectFrom('licenses').selectAll().where('id', '=', input.licenseId).forUpdate().executeTakeFirst();
    if (exists) {
      return {
        state: 'rejected', outcomeCode: 'LICENSE_ID_ALREADY_EXISTS', resultRevision: exists.revision.toString(), now,
        result: { license_id: input.licenseId, observed_revision: exists.revision.toString(), observed_status: exists.status },
      };
    }
    const anchorDay = now.getUTCDate();
    const subscriptionEnd = addCalendarPeriod(now, input.plan, anchorDay);
    await trx.insertInto('licenses').values({
      id: input.licenseId,
      account_id: accountId,
      plan: input.plan,
      billing_anchor_utc: now,
      anchor_day: anchorDay,
      confirmed_subscription_end: subscriptionEnd,
      status: 'active',
      entitlement_revision: '1',
      revision: '1',
      created_at: now,
      updated_at: now,
    }).execute();
    const result = {
      license_id: input.licenseId,
      account_id: accountId,
      plan: input.plan,
      billing_anchor_utc: now.toISOString(),
      anchor_day: anchorDay,
      subscription_end: subscriptionEnd.toISOString(),
      status: 'active',
      current_generation: '0',
      entitlement_revision: '1',
      revision: '1',
    };
    await appendCoreAudit(trx, session.actor, {
      licenseId: input.licenseId, operationId: input.operationId, kind: 'admin_license_created', reason,
      details: { plan: input.plan, anchor_day: anchorDay, billing_anchor_utc: now.toISOString(), subscription_end: subscriptionEnd.toISOString(), revision: '1' }, now,
    });
    return { state: 'succeeded', outcomeCode: 'LICENSE_CREATED', result, resultRevision: '1', now };
  });
}

async function issueActivationCode(
  session: AdminSession,
  input: IssueActivationCodeRequest,
): Promise<AdminOperationResult> {
  const reason = ensureReason(input.reason);
  const normalized = { ...input, reason, expiresInHours: input.expiresInHours ?? 24 };
  const requestDigest = issueActivationCodeRequestDigest(normalized);
  return executeMutation(session, {
    operationId: input.operationId,
    requestDigest,
    action: 'activation_code_issue',
    licenseId: input.licenseId,
    expectedRevision: input.expectedRevision,
    reason,
    confirmedRequestDigest: input.confirmedRequestDigest,
  }, async (trx) => {
    const license = await lockLicense(trx, input.licenseId);
    const now = await databaseNow(trx);
    if (!license) return {
      state: 'rejected', outcomeCode: 'LICENSE_NOT_FOUND', resultRevision: null, now,
      result: { license_id: input.licenseId },
    };
    const revision = license.revision.toString();
    if (revision !== input.expectedRevision) return {
      state: 'rejected', outcomeCode: 'EXPECTED_REVISION_MISMATCH', resultRevision: revision, now,
      result: { license_id: license.id, expected_revision: input.expectedRevision, observed_revision: revision, status: license.status },
    };
    if (license.status !== 'active') return {
      state: 'rejected', outcomeCode: 'LICENSE_REVOKED', resultRevision: revision, now,
      result: { license_id: license.id, observed_revision: revision, status: license.status },
    };
    if (license.confirmed_subscription_end.getTime() <= now.getTime()) return {
      state: 'rejected', outcomeCode: 'SUBSCRIPTION_EXPIRED', resultRevision: revision, now,
      result: { license_id: license.id, observed_revision: revision, subscription_end: license.confirmed_subscription_end.toISOString() },
    };
    if (BigInt(license.current_generation) > 0n) return {
      state: 'rejected', outcomeCode: 'LICENSE_ALREADY_ACTIVATED', resultRevision: revision, now,
      result: { license_id: license.id, current_generation: license.current_generation.toString() },
    };
    const existingCodes = await trx.selectFrom('activation_codes').selectAll()
      .where('license_id', '=', license.id).where('consumed_at', 'is', null).where('revoked_at', 'is', null)
      .orderBy('created_at', 'asc').forUpdate().execute();
    const validCodes = existingCodes.filter((code) => code.expires_at.getTime() > now.getTime());
    if (validCodes.length > 1) return {
      state: 'rejected', outcomeCode: 'ACTIVATION_CODE_STATE_AMBIGUOUS', resultRevision: revision, now,
      result: { license_id: license.id, unresolved_code_count: validCodes.length },
    };
    if (validCodes.length === 1 && input.replaceCodeId !== validCodes[0]!.id) return {
      state: 'rejected', outcomeCode: 'ACTIVATION_CODE_REPLACEMENT_REQUIRED', resultRevision: revision, now,
      result: { license_id: license.id, active_code_id: validCodes[0]!.id, expires_at: validCodes[0]!.expires_at.toISOString() },
    };
    if (input.replaceCodeId && validCodes[0]?.id !== input.replaceCodeId) return {
      state: 'rejected', outcomeCode: 'ACTIVATION_CODE_REPLACEMENT_TARGET_INVALID', resultRevision: revision, now,
      result: { license_id: license.id, replace_code_id: input.replaceCodeId },
    };
    const nextRevision = (BigInt(license.revision) + 1n).toString();
    const updatedLicense = await trx.updateTable('licenses').set({ revision: nextRevision, updated_at: now })
      .where('id', '=', license.id).where('revision', '=', revision).returning('id').executeTakeFirst();
    if (!updatedLicense) throw new AdminOperationError('EXPECTED_REVISION_MISMATCH');
    const retiredCodeIds: string[] = [];
    for (const code of existingCodes) {
      if (code.expires_at.getTime() <= now.getTime() || code.id === input.replaceCodeId) {
        await trx.updateTable('activation_codes').set({ revoked_at: now })
          .where('id', '=', code.id).where('consumed_at', 'is', null).where('revoked_at', 'is', null).execute();
        retiredCodeIds.push(code.id);
      }
    }
    const activationCode = randomBytes(32).toString('base64url');
    const codeId = randomUUID();
    const expiresAt = new Date(now.getTime() + normalized.expiresInHours * 60 * 60 * 1000);
    await trx.insertInto('activation_codes').values({
      id: codeId,
      license_id: license.id,
      token_hash: sha256Base64url(activationCode),
      expires_at: expiresAt,
      created_at: now,
    }).execute();
    const result = {
      license_id: license.id, code_id: codeId, expires_at: expiresAt.toISOString(),
      replaced_code_ids: retiredCodeIds, previous_revision: revision, revision: nextRevision,
    };
    await appendCoreAudit(trx, session.actor, {
      licenseId: license.id, operationId: input.operationId, kind: 'admin_activation_code_issued', reason,
      details: { code_id: codeId, expires_at: expiresAt.toISOString(), replaced_code_ids: retiredCodeIds }, now,
    });
    return { state: 'succeeded', outcomeCode: 'ACTIVATION_CODE_ISSUED', result, resultRevision: nextRevision, now, activationCode };
  });
}

async function renewLicense(session: AdminSession, input: RenewLicenseRequest): Promise<AdminOperationResult> {
  const reason = ensureReason(input.reason);
  const businessReference = ensureText(input.businessReference, 'ADMIN_BUSINESS_REFERENCE_REQUIRED', 200);
  const requestDigest = renewLicenseRequestDigest({ ...input, reason, businessReference });
  return executeMutation(session, {
    operationId: input.operationId,
    requestDigest,
    action: 'license_renew',
    licenseId: input.licenseId,
    expectedRevision: input.expectedRevision,
    reason,
    confirmedRequestDigest: input.confirmedRequestDigest,
  }, async (trx) => {
    const externalEventId = `admin:${input.operationId}`;
    await lockEntitlementEvent(trx, externalEventId);
    const license = await lockLicense(trx, input.licenseId);
    const now = await databaseNow(trx);
    if (!license) return {
      state: 'rejected', outcomeCode: 'LICENSE_NOT_FOUND', resultRevision: null, now,
      result: { license_id: input.licenseId, business_reference: businessReference },
    };
    const revision = license.revision.toString();
    if (revision !== input.expectedRevision) return {
      state: 'rejected', outcomeCode: 'EXPECTED_REVISION_MISMATCH', resultRevision: revision, now,
      result: { license_id: license.id, expected_revision: input.expectedRevision, observed_revision: revision, status: license.status },
    };
    const renewal = await applyConfirmedRenewalToLockedLicense(trx, license, {
      externalEventId,
      actor: actorLabel(session.actor),
      now,
      operationId: input.operationId,
      auditDetails: { operation_id: input.operationId, business_reference: businessReference, reason },
    });
    const current = await trx.selectFrom('licenses').selectAll().where('id', '=', license.id).executeTakeFirstOrThrow();
    const result = {
      license_id: license.id,
      event_id: renewal.eventId,
      previous_end: renewal.previousEnd.toISOString(),
      new_end: renewal.newEnd.toISOString(),
      plan: license.plan,
      status: current.status,
      entitlement_revision: renewal.revision,
      revision: current.revision.toString(),
      business_reference: businessReference,
    };
    return { state: 'succeeded', outcomeCode: 'LICENSE_RENEWED', result, resultRevision: current.revision.toString(), now };
  });
}

async function changeStatus(
  session: AdminSession,
  action: 'license_revoke' | 'license_restore',
  input: BaseRequest,
): Promise<AdminOperationResult> {
  const reason = ensureReason(input.reason);
  const requestDigest = changeLicenseStatusRequestDigest({ ...input, reason }, action);
  return executeMutation(session, {
    operationId: input.operationId,
    requestDigest,
    action,
    licenseId: input.licenseId,
    expectedRevision: input.expectedRevision,
    reason,
    confirmedRequestDigest: input.confirmedRequestDigest,
  }, async (trx) => {
    const license = await lockLicense(trx, input.licenseId);
    const now = await databaseNow(trx);
    if (!license) return {
      state: 'rejected', outcomeCode: 'LICENSE_NOT_FOUND', resultRevision: null, now,
      result: { license_id: input.licenseId },
    };
    const revision = license.revision.toString();
    if (revision !== input.expectedRevision) return {
      state: 'rejected', outcomeCode: 'EXPECTED_REVISION_MISMATCH', resultRevision: revision, now,
      result: { license_id: license.id, expected_revision: input.expectedRevision, observed_revision: revision, status: license.status },
    };
    const expectedStatus = action === 'license_revoke' ? 'active' : 'revoked';
    const newStatus = action === 'license_revoke' ? 'revoked' : 'active';
    if (license.status !== expectedStatus) return {
      state: 'rejected', outcomeCode: action === 'license_revoke' ? 'LICENSE_ALREADY_REVOKED' : 'LICENSE_NOT_REVOKED',
      resultRevision: revision, now,
      result: { license_id: license.id, observed_revision: revision, status: license.status },
    };
    const nextEntitlementRevision = (BigInt(license.entitlement_revision) + 1n).toString();
    const nextRevision = (BigInt(license.revision) + 1n).toString();
    await trx.updateTable('licenses').set({
      status: newStatus,
      entitlement_revision: nextEntitlementRevision,
      revision: nextRevision,
      updated_at: now,
    }).where('id', '=', license.id).where('revision', '=', revision).execute();
    const currentActivation = await trx.selectFrom('license_activations').selectAll()
      .where('license_id', '=', license.id).where('state', '=', 'active').executeTakeFirst();
    const result = {
      license_id: license.id,
      previous_status: license.status,
      status: newStatus,
      previous_revision: revision,
      revision: nextRevision,
      previous_entitlement_revision: license.entitlement_revision.toString(),
      entitlement_revision: nextEntitlementRevision,
      subscription_end: license.confirmed_subscription_end.toISOString(),
      current_generation: license.current_generation.toString(),
      activation_id: currentActivation?.id ?? null,
      activation_generation: currentActivation?.generation.toString() ?? null,
    };
    await appendCoreAudit(trx, session.actor, {
      licenseId: license.id,
      operationId: input.operationId,
      kind: action === 'license_revoke' ? 'admin_license_revoked' : 'admin_license_restored',
      reason,
      details: result,
      now,
    });
    return { state: 'succeeded', outcomeCode: action === 'license_revoke' ? 'LICENSE_REVOKED' : 'LICENSE_RESTORED', result, resultRevision: nextRevision, now };
  });
}

export interface AdminService {
  createLicense(input: CreateLicenseRequest): Promise<AdminOperationResult>;
  issueActivationCode(input: IssueActivationCodeRequest): Promise<AdminOperationResult>;
  renewLicense(input: RenewLicenseRequest): Promise<AdminOperationResult>;
  revokeLicense(input: BaseRequest): Promise<AdminOperationResult>;
  restoreLicense(input: BaseRequest): Promise<AdminOperationResult>;
  approveTransfer(input: ApproveTransferRequest): Promise<AdminOperationResult>;
  revokeTransferApproval(input: RevokeTransferApprovalRequest): Promise<AdminOperationResult>;
  approveDisasterTransfer(input: ApproveDisasterTransferRequest): Promise<AdminOperationResult>;
  revokeDisasterTransferApproval(input: RevokeDisasterTransferApprovalRequest): Promise<AdminOperationResult>;
  approveTimeReset(input: ApproveTimeResetRequest): Promise<AdminOperationResult>;
  revokeTimeResetApproval(input: RevokeTimeResetApprovalRequest): Promise<AdminOperationResult>;
  getLicense(licenseId: string): Promise<LicenseStatusView | undefined>;
  getOperation(operationId: string): Promise<Record<string, unknown> | undefined>;
  listAudit(licenseId: string, limit?: number): Promise<Array<Record<string, unknown>>>;
  close(): Promise<void>;
}

export async function createAdminService(policyFile?: string, options: { controlledTestNow?: () => Promise<Date> } = {}): Promise<AdminService> {
  const session = await openAdminSession(policyFile);
  if (options.controlledTestNow) controlledAdminClocks.set(session, options.controlledTestNow);
  return {
    createLicense: (input) => insertFinalLicenseOperation(session, input),
    issueActivationCode: (input) => issueActivationCode(session, input),
    renewLicense: (input) => renewLicense(session, input),
    revokeLicense: (input) => changeStatus(session, 'license_revoke', input),
    restoreLicense: (input) => changeStatus(session, 'license_restore', input),
    approveTransfer: (input) => approveTransfer(session, input),
    revokeTransferApproval: (input) => revokeTransferApproval(session, input),
    approveDisasterTransfer: (input) => approveDisasterTransfer(session, input),
    revokeDisasterTransferApproval: (input) => revokeDisasterTransferApproval(session, input),
    approveTimeReset: (input) => approveTimeReset(session, input),
    revokeTimeResetApproval: (input) => revokeTimeResetApproval(session, input),
    async getLicense(licenseId) {
      ensureUuid(licenseId, 'ADMIN_LICENSE_ID_INVALID');
      const license = await session.db.selectFrom('licenses').selectAll().where('id', '=', licenseId).executeTakeFirst();
      if (!license) return undefined;
      const activations = await session.db.selectFrom('license_activations').selectAll()
        .where('license_id', '=', licenseId).orderBy('generation', 'desc').execute();
      const codes = await session.db.selectFrom('activation_codes')
        .select(['id', 'created_at', 'expires_at', 'consumed_at', 'revoked_at'])
        .where('license_id', '=', licenseId).orderBy('created_at', 'desc').execute();
      const disasterApprovals = await session.db.selectFrom('license_disaster_transfer_approvals as approvals')
        .leftJoin('license_disaster_transfer_revocations as revocations', 'revocations.approval_id', 'approvals.approval_id')
        .select([
          'approvals.approval_id', 'approvals.request_id', 'approvals.account_reference', 'approvals.source_activation_id',
          'approvals.database_id', 'approvals.source_instance_id', 'approvals.source_identity_jkt',
          'approvals.target_instance_id', 'approvals.target_instance_mode', 'approvals.target_identity_jkt',
          'approvals.source_generation', 'approvals.expected_binding_revision', 'approvals.expected_revision',
          'approvals.entitlement_revision', 'approvals.actor_os_uid', 'approvals.actor_os_username',
          'approvals.actor_database_role', 'approvals.recovery_reason', 'approvals.approved_at', 'approvals.expires_at',
          'revocations.revocation_operation_id', 'revocations.revoked_at',
        ]).where('approvals.license_id', '=', licenseId).orderBy('approvals.approved_at', 'desc').execute();
      const timeResetApprovals = await session.db.selectFrom('license_time_reset_approvals as approvals')
        .leftJoin('license_time_reset_revocations as revocations', 'revocations.approval_id', 'approvals.approval_id')
        .select([
          'approvals.approval_id', 'approvals.activation_id', 'approvals.database_id', 'approvals.instance_id',
          'approvals.identity_jkt', 'approvals.activation_generation', 'approvals.expected_revision',
          'approvals.entitlement_revision', 'approvals.expected_time_epoch', 'approvals.new_time_epoch',
          'approvals.reset_operation_id', 'approvals.intent_digest', 'approvals.old_watermark_digest',
          'approvals.actor_os_uid', 'approvals.actor_os_username', 'approvals.actor_database_role',
          'approvals.reason', 'approvals.approved_at', 'approvals.expires_at',
          'revocations.revocation_operation_id', 'revocations.revoked_at',
        ]).where('approvals.license_id', '=', licenseId).orderBy('approvals.approved_at', 'desc').execute();
      const now = await databaseNow(session.db);
      return {
        license: {
          id: license.id,
          account_id: license.account_id,
          plan: license.plan,
          billing_anchor_utc: license.billing_anchor_utc.toISOString(),
          anchor_day: license.anchor_day,
          confirmed_subscription_end: license.confirmed_subscription_end.toISOString(),
          status: license.status,
          current_generation: license.current_generation.toString(),
          entitlement_revision: license.entitlement_revision.toString(),
          revision: license.revision.toString(),
          created_at: license.created_at.toISOString(),
          updated_at: license.updated_at.toISOString(),
        },
        activations: activations.map((activation) => ({
          id: activation.id,
          generation: activation.generation.toString(),
          instance_id: activation.instance_id,
          database_id: activation.database_id,
          identity_jkt: activation.identity_jkt,
          state: activation.state,
          activated_at: activation.activated_at.toISOString(),
          retired_at: activation.retired_at?.toISOString() ?? null,
          last_seen_at: activation.last_seen_at.toISOString(),
          origin_display: activation.origin_display,
          time_epoch: activation.time_epoch.toString(),
        })),
        activationCodes: codes.map((code) => ({
          id: code.id,
          created_at: code.created_at.toISOString(),
          expires_at: code.expires_at.toISOString(),
          consumed_at: code.consumed_at?.toISOString() ?? null,
          revoked_at: code.revoked_at?.toISOString() ?? null,
          status: code.consumed_at ? 'consumed' as const : code.revoked_at ? 'revoked' as const : code.expires_at.getTime() <= now.getTime() ? 'expired' as const : 'issued' as const,
        })),
        disasterTransferApprovals: disasterApprovals.map((row) => ({ ...row,
          status: row.revocation_operation_id ? 'revoked' : row.expires_at.getTime() <= now.getTime() ? 'expired' : 'approved',
        })),
        timeResetApprovals: timeResetApprovals.map((row) => ({ ...row,
          status: row.revocation_operation_id ? 'revoked' : row.expires_at.getTime() <= now.getTime() ? 'expired' : 'approved',
        })),
      };
    },
    async getOperation(operationId) {
      ensureUuid(operationId, 'ADMIN_OPERATION_ID_INVALID');
      const operation = await session.db.selectFrom('license_admin_operations').selectAll()
        .where('operation_id', '=', operationId).executeTakeFirst();
      if (!operation) return undefined;
      const [adminAudits, licenseAudits, entitlementEvents, transferApproval, transferPlans, transferEvents, transferRevocation,
        disasterRequest, disasterApproval, disasterPlans, disasterEvents, disasterRevocation] = await Promise.all([
        session.db.selectFrom('license_admin_audit_events').selectAll().where('operation_id', '=', operationId).execute(),
        session.db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', operationId).execute(),
        session.db.selectFrom('entitlement_events').selectAll()
          .where('external_event_id', '=', `admin:${operationId}`).execute(),
        session.db.selectFrom('license_transfer_approvals').selectAll().where('approval_id', '=', operationId).executeTakeFirst(),
        session.db.selectFrom('license_transfer_plans').select([
          'plan_id', 'license_id', 'approval_id', 'prepare_operation_id', 'prepare_intent_digest', 'database_id',
          'source_instance_id', 'source_identity_jkt', 'target_instance_id', 'target_identity_jkt', 'source_generation',
          'expected_binding_revision', 'expected_revision', 'entitlement_revision', 'ticket_digest', 'state', 'expires_at',
          'created_at', 'committed_at', 'commit_operation_id', 'committed_generation',
        ]).where('approval_id', '=', operationId).execute(),
        session.db.selectFrom('license_transfer_events').selectAll().where((eb) => eb.or([
          eb('approval_id', '=', operationId), eb('prepare_operation_id', '=', operationId), eb('commit_operation_id', '=', operationId),
        ])).orderBy('created_at', 'asc').execute(),
        session.db.selectFrom('license_transfer_revocations').selectAll().where((eb) => eb.or([
          eb('approval_id', '=', operationId), eb('revocation_operation_id', '=', operationId),
        ])).execute(),
        session.db.selectFrom('license_disaster_recovery_requests').selectAll().where('request_id', '=', operationId).executeTakeFirst(),
        session.db.selectFrom('license_disaster_transfer_approvals').selectAll().where('approval_id', '=', operationId).executeTakeFirst(),
        session.db.selectFrom('license_disaster_transfer_plans').select([
          'plan_id', 'request_id', 'approval_id', 'license_id', 'prepare_operation_id', 'prepare_intent_digest',
          'source_activation_id', 'database_id', 'source_instance_id', 'source_identity_jkt', 'target_instance_id',
          'target_identity_jkt', 'source_generation', 'expected_binding_revision', 'expected_revision',
          'entitlement_revision', 'ticket_digest', 'state', 'expires_at', 'created_at', 'committed_at',
          'commit_operation_id', 'committed_generation', 'result_mode',
        ]).where((eb) => eb.or([eb('approval_id', '=', operationId), eb('prepare_operation_id', '=', operationId), eb('commit_operation_id', '=', operationId)]))
          .orderBy('created_at', 'asc').execute(),
        session.db.selectFrom('license_disaster_transfer_events').selectAll().where((eb) => eb.or([
          eb('request_id', '=', operationId), eb('approval_id', '=', operationId),
          eb('prepare_operation_id', '=', operationId), eb('commit_operation_id', '=', operationId),
        ])).orderBy('created_at', 'asc').execute(),
        session.db.selectFrom('license_disaster_transfer_revocations').selectAll().where((eb) => eb.or([
          eb('approval_id', '=', operationId), eb('revocation_operation_id', '=', operationId),
        ])).execute(),
      ]);
      const [timeResetApprovals, timeResetRevocations, timeResetEvents] = await Promise.all([
        session.db.selectFrom('license_time_reset_approvals').selectAll().where((eb) => eb.or([
          eb('approval_id', '=', operationId), eb('reset_operation_id', '=', operationId),
        ])).execute(),
        session.db.selectFrom('license_time_reset_revocations').selectAll().where((eb) => eb.or([
          eb('approval_id', '=', operationId), eb('revocation_operation_id', '=', operationId),
        ])).execute(),
        session.db.selectFrom('license_time_reset_events').selectAll().where((eb) => eb.or([
          eb('approval_id', '=', operationId), eb('operation_id', '=', operationId),
        ])).orderBy('created_at', 'asc').execute(),
      ]);
      return {
        operation: mapOperation(operation, false),
        actor: { os_uid: operation.actor_os_uid, os_username: operation.actor_os_username, database_role: operation.actor_database_role },
        reason: operation.reason,
        expected_revision: operation.expected_revision.toString(),
        result: operation.result,
        admin_audit_events: adminAudits,
        license_audit_events: licenseAudits,
        entitlement_events: entitlementEvents,
        transfer_approval: transferApproval ?? null,
        transfer_plans: transferPlans,
        transfer_events: transferEvents,
        transfer_revocations: transferRevocation,
        disaster_recovery_request: disasterRequest ?? null,
        disaster_transfer_approval: disasterApproval ?? null,
        disaster_transfer_plans: disasterPlans,
        disaster_transfer_events: disasterEvents,
        disaster_transfer_revocations: disasterRevocation,
        time_reset_approvals: timeResetApprovals,
        time_reset_revocations: timeResetRevocations,
        time_reset_events: timeResetEvents,
      };
    },
    async listAudit(licenseId, limit = 50) {
      ensureUuid(licenseId, 'ADMIN_LICENSE_ID_INVALID');
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new AdminOperationError('ADMIN_AUDIT_LIMIT_INVALID');
      return session.db.selectFrom('license_admin_audit_events').selectAll()
        .where('license_id', '=', licenseId).orderBy('created_at', 'desc').limit(limit).execute() as Promise<Array<Record<string, unknown>>>;
    },
    close: () => session.close(),
  };
}
