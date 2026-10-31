import { randomUUID } from 'node:crypto';
import { sql, type Kysely, type Transaction } from 'kysely';
import type { RuntimeConfig } from '../config.js';
import type {
  ActivationCodeRow,
  ActivationRow,
  Database,
  LicenseDisasterTransferApprovalRow,
  LicenseDisasterTransferPlanRow,
  LicenseRow,
  LicenseTransferApprovalRow,
  LicenseTransferPlanRow,
  OperationRow,
  RequestNonceRow,
  LicenseTimeResetApprovalsTable,
} from '../db/types.js';
import { LicenseApiError } from '../errors.js';
import { sha256Base64url, validateIdentityJwk } from '../crypto/identity.js';
import { assertCenterTimeSourceHealthy, assertChallengeCurrent, databaseNow, challengeClaimsMatchRow, sha256, type AuthenticatedRequest } from './common.js';
import { lockSigningAuthorityForSigning } from '../crypto/signing-authority.js';
import type { SigningContext } from '../crypto/signing-types.js';
import {
  signDisasterTransferResult, signDisasterTransferTicket, signLicenseLease, signOperationReceipt, signStatusReceipt,
  signTransferReceipt, signTransferTicket, verifyDisasterTransferTicket, verifyTransferTicket,
  type OperationState,
} from '../receipts.js';
import { signTimeResetReceipt } from '../crypto/time-reset.js';

export type MutationKind = 'activation' | 'renewal' | 'recovery' | 'transfer_prepare' | 'transfer_commit' | 'disaster_transfer_prepare' | 'disaster_transfer_commit' | 'time_reset';
export interface ActivationInput {
  operation_id: string;
  intent_digest: string;
  attempt_no: number;
  license_id: string;
  database_id: string;
  instance_id: string;
  identity_jkt: string;
  public_jwk: unknown;
  challenge: string;
  activation_code: string;
  origin: string | null;
}

export interface RenewalInput {
  operation_id: string;
  intent_digest: string;
  attempt_no: number;
  license_id: string;
  database_id: string;
  instance_id: string;
  identity_jkt: string;
  public_jwk: unknown;
  challenge: string;
  expected_generation: string;
  known_revision: string;
  recovery_of_operation_id?: string;
}

export interface OperationQueryInput {
  operation_id: string;
  intent_digest: string;
  attempt_no: number;
  license_id: string;
  database_id: string;
  instance_id: string;
  identity_jkt: string;
  public_jwk: unknown;
  challenge: string;
}

export interface TransferPrepareInput {
  operation_id: string;
  intent_digest: string;
  attempt_no: number;
  license_id: string;
  database_id: string;
  instance_id: string;
  identity_jkt: string;
  public_jwk: unknown;
  challenge: string;
  approval_id: string;
  target_instance_id: string;
  target_identity_jkt: string;
  target_public_jwk: unknown;
  source_generation: string;
  expected_binding_revision: string;
  expected_revision: string;
}

export interface TransferCommitInput {
  operation_id: string;
  intent_digest: string;
  attempt_no: number;
  license_id: string;
  database_id: string;
  instance_id: string;
  identity_jkt: string;
  public_jwk: unknown;
  challenge: string;
  approval_id: string;
  prepare_operation_id: string;
  transfer_ticket: string;
}

export interface DisasterTransferPrepareInput {
  operation_id: string;
  intent_digest: string;
  attempt_no: number;
  license_id: string;
  database_id: string;
  instance_id: string;
  identity_jkt: string;
  public_jwk: unknown;
  challenge: string;
  approval_id: string;
  request_id: string;
  account_reference: string;
  source_activation_id: string;
  source_instance_id: string;
  source_identity_jkt: string;
  target_instance_id: string;
  target_identity_jkt: string;
  source_generation: string;
  expected_binding_revision: string;
  expected_revision: string;
}

export interface DisasterTransferCommitInput {
  operation_id: string;
  intent_digest: string;
  attempt_no: number;
  license_id: string;
  database_id: string;
  instance_id: string;
  identity_jkt: string;
  public_jwk: unknown;
  challenge: string;
  approval_id: string;
  prepare_operation_id: string;
  disaster_ticket: string;
}

export interface TimeResetInput {
  operation_id: string;
  intent_digest: string;
  attempt_no: number;
  license_id: string;
  database_id: string;
  instance_id: string;
  identity_jkt: string;
  public_jwk: unknown;
  challenge: string;
  activation_id: string;
  approval_id: string;
  expected_generation: string;
  expected_revision: string;
  expected_entitlement_revision: string;
  expected_time_epoch: string;
  old_watermark_digest: string;
}

export type MutationResponseType = 'license' | 'status' | 'operation' | 'disaster_ticket' | 'disaster_active' | 'disaster_binding' | 'time_reset';
export type MutationResult =
  | { kind: 'retryable'; code: string }
  | { kind: 'response'; responseType: MutationResponseType; token: string; state: 'committed' | 'rejected' | 'cancelled'; outcomeCode: string; unrecorded?: true };

type TransactionDatabase = Transaction<Database>;

function big(value: string | number | bigint): bigint {
  return BigInt(value);
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

async function acquireOperationLock(trx: TransactionDatabase, operationId: string): Promise<void> {
  await sql`SELECT pg_advisory_xact_lock(hashtextextended(${operationId}, 0))`.execute(trx);
}

async function acquireInstanceLock(trx: TransactionDatabase, instanceId: string): Promise<void> {
  await sql`SELECT pg_advisory_xact_lock(hashtextextended(${'activation-instance:' + instanceId}, 0))`.execute(trx);
}

async function lockLicense(trx: TransactionDatabase, licenseId: string): Promise<LicenseRow> {
  const license = await trx.selectFrom('licenses').selectAll().where('id', '=', licenseId).forUpdate().executeTakeFirst();
  if (!license) throw new LicenseApiError(404, 'LICENSE_NOT_FOUND');
  return license;
}

async function lockActorActivation(
  trx: TransactionDatabase,
  licenseId: string,
  identityJkt: string,
  instanceId: string,
): Promise<ActivationRow | undefined> {
  return trx.selectFrom('license_activations').selectAll()
    .where('license_id', '=', licenseId)
    .where('identity_jkt', '=', identityJkt)
    .where('instance_id', '=', instanceId)
    .orderBy('generation', 'desc')
    .forUpdate()
    .executeTakeFirst();
}

async function lockAnyActorActivation(
  trx: TransactionDatabase,
  licenseId: string,
  identityJkt: string,
): Promise<ActivationRow | undefined> {
  return trx.selectFrom('license_activations').selectAll()
    .where('license_id', '=', licenseId)
    .where('identity_jkt', '=', identityJkt)
    .orderBy('generation', 'desc')
    .forUpdate()
    .executeTakeFirst();
}

async function appendAudit(
  trx: TransactionDatabase,
  licenseId: string,
  operationId: string | null,
  kind: string,
  actor: string,
  details: Record<string, unknown>,
  now: Date,
): Promise<void> {
  await trx.insertInto('license_audit_events').values({
    id: randomUUID(), license_id: licenseId, operation_id: operationId,
    kind, actor, safe_details: details, created_at: now,
  }).execute();
}

async function appendAttempt(
  trx: TransactionDatabase,
  auth: AuthenticatedRequest,
  input: { operationId: string; attemptNo: number; intentDigest: string; outcome: 'accepted' | 'retryable_reject' | 'terminal_reject' | 'committed_replay' | 'terminal_replay' | 'cancelled_replay'; errorCode?: string | null; serverNonceHash?: string | null },
  now: Date,
): Promise<void> {
  const priorAttempt = await trx.selectFrom('license_operation_attempts').select('attempt_id')
    .where('operation_id', '=', input.operationId).where('attempt_no', '=', input.attemptNo).executeTakeFirst();
  if (priorAttempt) throw new LicenseApiError(409, 'ATTEMPT_NUMBER_REUSED');
  let serverNonceHash = input.serverNonceHash ?? null;
  if (serverNonceHash) {
    const priorNonce = await trx.selectFrom('license_operation_attempts').select('attempt_id')
      .where('server_nonce_hash', '=', serverNonceHash).executeTakeFirst();
    if (priorNonce) serverNonceHash = null;
  }
  await trx.insertInto('license_operation_attempts').values({
    attempt_id: randomUUID(),
    operation_id: input.operationId,
    attempt_no: input.attemptNo,
    intent_digest: input.intentDigest,
    body_digest: auth.requestDigest,
    client_nonce_hash: auth.challenge.clientNonceHash,
    server_nonce_hash: serverNonceHash,
    identity_jkt: auth.signature.identityJkt,
    signature_created_at: new Date(auth.signature.created * 1000),
    received_at: now,
    outcome: input.outcome,
    error_code: input.errorCode ?? null,
  }).execute();
}

async function loadAndConsumeNonce(
  trx: TransactionDatabase,
  auth: AuthenticatedRequest,
  now: Date,
): Promise<{ row?: RequestNonceRow; valid: boolean }> {
  const row = await trx.selectFrom('request_nonces').selectAll()
    .where('nonce_hash', '=', auth.challenge.nonceHash).forUpdate().executeTakeFirst();
  if (!row) return { valid: false };
  if (!challengeClaimsMatchRow(row, auth.challenge)) throw new LicenseApiError(401, 'CHALLENGE_BINDING_INVALID');
  const claimFresh = auth.challenge.fresh && now.getTime() >= auth.challenge.issuedAt * 1000 &&
    Math.floor(now.getTime() / 1000) < auth.challenge.expiresAt;
  if (!claimFresh || row.consumed_at !== null || row.expires_at.getTime() <= now.getTime()) return { row, valid: false };
  const consumed = await trx.updateTable('request_nonces').set({ consumed_at: now })
    .where('nonce_hash', '=', row.nonce_hash).where('consumed_at', 'is', null)
    .returning('nonce_hash').executeTakeFirst();
  return { row, valid: consumed !== undefined };
}

function terminalKind(state: OperationRow['state']): 'committed' | 'rejected' | 'cancelled' {
  return state;
}

async function insertOperation(
  trx: TransactionDatabase,
  input: {
    operationId: string;
    identityJkt: string;
    intentDigest: string;
    kind: MutationKind;
    licenseId: string;
    databaseId: string;
    state: 'committed' | 'rejected';
    outcomeCode: string;
    responseType: MutationResponseType;
    resultGeneration: string | null;
    resultRevision: string | null;
    responseJws: string;
    now: Date;
  },
): Promise<void> {
  await trx.insertInto('license_operations').values({
    operation_id: input.operationId,
    actor_jkt: input.identityJkt,
    intent_digest: input.intentDigest,
    kind: input.kind,
    license_id: input.licenseId,
    database_id: input.databaseId,
    state: input.state,
    outcome_code: input.outcomeCode,
    response_type: input.responseType,
    result_generation: input.resultGeneration,
    result_revision: input.resultRevision,
    response_jws: input.responseJws,
    result_digest: sha256Base64url(input.responseJws),
    created_at: input.now,
    finalized_at: input.now,
  }).execute();
}

async function terminalOperationReceipt(
  trx: TransactionDatabase,
  signer: SigningContext,
  auth: AuthenticatedRequest,
  input: {
    kind: MutationKind;
    licenseId: string;
    databaseId: string;
    state: 'rejected';
    outcomeCode: string;
    responseType: 'operation' | 'status';
    status?: { currentGeneration: string; generation: string; revision: string; subscriptionEnd: Date; state: 'expired' | 'revoked' | 'superseded' };
    generation?: string;
    revision?: string;
  },
  now: Date,
): Promise<string> {
  let token: string;
  if (input.responseType === 'status' && input.status) {
    token = await signStatusReceipt(signer, {
      licenseId: input.licenseId,
      instanceId: auth.challenge.instanceId,
      identityJkt: auth.signature.identityJkt,
      generation: input.status.generation,
      currentGeneration: input.status.currentGeneration,
      entitlementRevision: input.status.revision,
      subscriptionEnd: input.status.subscriptionEnd,
      status: input.status.state,
      requestNonce: auth.challenge.serverNonce,
      requestDigest: auth.requestDigest,
      now,
    });
  } else {
    token = await signOperationReceipt(signer, {
      licenseId: input.licenseId,
      identityJkt: auth.signature.identityJkt,
      operationId: auth.challenge.operationId,
      intentDigest: auth.challenge.intentDigest,
      state: 'rejected',
      outcomeCode: input.outcomeCode,
      attemptNo: authAttemptNo(auth),
      requestNonceHash: auth.challenge.nonceHash,
      requestDigest: auth.requestDigest,
      now,
    });
  }
  await insertOperation(trx, {
    operationId: auth.challenge.operationId,
    identityJkt: auth.signature.identityJkt,
    intentDigest: auth.challenge.intentDigest,
    kind: input.kind,
    licenseId: input.licenseId,
    databaseId: input.databaseId,
    state: input.state,
    outcomeCode: input.outcomeCode,
    responseType: input.responseType,
    resultGeneration: input.generation ?? null,
    resultRevision: input.revision ?? null,
    responseJws: token,
    now,
  });
  await appendAttempt(trx, auth, {
    operationId: auth.challenge.operationId,
    attemptNo: authAttemptNo(auth),
    intentDigest: auth.challenge.intentDigest,
    outcome: 'terminal_reject',
    errorCode: input.outcomeCode,
    serverNonceHash: auth.challenge.nonceHash,
  }, now);
  await appendAudit(trx, input.licenseId, auth.challenge.operationId, `${input.kind}_rejected`, auth.signature.identityJkt,
    { outcome_code: input.outcomeCode }, now);
  return token;
}

// attempt number is bound in the verified HTTP body at the route boundary.
const attempts = new WeakMap<AuthenticatedRequest, number>();
export function bindAttemptNumber(auth: AuthenticatedRequest, attemptNo: number): AuthenticatedRequest {
  attempts.set(auth, attemptNo);
  return auth;
}
function authAttemptNo(auth: AuthenticatedRequest): number {
  const value = attempts.get(auth);
  if (!value) throw new Error('Attempt number missing from authenticated request');
  return value;
}

async function replayExistingOperation(
  trx: TransactionDatabase,
  config: RuntimeConfig,
  auth: AuthenticatedRequest,
  operation: OperationRow,
  now: Date,
): Promise<MutationResult> {
  const actorActivation = await lockActorActivation(trx, operation.license_id, auth.signature.identityJkt, auth.challenge.instanceId);
  void actorActivation;
  const nonce = await loadAndConsumeNonce(trx, auth, now);
  if (!nonce.valid) {
    await appendAttempt(trx, auth, {
      operationId: operation.operation_id, attemptNo: authAttemptNo(auth), intentDigest: operation.intent_digest,
      outcome: 'retryable_reject', errorCode: 'CHALLENGE_EXPIRED_OR_REPLAYED',
      serverNonceHash: nonce.row?.consumed_at === null ? auth.challenge.nonceHash : null,
    }, now);
    return { kind: 'retryable', code: 'CHALLENGE_EXPIRED_OR_REPLAYED' };
  }
  const outcome = operation.state === 'committed' ? 'committed_replay' : operation.state === 'cancelled' ? 'cancelled_replay' : 'terminal_replay';
  await appendAttempt(trx, auth, {
    operationId: operation.operation_id, attemptNo: authAttemptNo(auth), intentDigest: operation.intent_digest,
    outcome, errorCode: operation.outcome_code, serverNonceHash: auth.challenge.nonceHash,
  }, now);
  await appendAudit(trx, operation.license_id, operation.operation_id, `${operation.state}_replay`, auth.signature.identityJkt,
    { attempt_no: authAttemptNo(auth) }, now);
  return {
    kind: 'response', responseType: operation.response_type, token: operation.response_jws,
    state: terminalKind(operation.state), outcomeCode: operation.outcome_code,
  };
}

async function recordRetryable(
  trx: TransactionDatabase,
  auth: AuthenticatedRequest,
  operationId: string,
  intentDigest: string,
  code: string,
  nonceRow: RequestNonceRow | undefined,
  now: Date,
): Promise<MutationResult> {
  await appendAttempt(trx, auth, {
    operationId, attemptNo: authAttemptNo(auth), intentDigest,
    outcome: 'retryable_reject', errorCode: code,
    serverNonceHash: nonceRow && nonceRow.consumed_at === null ? auth.challenge.nonceHash : null,
  }, now);
  return { kind: 'retryable', code };
}

async function findOperation(trx: TransactionDatabase, operationId: string): Promise<OperationRow | undefined> {
  return trx.selectFrom('license_operations').selectAll().where('operation_id', '=', operationId).executeTakeFirst();
}

function assertSameOperation(
  operation: OperationRow,
  auth: AuthenticatedRequest,
  kind: MutationKind,
  licenseId: string,
  databaseId: string,
): void {
  if (operation.actor_jkt !== auth.signature.identityJkt) throw new LicenseApiError(403, 'OPERATION_ACTOR_MISMATCH');
  if (operation.intent_digest !== auth.challenge.intentDigest || operation.kind !== kind || operation.license_id !== licenseId || operation.database_id !== databaseId) {
    throw new LicenseApiError(409, 'OPERATION_INTENT_CONFLICT');
  }
}

async function insertSuccessfulActivation(
  trx: TransactionDatabase,
  signer: SigningContext,
  auth: AuthenticatedRequest,
  license: LicenseRow,
  input: ActivationInput,
  code: ActivationCodeRow,
  now: Date,
): Promise<string> {
  const generation = (big(license.current_generation) + 1n).toString();
  const revision = license.entitlement_revision.toString();
  const lease = await signLicenseLease(signer, {
    licenseId: input.license_id,
    instanceId: input.instance_id,
    databaseId: input.database_id,
    identityJkt: auth.signature.identityJkt,
    generation,
    entitlementRevision: revision,
    plan: license.plan,
    subscriptionEnd: license.confirmed_subscription_end,
    requestNonce: auth.challenge.serverNonce,
    requestDigest: auth.requestDigest,
    now,
  });
  const consumed = await trx.updateTable('activation_codes').set({ consumed_at: now })
    .where('id', '=', code.id).where('consumed_at', 'is', null).where('revoked_at', 'is', null).where('expires_at', '>', now)
    .returning('id').executeTakeFirst();
  if (!consumed) throw new LicenseApiError(409, 'ACTIVATION_CODE_UNAVAILABLE');
  const activationId = randomUUID();
  await trx.insertInto('license_activations').values({
    id: activationId,
    license_id: input.license_id,
    generation,
    instance_id: input.instance_id,
    database_id: input.database_id,
    identity_jwk_public: auth.signature.identityJwk as unknown as Record<string, unknown>,
    identity_jkt: auth.signature.identityJkt,
    state: 'active',
    activated_at: now,
    retired_at: null,
    last_seen_at: now,
    origin_display: input.origin,
  }).execute();
  await trx.updateTable('licenses').set({
    current_generation: generation,
    revision: (big(license.revision) + 1n).toString(),
    updated_at: now,
  }).where('id', '=', input.license_id).execute();
  await insertOperation(trx, {
    operationId: auth.challenge.operationId,
    identityJkt: auth.signature.identityJkt,
    intentDigest: auth.challenge.intentDigest,
    kind: 'activation',
    licenseId: input.license_id,
    databaseId: input.database_id,
    state: 'committed',
    outcomeCode: 'ACTIVATED',
    responseType: 'license',
    resultGeneration: generation,
    resultRevision: revision,
    responseJws: lease.token,
    now,
  });
  await appendAttempt(trx, auth, {
    operationId: auth.challenge.operationId, attemptNo: input.attempt_no,
    intentDigest: auth.challenge.intentDigest, outcome: 'accepted', serverNonceHash: auth.challenge.nonceHash,
  }, now);
  await appendAudit(trx, input.license_id, auth.challenge.operationId, 'activation_committed', auth.signature.identityJkt,
    { generation, revision, instance_id: input.instance_id }, now);
  return lease.token;
}

async function lockActiveForActivation(trx: TransactionDatabase, licenseId: string): Promise<ActivationRow | undefined> {
  return trx.selectFrom('license_activations').selectAll()
    .where('license_id', '=', licenseId).where('state', '=', 'active').forUpdate().executeTakeFirst();
}

export async function processActivation(
  db: Kysely<Database>,
  config: RuntimeConfig,
  auth: AuthenticatedRequest,
  input: ActivationInput,
): Promise<MutationResult> {
  bindAttemptNumber(auth, input.attempt_no);
  return db.transaction().execute(async (trx) => {
    const signingAuthority = await lockSigningAuthorityForSigning(trx, config);
    const signer = signingAuthority.signer;
    await assertChallengeCurrent(signer, auth, signingAuthority.now);
    await acquireOperationLock(trx, input.operation_id);
    const license = await lockLicense(trx, input.license_id);
    const existing = await findOperation(trx, input.operation_id);
    if (existing) {
      assertSameOperation(existing, auth, 'activation', input.license_id, input.database_id);
      const now = await databaseNow(trx);
      return replayExistingOperation(trx, config, auth, existing, now);
    }
    await acquireInstanceLock(trx, input.instance_id);
    const activeActivation = await lockActiveForActivation(trx, input.license_id);
    const now = await databaseNow(trx);
    const codeHash = sha256Base64url(input.activation_code);
    const code = await trx.selectFrom('activation_codes').selectAll()
      .where('token_hash', '=', codeHash).forUpdate().executeTakeFirst();
    const nonce = await loadAndConsumeNonce(trx, auth, now);
    if (!nonce.valid) {
      if (code && code.license_id === input.license_id && code.consumed_at === null && code.revoked_at === null && code.expires_at.getTime() > now.getTime()) {
        return recordRetryable(trx, auth, input.operation_id, input.intent_digest, 'CHALLENGE_EXPIRED_OR_REPLAYED', nonce.row, now);
      }
      return { kind: 'retryable', code: 'CHALLENGE_EXPIRED_OR_REPLAYED' };
    }
    if (!code || code.license_id !== input.license_id || code.consumed_at !== null || code.revoked_at !== null || code.expires_at.getTime() <= now.getTime()) {
      if (code && code.license_id === input.license_id && code.consumed_at === null && code.revoked_at === null && code.expires_at.getTime() <= now.getTime()) {
        await trx.updateTable('activation_codes').set({ revoked_at: now }).where('id', '=', code.id).execute();
      }
      const token = await signOperationReceipt(signer, {
        licenseId: input.license_id, identityJkt: auth.signature.identityJkt,
        operationId: input.operation_id, intentDigest: input.intent_digest, state: 'rejected',
        outcomeCode: 'ACTIVATION_AUTHORIZATION_INVALID', attemptNo: input.attempt_no,
        requestNonceHash: auth.challenge.nonceHash, requestDigest: auth.requestDigest, now,
      });
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'ACTIVATION_AUTHORIZATION_INVALID', unrecorded: true };
    }
    if (license.status !== 'active') {
      const token = await terminalOperationReceipt(trx, signer, auth, {
        kind: 'activation', licenseId: input.license_id, databaseId: input.database_id, state: 'rejected',
        outcomeCode: 'LICENSE_REVOKED', responseType: 'operation',
      }, now);
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'LICENSE_REVOKED' };
    }
    if (license.confirmed_subscription_end.getTime() <= now.getTime()) {
      const token = await terminalOperationReceipt(trx, signer, auth, {
        kind: 'activation', licenseId: input.license_id, databaseId: input.database_id, state: 'rejected',
        outcomeCode: 'SUBSCRIPTION_EXPIRED', responseType: 'operation',
      }, now);
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'SUBSCRIPTION_EXPIRED' };
    }
    const activeInstance = await trx.selectFrom('license_activations').select('license_id')
      .where('instance_id', '=', input.instance_id).where('state', '=', 'active').executeTakeFirst();
    if (activeInstance && activeInstance.license_id !== input.license_id) {
      const token = await terminalOperationReceipt(trx, signer, auth, {
        kind: 'activation', licenseId: input.license_id, databaseId: input.database_id, state: 'rejected',
        outcomeCode: 'ACTIVATION_INSTANCE_ALREADY_ACTIVE', responseType: 'operation',
      }, now);
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'ACTIVATION_INSTANCE_ALREADY_ACTIVE' };
    }
    if (activeActivation || big(license.current_generation) !== 0n) {
      const token = await terminalOperationReceipt(trx, signer, auth, {
        kind: 'activation', licenseId: input.license_id, databaseId: input.database_id, state: 'rejected',
        outcomeCode: 'ACTIVATION_CONFLICT', responseType: 'operation',
      }, now);
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'ACTIVATION_CONFLICT' };
    }
    const token = await insertSuccessfulActivation(trx, signer, auth, license, input, code, now);
    return { kind: 'response', responseType: 'license', token, state: 'committed', outcomeCode: 'ACTIVATED' };
  });
}

async function signedStatus(
  trx: TransactionDatabase,
  signer: SigningContext,
  auth: AuthenticatedRequest,
  input: RenewalInput,
  license: LicenseRow,
  activation: ActivationRow,
  state: 'expired' | 'revoked' | 'superseded',
  outcomeCode: string,
  now: Date,
): Promise<MutationResult> {
  const token = await terminalOperationReceipt(trx, signer, auth, {
    kind: input.recovery_of_operation_id ? 'recovery' : 'renewal',
    licenseId: input.license_id,
    databaseId: input.database_id,
    state: 'rejected',
    outcomeCode,
    responseType: 'status',
    status: {
      currentGeneration: license.current_generation.toString(),
      generation: activation.generation.toString(),
      revision: license.entitlement_revision.toString(),
      subscriptionEnd: license.confirmed_subscription_end,
      state,
    },
    generation: activation.generation.toString(),
    revision: license.entitlement_revision.toString(),
  }, now);
  return { kind: 'response', responseType: 'status', token, state: 'rejected', outcomeCode };
}

async function lockSourceActivationOperation(trx: TransactionDatabase, operationId: string): Promise<OperationRow | undefined> {
  return trx.selectFrom('license_operations').selectAll().where('operation_id', '=', operationId).executeTakeFirst();
}

export async function processRenewal(
  db: Kysely<Database>,
  config: RuntimeConfig,
  auth: AuthenticatedRequest,
  input: RenewalInput,
): Promise<MutationResult> {
  const kind = input.recovery_of_operation_id ? 'recovery' : 'renewal';
  bindAttemptNumber(auth, input.attempt_no);
  return db.transaction().execute(async (trx) => {
    const signingAuthority = await lockSigningAuthorityForSigning(trx, config);
    const signer = signingAuthority.signer;
    await assertChallengeCurrent(signer, auth, signingAuthority.now);
    await acquireOperationLock(trx, input.operation_id);
    const license = await lockLicense(trx, input.license_id);
    const existing = await findOperation(trx, input.operation_id);
    if (existing) {
      assertSameOperation(existing, auth, kind, input.license_id, input.database_id);
      const now = await databaseNow(trx);
      return replayExistingOperation(trx, config, auth, existing, now);
    }
    const sourceOperation = input.recovery_of_operation_id
      ? await lockSourceActivationOperation(trx, input.recovery_of_operation_id)
      : undefined;
    const activation = await lockAnyActorActivation(trx, input.license_id, auth.signature.identityJkt);
    if (!activation) throw new LicenseApiError(403, 'IDENTITY_BINDING_MISMATCH');
    if (activation.instance_id !== input.instance_id) throw new LicenseApiError(403, 'IDENTITY_BINDING_MISMATCH');
    if (activation.database_id !== input.database_id) throw new LicenseApiError(409, 'DATABASE_BINDING_MISMATCH');
    const now = await databaseNow(trx);
    const nonce = await loadAndConsumeNonce(trx, auth, now);
    if (!nonce.valid) return recordRetryable(trx, auth, input.operation_id, input.intent_digest, 'CHALLENGE_EXPIRED_OR_REPLAYED', nonce.row, now);
    const operationKind: MutationKind = kind;
    if (activation.state !== 'active' || activation.generation !== license.current_generation ||
      activation.generation !== input.expected_generation) {
      if (activation.state === 'active' && activation.generation !== input.expected_generation) {
        throw new LicenseApiError(409, 'GENERATION_BINDING_MISMATCH');
      }
      return signedStatus(trx, signer, auth, input, license, activation, 'superseded', 'ACTIVATION_SUPERSEDED', now);
    }
    if (license.status === 'revoked') return signedStatus(trx, signer, auth, input, license, activation, 'revoked', 'LICENSE_REVOKED', now);
    if (big(input.known_revision) > big(license.entitlement_revision)) throw new LicenseApiError(409, 'REVISION_AHEAD');
    if (license.confirmed_subscription_end.getTime() <= now.getTime()) {
      return signedStatus(trx, signer, auth, input, license, activation, 'expired', 'SUBSCRIPTION_EXPIRED', now);
    }
    if (input.recovery_of_operation_id) {
      const sourceValid = sourceOperation?.state === 'committed' && sourceOperation.kind === 'activation' &&
        sourceOperation.license_id === input.license_id && sourceOperation.database_id === input.database_id &&
        sourceOperation.actor_jkt === auth.signature.identityJkt && sourceOperation.result_generation === activation.generation;
      if (!sourceValid) {
        const token = await terminalOperationReceipt(trx, signer, auth, {
          kind: operationKind, licenseId: input.license_id, databaseId: input.database_id,
          state: 'rejected', outcomeCode: 'RECOVERY_SOURCE_INVALID', responseType: 'operation',
        }, now);
        return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'RECOVERY_SOURCE_INVALID' };
      }
    }
    const lease = await signLicenseLease(signer, {
      licenseId: input.license_id,
      instanceId: input.instance_id,
      databaseId: input.database_id,
      identityJkt: auth.signature.identityJkt,
      generation: activation.generation.toString(),
      entitlementRevision: license.entitlement_revision.toString(),
      plan: license.plan,
      subscriptionEnd: license.confirmed_subscription_end,
      requestNonce: auth.challenge.serverNonce,
      requestDigest: auth.requestDigest,
      now,
    });
    await trx.updateTable('license_activations').set({ last_seen_at: now })
      .where('id', '=', activation.id).where('state', '=', 'active').execute();
    await insertOperation(trx, {
      operationId: auth.challenge.operationId,
      identityJkt: auth.signature.identityJkt,
      intentDigest: auth.challenge.intentDigest,
      kind: operationKind,
      licenseId: input.license_id,
      databaseId: input.database_id,
      state: 'committed',
      outcomeCode: 'LEASE_ISSUED',
      responseType: 'license',
      resultGeneration: activation.generation.toString(),
      resultRevision: license.entitlement_revision.toString(),
      responseJws: lease.token,
      now,
    });
    await appendAttempt(trx, auth, {
      operationId: auth.challenge.operationId, attemptNo: input.attempt_no,
      intentDigest: auth.challenge.intentDigest, outcome: 'accepted', serverNonceHash: auth.challenge.nonceHash,
    }, now);
    await appendAudit(trx, input.license_id, auth.challenge.operationId, `${kind}_committed`, auth.signature.identityJkt,
      { generation: activation.generation.toString(), revision: license.entitlement_revision.toString() }, now);
    return { kind: 'response', responseType: 'license', token: lease.token, state: 'committed', outcomeCode: 'LEASE_ISSUED' };
  });
}

export async function processTimeReset(
  db: Kysely<Database>,
  config: RuntimeConfig,
  auth: AuthenticatedRequest,
  input: TimeResetInput,
): Promise<MutationResult> {
  bindAttemptNumber(auth, input.attempt_no);
  const identity = await validateIdentityJwk(input.public_jwk);
  if (input.identity_jkt !== auth.signature.identityJkt || identity.jkt !== auth.signature.identityJkt ||
    input.operation_id !== auth.challenge.operationId || input.intent_digest !== auth.challenge.intentDigest ||
    input.instance_id !== auth.challenge.instanceId) throw new LicenseApiError(401, 'TIME_RESET_IDENTITY_PROOF_INVALID');

  return db.transaction().execute(async (trx) => {
    const signingAuthority = await lockSigningAuthorityForSigning(trx, config);
    const signer = signingAuthority.signer;
    await assertChallengeCurrent(signer, auth, signingAuthority.now);
    await acquireOperationLock(trx, input.operation_id);
    const license = await lockLicense(trx, input.license_id);
    const existing = await findOperation(trx, input.operation_id);
    if (existing) {
      assertSameOperation(existing, auth, 'time_reset', input.license_id, input.database_id);
      const activeGeneration = await trx.selectFrom('license_activations').selectAll()
        .where('id', '=', input.activation_id).where('license_id', '=', input.license_id)
        .where('database_id', '=', input.database_id).where('instance_id', '=', input.instance_id)
        .where('identity_jkt', '=', auth.signature.identityJkt).where('state', '=', 'active')
        .forUpdate().executeTakeFirst();
      if (!activeGeneration || activeGeneration.generation.toString() !== existing.result_generation ||
        activeGeneration.generation.toString() !== license.current_generation.toString() ||
        BigInt(activeGeneration.time_epoch) <= BigInt(input.expected_time_epoch)) {
        throw new LicenseApiError(403, 'TIME_RESET_INSTANCE_BINDING_MISMATCH');
      }
      const replayNow = await databaseNow(trx);
      assertCenterTimeSourceHealthy(replayNow);
      return replayExistingOperation(trx, config, auth, existing, replayNow);
    }

    const activation = await trx.selectFrom('license_activations').selectAll()
      .where('id', '=', input.activation_id).where('license_id', '=', input.license_id)
      .where('state', '=', 'active').forUpdate().executeTakeFirst();
    const now = await databaseNow(trx);
    assertCenterTimeSourceHealthy(now);
    if (!activation || activation.instance_id !== input.instance_id || activation.database_id !== input.database_id ||
      activation.identity_jkt !== auth.signature.identityJkt || activation.generation.toString() !== input.expected_generation ||
      activation.generation.toString() !== license.current_generation.toString() ||
      activation.identity_jwk_public['kty'] !== identity.jwk.kty || activation.identity_jwk_public['crv'] !== identity.jwk.crv ||
      activation.identity_jwk_public['x'] !== identity.jwk.x) {
      throw new LicenseApiError(403, 'TIME_RESET_INSTANCE_BINDING_MISMATCH');
    }
    if (license.revision.toString() !== input.expected_revision ||
      license.entitlement_revision.toString() !== input.expected_entitlement_revision ||
      activation.time_epoch.toString() !== input.expected_time_epoch) {
      throw new LicenseApiError(409, 'TIME_RESET_WATERMARK_CONFLICT');
    }

    const approval = await trx.selectFrom('license_time_reset_approvals').selectAll()
      .where('approval_id', '=', input.approval_id).forUpdate().executeTakeFirst();
    const adminOperation = await trx.selectFrom('license_admin_operations').selectAll()
      .where('operation_id', '=', input.approval_id).executeTakeFirst();
    const adminAudit = await trx.selectFrom('license_admin_audit_events').selectAll()
      .where('operation_id', '=', input.approval_id).where('action', '=', 'time_reset_approve')
      .executeTakeFirst();
    const revoked = await trx.selectFrom('license_time_reset_revocations').select('approval_id')
      .where('approval_id', '=', input.approval_id).executeTakeFirst();
    const approvalMatches = approval !== undefined && !revoked && adminOperation !== undefined && adminAudit !== undefined &&
      adminOperation.action === 'time_reset_approve' && adminOperation.state === 'succeeded' &&
      adminOperation.outcome_code === 'TIME_RESET_APPROVED' && adminOperation.license_id === license.id &&
      adminOperation.expected_revision.toString() === input.expected_revision && adminOperation.reason === approval.reason &&
      adminAudit.action === 'time_reset_approve' && adminAudit.license_id === license.id &&
      adminAudit.state === 'succeeded' && adminAudit.request_digest === approval.request_digest &&
      adminAudit.expected_revision.toString() === input.expected_revision && adminAudit.reason === approval.reason &&
      adminOperation.request_digest === approval.request_digest && adminAudit.actor_os_uid === approval.actor_os_uid &&
      adminAudit.actor_os_username === approval.actor_os_username && adminAudit.actor_database_role === approval.actor_database_role &&
      approval.license_id === license.id && approval.activation_id === activation.id &&
      approval.database_id === input.database_id && approval.instance_id === input.instance_id &&
      approval.identity_jkt === auth.signature.identityJkt && approval.activation_generation.toString() === input.expected_generation &&
      approval.expected_revision.toString() === input.expected_revision &&
      approval.entitlement_revision.toString() === input.expected_entitlement_revision &&
      approval.expected_time_epoch.toString() === input.expected_time_epoch &&
      approval.new_time_epoch.toString() === (BigInt(input.expected_time_epoch) + 1n).toString() &&
      approval.reset_operation_id === input.operation_id && approval.intent_digest === input.intent_digest &&
      approval.old_watermark_digest === input.old_watermark_digest && approval.expires_at.getTime() > now.getTime();
    if (!approvalMatches || !approval || !adminOperation || !adminAudit) {
      throw new LicenseApiError(403, revoked ? 'TIME_RESET_APPROVAL_REVOKED' : 'TIME_RESET_APPROVAL_INVALID');
    }

    const nonce = await loadAndConsumeNonce(trx, auth, now);
    if (!nonce.valid) return recordRetryable(trx, auth, input.operation_id, input.intent_digest, 'CHALLENGE_EXPIRED_OR_REPLAYED', nonce.row, now);

    const oldEpoch = activation.time_epoch.toString();
    const newEpoch = (BigInt(oldEpoch) + 1n).toString();
    if (BigInt(newEpoch) > MAX_DATABASE_INTEGER) throw new LicenseApiError(409, 'TIME_RESET_EPOCH_EXHAUSTED');
    const epochUpdate = await trx.updateTable('license_activations').set({ time_epoch: newEpoch, last_seen_at: now })
      .where('id', '=', activation.id).where('state', '=', 'active').where('time_epoch', '=', oldEpoch)
      .returning('id').executeTakeFirst();
    if (!epochUpdate) throw new LicenseApiError(409, 'TIME_RESET_WATERMARK_CONFLICT');

    const eventId = randomUUID();
    const token = await signTimeResetReceipt(signer, {
      license_id: license.id,
      database_id: activation.database_id,
      instance_id: activation.instance_id,
      identity_jkt: activation.identity_jkt,
      activation_generation: activation.generation.toString(),
      management_revision: license.revision.toString(),
      entitlement_revision: license.entitlement_revision.toString(),
      old_time_epoch: oldEpoch,
      new_time_epoch: newEpoch,
      old_watermark_digest: input.old_watermark_digest,
      operation_id: input.operation_id,
      intent_digest: input.intent_digest,
      request_nonce: auth.challenge.serverNonce,
      client_nonce: auth.challenge.clientNonce,
      request_digest: auth.requestDigest,
      admin_approval_id: approval.approval_id,
      admin_operation_id: adminOperation.operation_id,
      admin_approval_digest: approval.request_digest,
      admin_os_uid: approval.actor_os_uid,
      admin_os_username: approval.actor_os_username,
      admin_database_role: approval.actor_database_role,
      admin_reason: approval.reason,
      admin_audit_reference: `license_admin_audit_events:${approval.approval_id}`,
    }, now);

    await insertOperation(trx, {
      operationId: input.operation_id,
      identityJkt: auth.signature.identityJkt,
      intentDigest: input.intent_digest,
      kind: 'time_reset',
      licenseId: license.id,
      databaseId: input.database_id,
      state: 'committed',
      outcomeCode: 'TIME_RESET_COMMITTED',
      responseType: 'time_reset',
      resultGeneration: activation.generation.toString(),
      resultRevision: license.revision.toString(),
      responseJws: token,
      now,
    });
    await appendAttempt(trx, auth, {
      operationId: input.operation_id, attemptNo: input.attempt_no, intentDigest: input.intent_digest,
      outcome: 'accepted', serverNonceHash: auth.challenge.nonceHash,
    }, now);
    await appendAudit(trx, license.id, input.operation_id, 'time_reset_committed', auth.signature.identityJkt, {
      activation_id: activation.id, generation: activation.generation.toString(), old_time_epoch: oldEpoch,
      new_time_epoch: newEpoch, expected_revision: license.revision.toString(),
      entitlement_revision: license.entitlement_revision.toString(), approval_id: approval.approval_id,
      old_watermark_digest: input.old_watermark_digest, client_nonce_hash: sha256(auth.challenge.clientNonce),
      request_nonce_hash: auth.challenge.nonceHash, request_digest: auth.requestDigest, event_id: eventId,
    }, now);
    await trx.insertInto('license_time_reset_events').values({
      event_id: eventId, license_id: license.id, approval_id: approval.approval_id,
      operation_id: input.operation_id, kind: 'committed', actor: auth.signature.identityJkt,
      safe_details: { old_time_epoch: oldEpoch, new_time_epoch: newEpoch, request_digest: auth.requestDigest,
        old_watermark_digest: input.old_watermark_digest, admin_audit_reference: `license_admin_audit_events:${approval.approval_id}` },
      created_at: now,
    }).execute();
    return { kind: 'response', responseType: 'time_reset', token, state: 'committed', outcomeCode: 'TIME_RESET_COMMITTED' };
  });
}

export async function queryOperation(
  db: Kysely<Database>,
  config: RuntimeConfig,
  auth: AuthenticatedRequest,
  input: OperationQueryInput,
): Promise<string | { retryable: string }> {
  bindAttemptNumber(auth, input.attempt_no);
  return db.transaction().execute(async (trx) => {
    const signingAuthority = await lockSigningAuthorityForSigning(trx, config);
    const signer = signingAuthority.signer;
    await assertChallengeCurrent(signer, auth, signingAuthority.now);
    await acquireOperationLock(trx, input.operation_id);
    const visibleOperation = await findOperation(trx, input.operation_id);
    if (!visibleOperation || visibleOperation.actor_jkt !== auth.signature.identityJkt) {
      const now = await databaseNow(trx);
      const nonce = await loadAndConsumeNonce(trx, auth, now);
      if (!nonce.valid) return { retryable: 'CHALLENGE_EXPIRED_OR_REPLAYED' };
      return signOperationReceipt(signer, {
        licenseId: input.license_id, identityJkt: auth.signature.identityJkt,
        operationId: input.operation_id, intentDigest: input.intent_digest, state: 'not_found',
        outcomeCode: 'OPERATION_NOT_FOUND', attemptNo: input.attempt_no,
        requestNonceHash: auth.challenge.nonceHash, requestDigest: auth.requestDigest, now,
      });
    }
    const license = await lockLicense(trx, input.license_id);
    const activation = await lockActorActivation(trx, input.license_id, auth.signature.identityJkt, input.instance_id);
    if (activation && activation.database_id !== input.database_id) throw new LicenseApiError(409, 'DATABASE_BINDING_MISMATCH');
    const now = await databaseNow(trx);
    const normalTarget = !activation && license.status === 'active' && license.confirmed_subscription_end.getTime() > now.getTime()
      ? await sql<{ associated: boolean }>`
        SELECT EXISTS (
          SELECT 1
          FROM license_transfer_approvals AS approval
          JOIN license_admin_operations AS admin
            ON admin.operation_id = approval.approval_id
          JOIN license_activations AS source
            ON source.license_id = approval.license_id
            AND source.database_id = approval.database_id
            AND source.instance_id = approval.source_instance_id
            AND source.identity_jkt = approval.source_identity_jkt
            AND source.generation = approval.source_generation
            AND source.state = 'active'
          WHERE approval.license_id = ${license.id}
            AND approval.database_id = ${input.database_id}
            AND approval.target_instance_id = ${input.instance_id}
            AND approval.target_identity_jkt = ${auth.signature.identityJkt}
            AND approval.expected_revision = ${license.revision}
            AND approval.source_generation = ${license.current_generation}
            AND approval.expires_at > ${now}
            AND admin.action = 'transfer_approve'
            AND admin.state = 'succeeded'
            AND admin.request_digest = approval.request_digest
            AND NOT EXISTS (
              SELECT 1 FROM license_transfer_revocations AS revocation
              WHERE revocation.approval_id = approval.approval_id
            )
        ) AS associated
      `.execute(trx)
      : undefined;
    const normalAssociated = normalTarget?.rows[0]?.associated === true;
    const disasterTarget = !activation && !normalAssociated
      ? await sql<{ associated: boolean }>`
        SELECT EXISTS (
          SELECT 1
          FROM license_disaster_transfer_approvals AS approval
          JOIN license_admin_operations AS admin
            ON admin.operation_id = approval.approval_id
          JOIN license_disaster_recovery_requests AS recovery
            ON recovery.request_id = approval.request_id
          JOIN license_activations AS source
            ON source.id = approval.source_activation_id
            AND source.license_id = approval.license_id
            AND source.database_id = approval.database_id
            AND source.instance_id = approval.source_instance_id
            AND source.identity_jkt = approval.source_identity_jkt
            AND source.generation = approval.source_generation
            AND source.state = 'active'
          WHERE approval.license_id = ${license.id}
            AND approval.account_reference = ${license.account_id}
            AND approval.database_id = ${input.database_id}
            AND approval.target_instance_id = ${input.instance_id}
            AND approval.target_identity_jkt = ${auth.signature.identityJkt}
            AND approval.expected_revision = ${license.revision}
            AND approval.source_generation = ${license.current_generation}
            AND approval.entitlement_revision = ${license.entitlement_revision}
            AND approval.expires_at > ${now}
            AND admin.action = 'disaster_transfer_approve'
            AND admin.state = 'succeeded'
            AND admin.request_digest = approval.request_digest
            AND recovery.request_digest = approval.request_digest
            AND recovery.license_id = approval.license_id
            AND recovery.account_reference = approval.account_reference
            AND recovery.source_activation_id = approval.source_activation_id
            AND recovery.database_id = approval.database_id
            AND recovery.source_instance_id = approval.source_instance_id
            AND recovery.source_identity_jkt = approval.source_identity_jkt
            AND recovery.target_instance_id = approval.target_instance_id
            AND recovery.target_identity_jkt = approval.target_identity_jkt
            AND NOT EXISTS (
              SELECT 1 FROM license_disaster_transfer_revocations AS revocation
              WHERE revocation.approval_id = approval.approval_id
            )
        ) AS associated
      `.execute(trx)
      : undefined;
    const associated = visibleOperation.actor_jkt === auth.signature.identityJkt || activation !== undefined || normalAssociated || disasterTarget?.rows[0]?.associated === true;
    const nonce = await loadAndConsumeNonce(trx, auth, now);
    const result = async (state: OperationState, outcomeCode: string | null, resultJws: string | null,
      attempt: { attemptNo: number; nonceHash: string; requestDigest: string } | undefined) => signOperationReceipt(signer, {
      licenseId: input.license_id,
      identityJkt: auth.signature.identityJkt,
      operationId: input.operation_id,
      intentDigest: input.intent_digest,
      state,
      outcomeCode,
      attemptNo: input.attempt_no,
      requestNonceHash: auth.challenge.nonceHash,
      requestDigest: auth.requestDigest,
      committedAttemptNo: attempt?.attemptNo ?? null,
      committedRequestNonceHash: attempt?.nonceHash ?? null,
      committedRequestDigest: attempt?.requestDigest ?? null,
      resultJws,
      now,
    });
    if (!associated) {
      if (!nonce.valid) return { retryable: 'CHALLENGE_EXPIRED_OR_REPLAYED' };
      return result('not_found', 'OPERATION_NOT_FOUND', null, undefined);
    }
    const existing = await findOperation(trx, input.operation_id);
    if (existing && existing.actor_jkt !== auth.signature.identityJkt) throw new LicenseApiError(403, 'OPERATION_ACTOR_MISMATCH');
    if (existing && (existing.intent_digest !== input.intent_digest || existing.license_id !== input.license_id || existing.database_id !== input.database_id)) {
      throw new LicenseApiError(409, 'OPERATION_INTENT_CONFLICT');
    }
    if (!nonce.valid) {
      await appendAttempt(trx, auth, {
        operationId: input.operation_id, attemptNo: input.attempt_no, intentDigest: input.intent_digest,
        outcome: 'retryable_reject', errorCode: 'CHALLENGE_EXPIRED_OR_REPLAYED',
        serverNonceHash: nonce.row?.consumed_at === null ? auth.challenge.nonceHash : null,
      }, now);
      return { retryable: 'CHALLENGE_EXPIRED_OR_REPLAYED' };
    }
    if (!existing) {
      await appendAttempt(trx, auth, {
        operationId: input.operation_id, attemptNo: input.attempt_no, intentDigest: input.intent_digest,
        outcome: 'retryable_reject', errorCode: 'OPERATION_NOT_FOUND', serverNonceHash: auth.challenge.nonceHash,
      }, now);
      await appendAudit(trx, license.id, input.operation_id, 'operation_query_not_found', auth.signature.identityJkt, {}, now);
      return result('not_found', 'OPERATION_NOT_FOUND', null, undefined);
    }
    const attempt = await trx.selectFrom('license_operation_attempts').selectAll()
      .where('operation_id', '=', existing.operation_id)
      .where('outcome', 'in', ['accepted', 'terminal_reject'])
      .orderBy('attempt_no', 'asc').executeTakeFirst();
    const replayOutcome = existing.state === 'committed' ? 'committed_replay' : existing.state === 'cancelled' ? 'cancelled_replay' : 'terminal_replay';
    await appendAttempt(trx, auth, {
      operationId: input.operation_id, attemptNo: input.attempt_no, intentDigest: input.intent_digest,
      outcome: replayOutcome, errorCode: existing.outcome_code, serverNonceHash: auth.challenge.nonceHash,
    }, now);
    await appendAudit(trx, license.id, input.operation_id, 'operation_query', auth.signature.identityJkt,
      { state: existing.state }, now);
    return result(terminalKind(existing.state), existing.outcome_code, existing.response_jws,
      attempt ? { attemptNo: attempt.attempt_no, nonceHash: attempt.server_nonce_hash ?? '', requestDigest: attempt.body_digest } : undefined);
  });
}

export async function continueOperation(
  db: Kysely<Database>,
  config: RuntimeConfig,
  auth: AuthenticatedRequest,
  kind: MutationKind,
  input: ActivationInput | RenewalInput,
): Promise<string> {
  bindAttemptNumber(auth, input.attempt_no);
  const direct = kind === 'activation'
    ? await processActivation(db, config, auth, input as ActivationInput)
    : await processRenewal(db, config, auth, input as RenewalInput);
  if (direct.kind === 'retryable') throw new LicenseApiError(409, direct.code);
  if (direct.unrecorded) return direct.token;
  return db.transaction().execute(async (trx) => {
    const signingAuthority = await lockSigningAuthorityForSigning(trx, config);
    const signer = signingAuthority.signer;
    await assertChallengeCurrent(signer, auth, signingAuthority.now);
    await acquireOperationLock(trx, input.operation_id);
    const source = await trx.selectFrom('license_operations').selectAll().where('operation_id', '=', input.operation_id).executeTakeFirst();
    if (!source) throw new LicenseApiError(503, 'OPERATION_STATE_UNKNOWN');
    const attempt = await trx.selectFrom('license_operation_attempts').selectAll()
      .where('operation_id', '=', source.operation_id).where('outcome', 'in', ['accepted', 'terminal_reject'])
      .orderBy('attempt_no', 'asc').executeTakeFirst();
    const now = await databaseNow(trx);
    return signOperationReceipt(signer, {
      licenseId: source.license_id,
      identityJkt: auth.signature.identityJkt,
      operationId: source.operation_id,
      intentDigest: source.intent_digest,
      state: source.state,
      outcomeCode: source.outcome_code,
      attemptNo: input.attempt_no,
      requestNonceHash: auth.challenge.nonceHash,
      requestDigest: auth.requestDigest,
      committedAttemptNo: attempt?.attempt_no ?? null,
      committedRequestNonceHash: attempt?.server_nonce_hash ?? null,
      committedRequestDigest: attempt?.body_digest ?? null,
      resultJws: source.response_jws,
      now,
    });
  });
}

const MAX_DATABASE_INTEGER = 9_223_372_036_854_775_807n;

function transferEventActor(identityJkt: string): string {
  return `instance_jkt:${identityJkt}`;
}

async function appendTransferEvent(trx: TransactionDatabase, input: {
  licenseId: string;
  approvalId: string;
  prepareOperationId?: string | null;
  commitOperationId?: string | null;
  planId?: string | null;
  kind: 'approved' | 'prepared' | 'expired' | 'invalidated' | 'committed' | 'rejected';
  actor: string;
  details: Record<string, unknown>;
  now: Date;
}): Promise<void> {
  await trx.insertInto('license_transfer_events').values({
    event_id: randomUUID(), license_id: input.licenseId, approval_id: input.approvalId,
    prepare_operation_id: input.prepareOperationId ?? null, commit_operation_id: input.commitOperationId ?? null,
    plan_id: input.planId ?? null, kind: input.kind, actor: input.actor, safe_details: input.details, created_at: input.now,
  }).execute();
}

async function expireOrInvalidatePlan(trx: TransactionDatabase, plan: LicenseTransferPlanRow,
  state: 'expired' | 'invalidated', actor: string, reason: string, now: Date): Promise<void> {
  await trx.updateTable('license_transfer_plans').set({ state }).where('plan_id', '=', plan.plan_id).where('state', '=', 'prepared').execute();
  await appendTransferEvent(trx, {
    licenseId: plan.license_id, approvalId: plan.approval_id, prepareOperationId: plan.prepare_operation_id,
    planId: plan.plan_id, kind: state, actor, details: { reason }, now,
  });
}

function approvalMatchesPrepare(approval: LicenseTransferApprovalRow, input: TransferPrepareInput,
  identityJkt: string, targetJkt: string, license: LicenseRow, now: Date): boolean {
  return approval.license_id === input.license_id && approval.database_id === input.database_id &&
    approval.source_instance_id === input.instance_id && approval.source_identity_jkt === identityJkt &&
    approval.target_instance_id === input.target_instance_id && approval.target_identity_jkt === targetJkt &&
    approval.source_generation.toString() === input.source_generation &&
    approval.expected_binding_revision.toString() === input.expected_binding_revision &&
    approval.expected_revision.toString() === input.expected_revision && license.revision.toString() === input.expected_revision &&
    license.current_generation.toString() === input.source_generation && license.status === 'active' &&
    license.confirmed_subscription_end.getTime() > now.getTime() && approval.expires_at.getTime() > now.getTime();
}

export async function processTransferPrepare(
  db: Kysely<Database>, config: RuntimeConfig, auth: AuthenticatedRequest, input: TransferPrepareInput,
): Promise<MutationResult> {
  bindAttemptNumber(auth, input.attempt_no);
  const targetIdentity = await validateIdentityJwk(input.target_public_jwk);
  if (input.identity_jkt !== auth.signature.identityJkt || input.target_identity_jkt !== targetIdentity.jkt ||
    input.target_instance_id !== input.instance_id || input.target_identity_jkt === auth.signature.identityJkt) {
    throw new LicenseApiError(409, 'TRANSFER_TARGET_BINDING_INVALID');
  }
  if (input.operation_id === input.approval_id) throw new LicenseApiError(409, 'TRANSFER_OPERATION_ID_REUSE');
  return db.transaction().execute(async (trx) => {
    const signingAuthority = await lockSigningAuthorityForSigning(trx, config);
    const signer = signingAuthority.signer;
    await assertChallengeCurrent(signer, auth, signingAuthority.now);
    await acquireOperationLock(trx, input.operation_id);
    const license = await lockLicense(trx, input.license_id);
    const existing = await findOperation(trx, input.operation_id);
    if (existing) {
      assertSameOperation(existing, auth, 'transfer_prepare', input.license_id, input.database_id);
      const now = await databaseNow(trx);
      return replayExistingOperation(trx, config, auth, existing, now);
    }
    await acquireInstanceLock(trx, input.instance_id);
    const now = await databaseNow(trx);
    const approval = await trx.selectFrom('license_transfer_approvals').selectAll()
      .where('approval_id', '=', input.approval_id).executeTakeFirst();
    const adminApproval = await trx.selectFrom('license_admin_operations').select(['operation_id', 'action', 'state', 'request_digest'])
      .where('operation_id', '=', input.approval_id).executeTakeFirst();
    const approvalRevoked = await trx.selectFrom('license_transfer_revocations').select('approval_id')
      .where('approval_id', '=', input.approval_id).executeTakeFirst();
    const targetWasUsed = await trx.selectFrom('license_activations').select('id')
      .where('license_id', '=', input.license_id).where('identity_jkt', '=', targetIdentity.jkt).executeTakeFirst();
    const source = await lockActorActivation(trx, input.license_id, auth.signature.identityJkt, input.instance_id);
    const validSource = source !== undefined && source.state === 'active' && source.database_id === input.database_id &&
      source.generation.toString() === input.source_generation && source.identity_jkt === auth.signature.identityJkt &&
      source.identity_jwk_public['kty'] === auth.signature.identityJwk.kty &&
      source.identity_jwk_public['crv'] === auth.signature.identityJwk.crv &&
      source.identity_jwk_public['x'] === auth.signature.identityJwk.x;
    const validApproval = approval !== undefined && !approvalRevoked && targetWasUsed === undefined &&
      adminApproval?.action === 'transfer_approve' && adminApproval.state === 'succeeded' &&
      adminApproval.request_digest === approval.request_digest &&
      approvalMatchesPrepare(approval, input, auth.signature.identityJkt, targetIdentity.jkt, license, now);
    if (!validSource || !validApproval) throw new LicenseApiError(403, 'TRANSFER_PREPARE_FORBIDDEN');
    const nonce = await loadAndConsumeNonce(trx, auth, now);
    if (!nonce.valid) return recordRetryable(trx, auth, input.operation_id, input.intent_digest, 'CHALLENGE_EXPIRED_OR_REPLAYED', nonce.row, now);

    const disasterApprovalConflict = await sql<{ present: boolean }>`
      SELECT EXISTS (
        SELECT 1 FROM license_disaster_transfer_approvals a
        LEFT JOIN license_disaster_transfer_revocations r ON r.approval_id = a.approval_id
        WHERE a.license_id = ${input.license_id} AND a.expected_revision = ${license.revision}
          AND a.source_generation = ${license.current_generation} AND a.expires_at > ${now} AND r.approval_id IS NULL
      ) OR EXISTS (
        SELECT 1 FROM license_disaster_transfer_plans p
        WHERE p.license_id = ${input.license_id} AND p.state = 'prepared'
      ) AS present
    `.execute(trx);
    if (disasterApprovalConflict.rows[0]?.present) {
      const token = await terminalOperationReceipt(trx, signer, auth, {
        kind: 'transfer_prepare', licenseId: input.license_id, databaseId: input.database_id, state: 'rejected',
        outcomeCode: 'DISASTER_TRANSFER_REQUIRES_EXPLICIT_REVOCATION', responseType: 'operation',
      }, now);
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'DISASTER_TRANSFER_REQUIRES_EXPLICIT_REVOCATION' };
    }
    const matchingApprovals = await trx.selectFrom('license_transfer_approvals').select('approval_id')
      .where('license_id', '=', input.license_id).where('expires_at', '>', now)
      .where('expected_revision', '=', license.revision).where('source_generation', '=', license.current_generation).execute();
    const activeApprovals = await Promise.all(matchingApprovals.map(async ({ approval_id }) => {
      const revocation = await trx.selectFrom('license_transfer_revocations').select('approval_id')
        .where('approval_id', '=', approval_id).executeTakeFirst();
      return revocation ? null : approval_id;
    }));
    const unrevokedApprovals = activeApprovals.filter((id): id is string => id !== null);
    if (unrevokedApprovals.length !== 1 || unrevokedApprovals[0] !== input.approval_id) {
      const token = await terminalOperationReceipt(trx, signer, auth, {
        kind: 'transfer_prepare', licenseId: input.license_id, databaseId: input.database_id, state: 'rejected',
        outcomeCode: 'TRANSFER_APPROVAL_AMBIGUOUS', responseType: 'operation',
      }, now);
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'TRANSFER_APPROVAL_AMBIGUOUS' };
    }

    const currentPlan = await trx.selectFrom('license_transfer_plans').selectAll()
      .where('license_id', '=', input.license_id).where('state', '=', 'prepared').forUpdate().executeTakeFirst();
    if (currentPlan) {
      if (currentPlan.expires_at.getTime() <= now.getTime()) {
        await expireOrInvalidatePlan(trx, currentPlan, 'expired', transferEventActor(auth.signature.identityJkt), 'ticket_expired', now);
      } else {
        const currentApproval = await trx.selectFrom('license_transfer_approvals').selectAll()
          .where('approval_id', '=', currentPlan.approval_id).executeTakeFirst();
        const currentRevocation = await trx.selectFrom('license_transfer_revocations').select('approval_id')
          .where('approval_id', '=', currentPlan.approval_id).executeTakeFirst();
        const stillCurrent = currentApproval !== undefined && currentApproval.expires_at.getTime() > now.getTime() &&
          currentRevocation === undefined &&
          currentPlan.expected_revision.toString() === license.revision.toString() &&
          currentPlan.source_generation.toString() === license.current_generation.toString() &&
          license.status === 'active' && license.confirmed_subscription_end.getTime() > now.getTime();
        if (stillCurrent) {
          const token = await terminalOperationReceipt(trx, signer, auth, {
            kind: 'transfer_prepare', licenseId: input.license_id, databaseId: input.database_id, state: 'rejected',
            outcomeCode: 'TRANSFER_PLAN_ALREADY_PREPARED', responseType: 'operation',
          }, now);
          return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'TRANSFER_PLAN_ALREADY_PREPARED' };
        }
        await expireOrInvalidatePlan(trx, currentPlan, 'invalidated', transferEventActor(auth.signature.identityJkt), 'approval_or_license_revision_changed', now);
      }
    }

    const planId = randomUUID();
    const expiresAt = new Date((Math.floor(now.getTime() / 1000) + 10 * 60) * 1000);
    const ticket = await signTransferTicket(signer, {
      plan_id: planId,
      approval_operation_id: approval.approval_id,
      prepare_operation_id: input.operation_id,
      prepare_intent_digest: input.intent_digest,
      prepare_request_nonce: auth.challenge.serverNonce,
      prepare_request_digest: auth.requestDigest,
      license_id: input.license_id,
      database_id: input.database_id,
      source_instance_id: input.instance_id,
      source_identity_jkt: auth.signature.identityJkt,
      source_activation_generation: input.source_generation,
      target_instance_id: input.target_instance_id,
      target_identity_jkt: targetIdentity.jkt,
      expected_binding_revision: input.expected_binding_revision,
      expected_revision: input.expected_revision,
      entitlement_revision: license.entitlement_revision.toString(),
      now,
    });
    const ticketDigest = sha256Base64url(ticket);
    await insertOperation(trx, {
      operationId: input.operation_id, identityJkt: auth.signature.identityJkt, intentDigest: input.intent_digest,
      kind: 'transfer_prepare', licenseId: input.license_id, databaseId: input.database_id,
      state: 'committed', outcomeCode: 'TRANSFER_PREPARED', responseType: 'operation',
      resultGeneration: input.source_generation, resultRevision: license.entitlement_revision.toString(), responseJws: ticket, now,
    });
    await trx.insertInto('license_transfer_plans').values({
      plan_id: planId, license_id: input.license_id, approval_id: approval.approval_id,
      prepare_operation_id: input.operation_id, prepare_intent_digest: input.intent_digest,
      source_activation_id: source.id, database_id: input.database_id, source_instance_id: input.instance_id,
      source_identity_jkt: auth.signature.identityJkt, target_instance_id: input.target_instance_id,
      target_identity_jkt: targetIdentity.jkt, target_identity_jwk_public: targetIdentity.jwk as unknown as Record<string, unknown>,
      source_generation: input.source_generation, expected_binding_revision: input.expected_binding_revision,
      expected_revision: input.expected_revision, entitlement_revision: license.entitlement_revision.toString(),
      ticket_jws: ticket, ticket_digest: ticketDigest, state: 'prepared', expires_at: expiresAt, created_at: now,
      committed_at: null, commit_operation_id: null, committed_generation: null, transfer_receipt_jws: null,
    }).execute();
    await appendAttempt(trx, auth, {
      operationId: input.operation_id, attemptNo: input.attempt_no, intentDigest: input.intent_digest,
      outcome: 'accepted', serverNonceHash: auth.challenge.nonceHash,
    }, now);
    await appendAudit(trx, input.license_id, input.operation_id, 'transfer_prepared', auth.signature.identityJkt,
      { approval_id: input.approval_id, plan_id: planId, source_generation: input.source_generation, target_identity_jkt: targetIdentity.jkt }, now);
    await appendTransferEvent(trx, {
      licenseId: input.license_id, approvalId: input.approval_id, prepareOperationId: input.operation_id,
      planId, kind: 'prepared', actor: transferEventActor(auth.signature.identityJkt),
      details: { source_generation: input.source_generation, target_identity_jkt: targetIdentity.jkt, ticket_digest: ticketDigest }, now,
    });
    return { kind: 'response', responseType: 'operation', token: ticket, state: 'committed', outcomeCode: 'TRANSFER_PREPARED' };
  });
}

function ticketString(claims: Record<string, unknown>, name: string): string {
  const value = claims[name];
  if (typeof value !== 'string') throw new LicenseApiError(401, 'TRANSFER_TICKET_INVALID');
  return value;
}

export async function processTransferCommit(
  db: Kysely<Database>, config: RuntimeConfig, auth: AuthenticatedRequest, input: TransferCommitInput,
  controlledNow?: () => Promise<Date>,
): Promise<MutationResult> {
  bindAttemptNumber(auth, input.attempt_no);
  const targetIdentity = await validateIdentityJwk(input.public_jwk);
  if (input.operation_id === input.approval_id) {
    throw new LicenseApiError(409, 'TRANSFER_OPERATION_ID_REUSE');
  }
  if (input.identity_jkt !== auth.signature.identityJkt || targetIdentity.jkt !== auth.signature.identityJkt) {
    throw new LicenseApiError(401, 'TRANSFER_TICKET_BINDING_INVALID');
  }
  return db.transaction().execute(async (trx) => {
    const signingAuthority = await lockSigningAuthorityForSigning(trx, config);
    const signer = signingAuthority.signer;
    await assertChallengeCurrent(signer, auth, signingAuthority.now);
    let ticket: Awaited<ReturnType<typeof verifyTransferTicket>>;
    try {
      ticket = await verifyTransferTicket(input.transfer_ticket, {
        issuer: signer.issuer, resolver: signer.resolver, trustedTime: Math.floor(signingAuthority.now.getTime() / 1000),
      }, signingAuthority.now);
    } catch {
      throw new LicenseApiError(401, 'TRANSFER_TICKET_INVALID');
    }
    const claims = ticket.claims;
    if (input.operation_id === input.prepare_operation_id ||
      ticketString(claims, 'license_id') !== input.license_id || ticketString(claims, 'database_id') !== input.database_id ||
      ticketString(claims, 'target_instance_id') !== input.instance_id || ticketString(claims, 'target_identity_jkt') !== auth.signature.identityJkt ||
      ticketString(claims, 'approval_operation_id') !== input.approval_id ||
      ticketString(claims, 'prepare_operation_id') !== input.prepare_operation_id) {
      throw new LicenseApiError(401, 'TRANSFER_TICKET_BINDING_INVALID');
    }
    await acquireOperationLock(trx, input.operation_id);
    const license = await lockLicense(trx, input.license_id);
    const existing = await findOperation(trx, input.operation_id);
    if (existing) {
      assertSameOperation(existing, auth, 'transfer_commit', input.license_id, input.database_id);
      const now = controlledNow ? await controlledNow() : await databaseNow(trx);
      return replayExistingOperation(trx, config, auth, existing, now);
    }
    await acquireInstanceLock(trx, input.instance_id);
    const planId = ticketString(claims, 'plan_id');
    const plan = await trx.selectFrom('license_transfer_plans').selectAll().where('plan_id', '=', planId).forUpdate().executeTakeFirst();
    const now = controlledNow ? await controlledNow() : await databaseNow(trx);
    const nonce = await loadAndConsumeNonce(trx, auth, now);
    if (!nonce.valid) return recordRetryable(trx, auth, input.operation_id, input.intent_digest, 'CHALLENGE_EXPIRED_OR_REPLAYED', nonce.row, now);

    const reject = async (code: string): Promise<MutationResult> => {
      const token = await terminalOperationReceipt(trx, signer, auth, {
        kind: 'transfer_commit', licenseId: input.license_id, databaseId: input.database_id,
        state: 'rejected', outcomeCode: code, responseType: 'operation',
      }, now);
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: code };
    };
    if (!plan || plan.prepare_operation_id !== input.prepare_operation_id || plan.approval_id !== input.approval_id ||
      plan.license_id !== input.license_id || plan.ticket_jws !== input.transfer_ticket ||
      plan.ticket_digest !== sha256Base64url(input.transfer_ticket) || plan.database_id !== input.database_id ||
      plan.source_instance_id !== ticketString(claims, 'source_instance_id') || plan.source_identity_jkt !== ticketString(claims, 'source_identity_jkt') ||
      plan.source_generation.toString() !== ticketString(claims, 'source_activation_generation') ||
      plan.target_instance_id !== input.instance_id || plan.target_identity_jkt !== auth.signature.identityJkt ||
      plan.expected_binding_revision.toString() !== ticketString(claims, 'expected_binding_revision') ||
      plan.expected_revision.toString() !== ticketString(claims, 'expected_revision') ||
      plan.entitlement_revision.toString() !== ticketString(claims, 'entitlement_revision') ||
      plan.prepare_intent_digest !== ticketString(claims, 'prepare_intent_digest') ||
      Math.floor(plan.expires_at.getTime() / 1000) !== Number(claims['exp']) ||
      Math.floor(plan.created_at.getTime() / 1000) !== Number(claims['iat']) ||
      plan.target_identity_jwk_public['kty'] !== auth.signature.identityJwk.kty ||
      plan.target_identity_jwk_public['crv'] !== auth.signature.identityJwk.crv ||
      plan.target_identity_jwk_public['x'] !== auth.signature.identityJwk.x) return reject('TRANSFER_TICKET_INVALID');
    const prepareOperation = await trx.selectFrom('license_operations').selectAll()
      .where('operation_id', '=', plan.prepare_operation_id).executeTakeFirst();
    const prepareAttempt = await trx.selectFrom('license_operation_attempts').selectAll()
      .where('operation_id', '=', plan.prepare_operation_id)
      .where('server_nonce_hash', '=', sha256(ticketString(claims, 'prepare_request_nonce')))
      .executeTakeFirst();
    if (!prepareOperation || prepareOperation.kind !== 'transfer_prepare' || prepareOperation.state !== 'committed' ||
      prepareOperation.actor_jkt !== plan.source_identity_jkt || prepareOperation.intent_digest !== plan.prepare_intent_digest ||
      prepareOperation.response_jws !== plan.ticket_jws || !prepareAttempt || prepareAttempt.outcome !== 'accepted' ||
      prepareAttempt.identity_jkt !== plan.source_identity_jkt || prepareAttempt.body_digest !== ticketString(claims, 'prepare_request_digest') ||
      prepareAttempt.intent_digest !== plan.prepare_intent_digest) return reject('TRANSFER_TICKET_INVALID');
    if (plan.state !== 'prepared') return reject(plan.state === 'expired' ? 'TRANSFER_TICKET_EXPIRED' : 'TRANSFER_TICKET_CONSUMED');
    if (ticket.expired || plan.expires_at.getTime() <= now.getTime()) {
      await expireOrInvalidatePlan(trx, plan, 'expired', transferEventActor(auth.signature.identityJkt), 'ticket_expired', now);
      return reject('TRANSFER_TICKET_EXPIRED');
    }
    const approval = await trx.selectFrom('license_transfer_approvals').selectAll().where('approval_id', '=', plan.approval_id).executeTakeFirst();
    const approvalRevoked = await trx.selectFrom('license_transfer_revocations').select('approval_id').where('approval_id', '=', plan.approval_id).executeTakeFirst();
    const targetWasUsed = await trx.selectFrom('license_activations').select('id')
      .where('license_id', '=', plan.license_id).where('identity_jkt', '=', plan.target_identity_jkt).executeTakeFirst();
    const adminApproval = await trx.selectFrom('license_admin_operations').selectAll()
      .where('operation_id', '=', plan.approval_id).executeTakeFirst();
    const source = await trx.selectFrom('license_activations').selectAll().where('id', '=', plan.source_activation_id).forUpdate().executeTakeFirst();
    if (!approval || approvalRevoked || targetWasUsed || !adminApproval || adminApproval.action !== 'transfer_approve' || adminApproval.state !== 'succeeded' ||
      adminApproval.request_digest !== approval.request_digest || approval.expires_at.getTime() <= now.getTime() ||
      approval.expected_revision.toString() !== plan.expected_revision.toString() ||
      approval.source_generation.toString() !== plan.source_generation.toString() || approval.database_id !== plan.database_id ||
      approval.source_instance_id !== plan.source_instance_id || approval.source_identity_jkt !== plan.source_identity_jkt ||
      approval.target_instance_id !== plan.target_instance_id || approval.target_identity_jkt !== plan.target_identity_jkt ||
      approval.expected_binding_revision.toString() !== plan.expected_binding_revision.toString() ||
      license.status !== 'active' || license.confirmed_subscription_end.getTime() <= now.getTime() ||
      license.revision.toString() !== plan.expected_revision.toString() ||
      license.current_generation.toString() !== plan.source_generation.toString() ||
      license.entitlement_revision.toString() !== plan.entitlement_revision.toString() ||
      !source || source.id !== plan.source_activation_id || source.state !== 'active' ||
      source.license_id !== plan.license_id || source.database_id !== plan.database_id ||
      source.instance_id !== plan.source_instance_id || source.identity_jkt !== plan.source_identity_jkt ||
      source.generation.toString() !== plan.source_generation.toString()) {
      await expireOrInvalidatePlan(trx, plan, 'invalidated', transferEventActor(auth.signature.identityJkt), 'approval_or_source_no_longer_current', now);
      const code = approvalRevoked ? 'TRANSFER_APPROVAL_REVOKED' : !approval || !adminApproval ? 'TRANSFER_APPROVAL_INVALID'
        : approval.expires_at.getTime() <= now.getTime() ? 'TRANSFER_APPROVAL_EXPIRED'
          : license.status !== 'active' ? 'LICENSE_REVOKED' : license.confirmed_subscription_end.getTime() <= now.getTime()
            ? 'SUBSCRIPTION_EXPIRED' : license.revision.toString() !== plan.expected_revision.toString()
              ? 'TRANSFER_REVISION_CONFLICT' : 'TRANSFER_SOURCE_SUPERSEDED';
      return reject(code);
    }
    const databaseInteger = BigInt(license.current_generation) + 1n;
    const nextRevision = BigInt(license.revision) + 1n;
    if (databaseInteger > MAX_DATABASE_INTEGER || nextRevision > MAX_DATABASE_INTEGER) throw new LicenseApiError(409, 'TRANSFER_REVISION_EXHAUSTED');
    const nextGeneration = databaseInteger.toString();
    const nextManagementRevision = nextRevision.toString();
    const retired = await trx.updateTable('license_activations').set({ state: 'retired', retired_at: now })
      .where('id', '=', source.id).where('state', '=', 'active').where('generation', '=', plan.source_generation)
      .returning('id').executeTakeFirst();
    if (!retired) throw new LicenseApiError(409, 'TRANSFER_SOURCE_SUPERSEDED');
    const lease = await signLicenseLease(signer, {
      licenseId: input.license_id,
      instanceId: input.instance_id,
      databaseId: input.database_id,
      identityJkt: auth.signature.identityJkt,
      generation: nextGeneration,
      entitlementRevision: license.entitlement_revision.toString(),
      plan: license.plan,
      subscriptionEnd: license.confirmed_subscription_end,
      requestNonce: auth.challenge.serverNonce,
      requestDigest: auth.requestDigest,
      now,
    });
    const transferReceipt = await signTransferReceipt(signer, {
      licenseId: input.license_id,
      databaseId: input.database_id,
      sourceInstanceId: plan.source_instance_id,
      sourceIdentityJkt: plan.source_identity_jkt,
      sourceGeneration: plan.source_generation.toString(),
      targetInstanceId: input.instance_id,
      targetIdentityJkt: auth.signature.identityJkt,
      targetGeneration: nextGeneration,
      expectedBindingRevision: plan.expected_binding_revision.toString(),
      expectedRevision: plan.expected_revision.toString(),
      resultRevision: nextManagementRevision,
      entitlementRevision: license.entitlement_revision.toString(),
      operationId: input.operation_id,
      intentDigest: input.intent_digest,
      requestNonce: auth.challenge.serverNonce,
      requestDigest: auth.requestDigest,
      newLease: lease.token,
      subscriptionEnd: license.confirmed_subscription_end,
      now,
    });
    await trx.insertInto('license_activations').values({
      id: randomUUID(), license_id: input.license_id, generation: nextGeneration,
      instance_id: input.instance_id, database_id: input.database_id,
      identity_jwk_public: auth.signature.identityJwk as unknown as Record<string, unknown>,
      identity_jkt: auth.signature.identityJkt, state: 'active', activated_at: now, retired_at: null,
      last_seen_at: now, origin_display: source.origin_display,
    }).execute();
    const changedLicense = await trx.updateTable('licenses').set({ current_generation: nextGeneration, revision: nextManagementRevision, updated_at: now })
      .where('id', '=', input.license_id).where('current_generation', '=', plan.source_generation)
      .where('revision', '=', plan.expected_revision).executeTakeFirst();
    if (BigInt(changedLicense.numUpdatedRows) !== 1n) throw new LicenseApiError(409, 'TRANSFER_REVISION_CONFLICT');
    await insertOperation(trx, {
      operationId: input.operation_id, identityJkt: auth.signature.identityJkt, intentDigest: input.intent_digest,
      kind: 'transfer_commit', licenseId: input.license_id, databaseId: input.database_id,
      state: 'committed', outcomeCode: 'TRANSFER_COMMITTED', responseType: 'operation',
      resultGeneration: nextGeneration, resultRevision: license.entitlement_revision.toString(),
      responseJws: transferReceipt, now,
    });
    await trx.updateTable('license_transfer_plans').set({
      state: 'committed', committed_at: now, commit_operation_id: input.operation_id,
      committed_generation: nextGeneration, transfer_receipt_jws: transferReceipt,
    }).where('plan_id', '=', plan.plan_id).where('state', '=', 'prepared').execute();
    await appendAttempt(trx, auth, {
      operationId: input.operation_id, attemptNo: input.attempt_no, intentDigest: input.intent_digest,
      outcome: 'accepted', serverNonceHash: auth.challenge.nonceHash,
    }, now);
    await appendAudit(trx, input.license_id, input.operation_id, 'transfer_committed', auth.signature.identityJkt,
      { approval_id: input.approval_id, plan_id: plan.plan_id, old_generation: plan.source_generation.toString(),
        new_generation: nextGeneration, entitlement_revision: license.entitlement_revision.toString(), revision: nextManagementRevision }, now);
    await appendTransferEvent(trx, {
      licenseId: input.license_id, approvalId: input.approval_id, prepareOperationId: plan.prepare_operation_id,
      commitOperationId: input.operation_id, planId: plan.plan_id, kind: 'committed',
      actor: transferEventActor(auth.signature.identityJkt),
      details: { old_generation: plan.source_generation.toString(), new_generation: nextGeneration,
        result_revision: nextManagementRevision, entitlement_revision: license.entitlement_revision.toString() }, now,
    });
    return { kind: 'response', responseType: 'operation', token: transferReceipt, state: 'committed', outcomeCode: 'TRANSFER_COMMITTED' };
  });
}

function disasterEventActor(identityJkt: string): string {
  return `disaster_target_jkt:${identityJkt}`;
}

async function appendDisasterEvent(trx: TransactionDatabase, input: {
  licenseId: string;
  requestId: string;
  approvalId: string;
  prepareOperationId?: string | null;
  commitOperationId?: string | null;
  planId?: string | null;
  kind: 'requested' | 'approved' | 'approval_revoked' | 'prepared' | 'expired' | 'invalidated' | 'committed' | 'rejected';
  actor: string;
  details: Record<string, unknown>;
  now: Date;
}): Promise<void> {
  await trx.insertInto('license_disaster_transfer_events').values({
    event_id: randomUUID(), license_id: input.licenseId, request_id: input.requestId, approval_id: input.approvalId,
    prepare_operation_id: input.prepareOperationId ?? null, commit_operation_id: input.commitOperationId ?? null,
    plan_id: input.planId ?? null, kind: input.kind, actor: input.actor, safe_details: input.details, created_at: input.now,
  }).execute();
}

async function expireOrInvalidateDisasterPlan(
  trx: TransactionDatabase,
  plan: LicenseDisasterTransferPlanRow,
  state: 'expired' | 'invalidated',
  actor: string,
  reason: string,
  now: Date,
): Promise<void> {
  const updated = await trx.updateTable('license_disaster_transfer_plans').set({ state })
    .where('plan_id', '=', plan.plan_id).where('state', '=', 'prepared').returning('plan_id').executeTakeFirst();
  if (!updated) return;
  await appendDisasterEvent(trx, {
    licenseId: plan.license_id, requestId: plan.request_id, approvalId: plan.approval_id,
    prepareOperationId: plan.prepare_operation_id, planId: plan.plan_id, kind: state,
    actor, details: { reason, ticket_digest: plan.ticket_digest }, now,
  });
}

async function hasNormalTransferConflict(trx: TransactionDatabase, license: LicenseRow, now: Date): Promise<boolean> {
  const result = await sql<{ present: boolean }>`
    SELECT EXISTS (
      SELECT 1 FROM license_transfer_approvals a
      LEFT JOIN license_transfer_revocations r ON r.approval_id = a.approval_id
      WHERE a.license_id = ${license.id} AND a.expected_revision = ${license.revision}
        AND a.source_generation = ${license.current_generation} AND a.expires_at > ${now} AND r.approval_id IS NULL
    ) OR EXISTS (
      SELECT 1 FROM license_transfer_plans p WHERE p.license_id = ${license.id} AND p.state = 'prepared'
    ) AS present
  `.execute(trx);
  return result.rows[0]?.present === true;
}

function disasterTicketString(claims: Record<string, unknown>, name: string): string {
  const value = claims[name];
  if (typeof value !== 'string') throw new LicenseApiError(401, 'DISASTER_TICKET_INVALID');
  return value;
}

function disasterApprovalMatches(
  approval: LicenseDisasterTransferApprovalRow,
  request: DisasterTransferPrepareInput,
  license: LicenseRow,
  source: ActivationRow | undefined,
  now: Date,
): boolean {
  return approval.approval_id === request.approval_id && approval.request_id === request.request_id &&
    approval.license_id === request.license_id && approval.account_reference === request.account_reference &&
    approval.source_activation_id === request.source_activation_id && approval.database_id === request.database_id &&
    approval.source_instance_id === request.source_instance_id && approval.source_identity_jkt === request.source_identity_jkt &&
    approval.target_instance_id === request.target_instance_id && approval.target_identity_jkt === request.target_identity_jkt &&
    approval.source_generation.toString() === request.source_generation &&
    approval.expected_binding_revision.toString() === request.expected_binding_revision &&
    approval.expected_revision.toString() === request.expected_revision &&
    approval.entitlement_revision.toString() === license.entitlement_revision.toString() &&
    license.account_id === approval.account_reference && license.revision.toString() === request.expected_revision &&
    license.current_generation.toString() === request.source_generation && approval.expires_at.getTime() > now.getTime() &&
    source !== undefined && source.id === approval.source_activation_id && source.license_id === approval.license_id &&
    source.state === 'active' && source.database_id === approval.database_id && source.instance_id === approval.source_instance_id &&
    source.identity_jkt === approval.source_identity_jkt && source.generation.toString() === approval.source_generation.toString();
}

export async function processDisasterTransferPrepare(
  db: Kysely<Database>, config: RuntimeConfig, auth: AuthenticatedRequest, input: DisasterTransferPrepareInput,
): Promise<MutationResult> {
  bindAttemptNumber(auth, input.attempt_no);
  const target = await validateIdentityJwk(input.public_jwk);
  if (input.identity_jkt !== auth.signature.identityJkt || target.jkt !== auth.signature.identityJkt ||
    input.target_identity_jkt !== target.jkt || input.target_instance_id !== input.instance_id ||
    input.operation_id === input.approval_id || input.operation_id === input.request_id) {
    throw new LicenseApiError(409, 'DISASTER_TARGET_BINDING_INVALID');
  }
  return db.transaction().execute(async (trx) => {
    const signingAuthority = await lockSigningAuthorityForSigning(trx, config);
    const signer = signingAuthority.signer;
    await assertChallengeCurrent(signer, auth, signingAuthority.now);
    await acquireOperationLock(trx, input.operation_id);
    const license = await lockLicense(trx, input.license_id);
    const existing = await findOperation(trx, input.operation_id);
    if (existing) {
      assertSameOperation(existing, auth, 'disaster_transfer_prepare', input.license_id, input.database_id);
      return replayExistingOperation(trx, config, auth, existing, await databaseNow(trx));
    }
    await acquireInstanceLock(trx, input.instance_id);
    const now = await databaseNow(trx);
    const approval = await trx.selectFrom('license_disaster_transfer_approvals').selectAll()
      .where('approval_id', '=', input.approval_id).forUpdate().executeTakeFirst();
    const recoveryRequest = await trx.selectFrom('license_disaster_recovery_requests').selectAll()
      .where('request_id', '=', input.request_id).executeTakeFirst();
    const adminApproval = await trx.selectFrom('license_admin_operations').selectAll()
      .where('operation_id', '=', input.approval_id).executeTakeFirst();
    const revoked = await trx.selectFrom('license_disaster_transfer_revocations').select('approval_id')
      .where('approval_id', '=', input.approval_id).executeTakeFirst();
    const source = await trx.selectFrom('license_activations').selectAll()
      .where('id', '=', input.source_activation_id).where('license_id', '=', input.license_id).forUpdate().executeTakeFirst();
    const targetWasUsed = await trx.selectFrom('license_activations').select('id')
      .where('license_id', '=', input.license_id).where('identity_jkt', '=', target.jkt).executeTakeFirst();
    const approvalValid = approval !== undefined && !revoked && adminApproval?.action === 'disaster_transfer_approve' &&
      adminApproval.state === 'succeeded' && adminApproval.request_digest === approval.request_digest &&
      recoveryRequest?.request_digest === approval.request_digest && recoveryRequest.request_id === approval.request_id &&
      recoveryRequest.license_id === approval.license_id && recoveryRequest.source_activation_id === approval.source_activation_id &&
      recoveryRequest.account_reference === approval.account_reference && recoveryRequest.target_identity_jkt === approval.target_identity_jkt &&
      disasterApprovalMatches(approval, input, license, source, now);
    const reject = async (code: string): Promise<MutationResult> => {
      const token = await terminalOperationReceipt(trx, signer, auth, {
        kind: 'disaster_transfer_prepare', licenseId: input.license_id, databaseId: input.database_id,
        state: 'rejected', outcomeCode: code, responseType: 'operation',
      }, now);
      if (approval && recoveryRequest) await appendDisasterEvent(trx, {
        licenseId: input.license_id, requestId: approval.request_id, approvalId: approval.approval_id,
        prepareOperationId: input.operation_id, kind: 'rejected', actor: disasterEventActor(target.jkt),
        details: { outcome_code: code }, now,
      });
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: code };
    };
    if (!approvalValid) throw new LicenseApiError(403, 'DISASTER_PREPARE_FORBIDDEN');
    const nonce = await loadAndConsumeNonce(trx, auth, now);
    if (!nonce.valid) return recordRetryable(trx, auth, input.operation_id, input.intent_digest, 'CHALLENGE_EXPIRED_OR_REPLAYED', nonce.row, now);
    if (license.revision.toString() !== approval.expected_revision.toString() ||
      license.current_generation.toString() !== approval.source_generation.toString() ||
      license.entitlement_revision.toString() !== approval.entitlement_revision.toString()) return reject('DISASTER_REVISION_CONFLICT');
    if (targetWasUsed) return reject('DISASTER_TARGET_IDENTITY_WAS_USED');
    if (input.database_id !== approval.database_id || input.account_reference !== license.account_id) return reject('DISASTER_DATABASE_BINDING_MISMATCH');
    if (approval.target_identity_jkt !== target.jkt || approval.target_instance_id !== input.instance_id) return reject('DISASTER_TARGET_IDENTITY_MISMATCH');
    if (await hasNormalTransferConflict(trx, license, now)) return reject('NORMAL_TRANSFER_REQUIRES_EXPLICIT_REVOCATION');
    if (approval.target_instance_mode === 'replace') {
      const activeInstance = await trx.selectFrom('license_activations').select(['license_id', 'id'])
        .where('instance_id', '=', input.instance_id).where('state', '=', 'active').executeTakeFirst();
      if (activeInstance) return reject('DISASTER_TARGET_INSTANCE_ALREADY_ACTIVE');
    }

    const currentPlan = await trx.selectFrom('license_disaster_transfer_plans').selectAll()
      .where('license_id', '=', input.license_id).where('state', '=', 'prepared').forUpdate().executeTakeFirst();
    if (currentPlan) {
      if (currentPlan.expires_at.getTime() <= now.getTime()) {
        await expireOrInvalidateDisasterPlan(trx, currentPlan, 'expired', disasterEventActor(target.jkt), 'ticket_expired', now);
      } else {
        return reject('DISASTER_TRANSFER_PLAN_ALREADY_PREPARED');
      }
    }
    const approvalCount = await sql<{ count: string }>`
      SELECT count(*)::text AS count FROM license_disaster_transfer_approvals a
      LEFT JOIN license_disaster_transfer_revocations r ON r.approval_id = a.approval_id
      WHERE a.license_id = ${input.license_id} AND a.expected_revision = ${license.revision}
        AND a.source_generation = ${license.current_generation} AND a.expires_at > ${now} AND r.approval_id IS NULL
    `.execute(trx);
    if (approvalCount.rows[0]?.count !== '1') return reject('DISASTER_APPROVAL_AMBIGUOUS');

    const planId = randomUUID();
    const expiresAt = new Date((Math.floor(now.getTime() / 1000) + 10 * 60) * 1000);
    const ticket = await signDisasterTransferTicket(signer, {
      plan_id: planId,
      request_id: approval.request_id,
      approval_id: approval.approval_id,
      approval_request_digest: approval.request_digest,
      prepare_operation_id: input.operation_id,
      prepare_intent_digest: input.intent_digest,
      prepare_request_nonce: auth.challenge.serverNonce,
      prepare_request_digest: auth.requestDigest,
      license_id: input.license_id,
      account_reference: approval.account_reference,
      database_id: approval.database_id,
      source_activation_id: approval.source_activation_id,
      source_instance_id: approval.source_instance_id,
      source_identity_jkt: approval.source_identity_jkt,
      source_activation_generation: approval.source_generation.toString(),
      target_instance_id: approval.target_instance_id,
      target_identity_jkt: target.jkt,
      expected_binding_revision: approval.expected_binding_revision.toString(),
      expected_revision: approval.expected_revision.toString(),
      entitlement_revision: approval.entitlement_revision.toString(),
      now,
    });
    const ticketDigest = sha256Base64url(ticket);
    await insertOperation(trx, {
      operationId: input.operation_id, identityJkt: target.jkt, intentDigest: input.intent_digest,
      kind: 'disaster_transfer_prepare', licenseId: input.license_id, databaseId: input.database_id,
      state: 'committed', outcomeCode: 'DISASTER_TRANSFER_PREPARED', responseType: 'disaster_ticket',
      resultGeneration: approval.source_generation.toString(), resultRevision: approval.entitlement_revision.toString(),
      responseJws: ticket, now,
    });
    await trx.insertInto('license_disaster_transfer_plans').values({
      plan_id: planId, request_id: approval.request_id, approval_id: approval.approval_id, license_id: input.license_id,
      prepare_operation_id: input.operation_id, prepare_intent_digest: input.intent_digest,
      source_activation_id: approval.source_activation_id, database_id: approval.database_id,
      source_instance_id: approval.source_instance_id, source_identity_jkt: approval.source_identity_jkt,
      target_instance_id: approval.target_instance_id, target_identity_jkt: target.jkt,
      target_identity_jwk_public: target.jwk as unknown as Record<string, unknown>,
      source_generation: approval.source_generation.toString(), expected_binding_revision: approval.expected_binding_revision.toString(),
      expected_revision: approval.expected_revision.toString(), entitlement_revision: approval.entitlement_revision.toString(),
      ticket_jws: ticket, ticket_digest: ticketDigest, state: 'prepared', expires_at: expiresAt, created_at: now,
      committed_at: null, commit_operation_id: null, committed_generation: null, result_mode: null, disaster_result_jws: null,
    }).execute();
    await appendAttempt(trx, auth, { operationId: input.operation_id, attemptNo: input.attempt_no,
      intentDigest: input.intent_digest, outcome: 'accepted', serverNonceHash: auth.challenge.nonceHash }, now);
    await appendAudit(trx, input.license_id, input.operation_id, 'disaster_transfer_prepared', target.jkt,
      { approval_id: approval.approval_id, request_id: approval.request_id, plan_id: planId, ticket_digest: ticketDigest }, now);
    await appendDisasterEvent(trx, { licenseId: input.license_id, requestId: approval.request_id, approvalId: approval.approval_id,
      prepareOperationId: input.operation_id, planId, kind: 'prepared', actor: disasterEventActor(target.jkt),
      details: { source_generation: approval.source_generation.toString(), target_identity_jkt: target.jkt, ticket_digest: ticketDigest }, now });
    return { kind: 'response', responseType: 'disaster_ticket', token: ticket, state: 'committed', outcomeCode: 'DISASTER_TRANSFER_PREPARED' };
  });
}

export async function processDisasterTransferCommit(
  db: Kysely<Database>, config: RuntimeConfig, auth: AuthenticatedRequest, input: DisasterTransferCommitInput,
  controlledNow?: () => Promise<Date>,
): Promise<MutationResult> {
  bindAttemptNumber(auth, input.attempt_no);
  const target = await validateIdentityJwk(input.public_jwk);
  if (input.identity_jkt !== auth.signature.identityJkt || target.jkt !== auth.signature.identityJkt ||
    input.operation_id === input.approval_id) {
    throw new LicenseApiError(401, 'DISASTER_TICKET_BINDING_INVALID');
  }
  return db.transaction().execute(async (trx) => {
    const signingAuthority = await lockSigningAuthorityForSigning(trx, config);
    const signer = signingAuthority.signer;
    await assertChallengeCurrent(signer, auth, signingAuthority.now);
    let verifiedTicket: Awaited<ReturnType<typeof verifyDisasterTransferTicket>>;
    try {
      verifiedTicket = await verifyDisasterTransferTicket(input.disaster_ticket, {
        issuer: signer.issuer, resolver: signer.resolver, trustedTime: Math.floor(signingAuthority.now.getTime() / 1000),
      }, signingAuthority.now);
    } catch { throw new LicenseApiError(401, 'DISASTER_TICKET_INVALID'); }
    const claims = verifiedTicket.claims;
    if (input.operation_id === input.prepare_operation_id ||
      disasterTicketString(claims, 'license_id') !== input.license_id ||
      disasterTicketString(claims, 'database_id') !== input.database_id ||
      disasterTicketString(claims, 'target_instance_id') !== input.instance_id ||
      disasterTicketString(claims, 'target_identity_jkt') !== target.jkt ||
      disasterTicketString(claims, 'approval_id') !== input.approval_id ||
      disasterTicketString(claims, 'prepare_operation_id') !== input.prepare_operation_id) {
      throw new LicenseApiError(401, 'DISASTER_TICKET_BINDING_INVALID');
    }
    await acquireOperationLock(trx, input.operation_id);
    const license = await lockLicense(trx, input.license_id);
    const existing = await findOperation(trx, input.operation_id);
    if (existing) {
      assertSameOperation(existing, auth, 'disaster_transfer_commit', input.license_id, input.database_id);
      return replayExistingOperation(trx, config, auth, existing, controlledNow ? await controlledNow() : await databaseNow(trx));
    }
    await acquireInstanceLock(trx, input.instance_id);
    const plan = await trx.selectFrom('license_disaster_transfer_plans').selectAll()
      .where('plan_id', '=', disasterTicketString(claims, 'plan_id')).forUpdate().executeTakeFirst();
    const now = controlledNow ? await controlledNow() : await databaseNow(trx);
    const nonce = await loadAndConsumeNonce(trx, auth, now);
    if (!nonce.valid) return recordRetryable(trx, auth, input.operation_id, input.intent_digest, 'CHALLENGE_EXPIRED_OR_REPLAYED', nonce.row, now);

    const reject = async (code: string): Promise<MutationResult> => {
      const token = await terminalOperationReceipt(trx, signer, auth, {
        kind: 'disaster_transfer_commit', licenseId: input.license_id, databaseId: input.database_id,
        state: 'rejected', outcomeCode: code, responseType: 'operation',
      }, now);
      if (plan) await appendDisasterEvent(trx, { licenseId: input.license_id, requestId: plan.request_id,
        approvalId: plan.approval_id, prepareOperationId: plan.prepare_operation_id, commitOperationId: input.operation_id,
        planId: plan.plan_id, kind: 'rejected', actor: disasterEventActor(target.jkt), details: { outcome_code: code }, now });
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: code };
    };
    if (!plan || plan.request_id !== disasterTicketString(claims, 'request_id') ||
      plan.approval_id !== input.approval_id || plan.prepare_operation_id !== input.prepare_operation_id ||
      plan.license_id !== input.license_id || plan.ticket_jws !== input.disaster_ticket ||
      plan.ticket_digest !== sha256Base64url(input.disaster_ticket) || plan.database_id !== input.database_id ||
      plan.source_activation_id !== disasterTicketString(claims, 'source_activation_id') ||
      plan.source_instance_id !== disasterTicketString(claims, 'source_instance_id') ||
      plan.source_identity_jkt !== disasterTicketString(claims, 'source_identity_jkt') ||
      plan.source_generation.toString() !== disasterTicketString(claims, 'source_activation_generation') ||
      plan.target_instance_id !== input.instance_id || plan.target_identity_jkt !== target.jkt ||
      plan.expected_binding_revision.toString() !== disasterTicketString(claims, 'expected_binding_revision') ||
      plan.expected_revision.toString() !== disasterTicketString(claims, 'expected_revision') ||
      plan.entitlement_revision.toString() !== disasterTicketString(claims, 'entitlement_revision') ||
      plan.prepare_intent_digest !== disasterTicketString(claims, 'prepare_intent_digest') ||
      disasterTicketString(claims, 'approval_request_digest') !== (await trx.selectFrom('license_disaster_transfer_approvals')
        .select('request_digest').where('approval_id', '=', input.approval_id).executeTakeFirst())?.request_digest ||
      Math.floor(plan.expires_at.getTime() / 1000) !== Number(claims['exp']) ||
      Math.floor(plan.created_at.getTime() / 1000) !== Number(claims['iat']) ||
      plan.target_identity_jwk_public['kty'] !== auth.signature.identityJwk.kty ||
      plan.target_identity_jwk_public['crv'] !== auth.signature.identityJwk.crv ||
      plan.target_identity_jwk_public['x'] !== auth.signature.identityJwk.x) return reject('DISASTER_TICKET_INVALID');

    const prepareOperation = await trx.selectFrom('license_operations').selectAll()
      .where('operation_id', '=', plan.prepare_operation_id).executeTakeFirst();
    const prepareAttempt = await trx.selectFrom('license_operation_attempts').selectAll()
      .where('operation_id', '=', plan.prepare_operation_id)
      .where('server_nonce_hash', '=', sha256(disasterTicketString(claims, 'prepare_request_nonce'))).executeTakeFirst();
    if (!prepareOperation || prepareOperation.kind !== 'disaster_transfer_prepare' || prepareOperation.state !== 'committed' ||
      prepareOperation.actor_jkt !== plan.target_identity_jkt || prepareOperation.intent_digest !== plan.prepare_intent_digest ||
      prepareOperation.response_jws !== plan.ticket_jws || !prepareAttempt || prepareAttempt.outcome !== 'accepted' ||
      prepareAttempt.identity_jkt !== plan.target_identity_jkt || prepareAttempt.body_digest !== disasterTicketString(claims, 'prepare_request_digest') ||
      prepareAttempt.intent_digest !== plan.prepare_intent_digest) return reject('DISASTER_TICKET_INVALID');
    if (plan.state !== 'prepared') return reject(plan.state === 'expired' ? 'DISASTER_TICKET_EXPIRED' : 'DISASTER_TICKET_CONSUMED');
    if (verifiedTicket.expired || plan.expires_at.getTime() <= now.getTime()) {
      await expireOrInvalidateDisasterPlan(trx, plan, 'expired', disasterEventActor(target.jkt), 'ticket_expired', now);
      return reject('DISASTER_TICKET_EXPIRED');
    }
    const approval = await trx.selectFrom('license_disaster_transfer_approvals').selectAll()
      .where('approval_id', '=', plan.approval_id).forUpdate().executeTakeFirst();
    const recoveryRequest = await trx.selectFrom('license_disaster_recovery_requests').selectAll()
      .where('request_id', '=', plan.request_id).executeTakeFirst();
    const approvalRevoked = await trx.selectFrom('license_disaster_transfer_revocations').select('approval_id')
      .where('approval_id', '=', plan.approval_id).executeTakeFirst();
    const adminApproval = await trx.selectFrom('license_admin_operations').selectAll()
      .where('operation_id', '=', plan.approval_id).executeTakeFirst();
    const targetWasUsed = await trx.selectFrom('license_activations').select('id')
      .where('license_id', '=', plan.license_id).where('identity_jkt', '=', plan.target_identity_jkt).executeTakeFirst();
    const source = await trx.selectFrom('license_activations').selectAll()
      .where('id', '=', plan.source_activation_id).forUpdate().executeTakeFirst();
    const approvalCurrent = approval !== undefined && recoveryRequest !== undefined && !approvalRevoked &&
      adminApproval?.action === 'disaster_transfer_approve' && adminApproval.state === 'succeeded' &&
      adminApproval.request_digest === approval.request_digest && recoveryRequest.request_digest === approval.request_digest &&
      approval.request_id === plan.request_id && approval.license_id === plan.license_id &&
      approval.account_reference === license.account_id && approval.database_id === plan.database_id &&
      approval.source_activation_id === plan.source_activation_id && approval.source_instance_id === plan.source_instance_id &&
      approval.source_identity_jkt === plan.source_identity_jkt && approval.target_instance_id === plan.target_instance_id &&
      approval.target_identity_jkt === plan.target_identity_jkt && approval.source_generation.toString() === plan.source_generation.toString() &&
      approval.expected_binding_revision.toString() === plan.expected_binding_revision.toString() &&
      approval.expected_revision.toString() === plan.expected_revision.toString() &&
      approval.entitlement_revision.toString() === plan.entitlement_revision.toString() && approval.expires_at.getTime() > now.getTime();
    if (!approvalCurrent || approvalRevoked) {
      await expireOrInvalidateDisasterPlan(trx, plan, 'invalidated', disasterEventActor(target.jkt), 'approval_revoked_or_invalid', now);
      return reject(approvalRevoked ? 'DISASTER_APPROVAL_REVOKED' : 'DISASTER_APPROVAL_INVALID');
    }
    if (targetWasUsed || license.revision.toString() !== plan.expected_revision.toString() ||
      license.current_generation.toString() !== plan.source_generation.toString() ||
      license.entitlement_revision.toString() !== plan.entitlement_revision.toString() ||
      !source || source.id !== plan.source_activation_id || source.state !== 'active' || source.license_id !== plan.license_id ||
      source.database_id !== plan.database_id || source.instance_id !== plan.source_instance_id ||
      source.identity_jkt !== plan.source_identity_jkt || source.generation.toString() !== plan.source_generation.toString()) {
      await expireOrInvalidateDisasterPlan(trx, plan, 'invalidated', disasterEventActor(target.jkt), 'source_or_revision_changed', now);
      return reject('DISASTER_SOURCE_OR_REVISION_CHANGED');
    }
    const conflictingInstance = await trx.selectFrom('license_activations').select(['license_id', 'id'])
      .where('instance_id', '=', plan.target_instance_id).where('state', '=', 'active').executeTakeFirst();
    if (conflictingInstance && conflictingInstance.id !== plan.source_activation_id) return reject('DISASTER_TARGET_INSTANCE_ALREADY_ACTIVE');
    if (await hasNormalTransferConflict(trx, license, now)) {
      await expireOrInvalidateDisasterPlan(trx, plan, 'invalidated', disasterEventActor(target.jkt), 'normal_transfer_conflict', now);
      return reject('NORMAL_TRANSFER_REQUIRES_EXPLICIT_REVOCATION');
    }

    const nextGenerationValue = BigInt(license.current_generation) + 1n;
    const nextRevisionValue = BigInt(license.revision) + 1n;
    if (nextGenerationValue > MAX_DATABASE_INTEGER || nextRevisionValue > MAX_DATABASE_INTEGER) throw new LicenseApiError(409, 'DISASTER_REVISION_EXHAUSTED');
    const nextGeneration = nextGenerationValue.toString();
    const nextManagementRevision = nextRevisionValue.toString();
    const retired = await trx.updateTable('license_activations').set({ state: 'retired', retired_at: now })
      .where('id', '=', source.id).where('state', '=', 'active').where('generation', '=', plan.source_generation)
      .returning('id').executeTakeFirst();
    if (!retired) throw new LicenseApiError(409, 'DISASTER_SOURCE_SUPERSEDED');

    const endsAtSeconds = Math.floor(license.confirmed_subscription_end.getTime() / 1000);
    const nowSeconds = Math.floor(now.getTime() / 1000);
    const canOperate = license.status === 'active' && license.confirmed_subscription_end.getTime() > now.getTime() && endsAtSeconds > nowSeconds;
    let lease: string | undefined;
    if (canOperate) {
      const signedLease = await signLicenseLease(signer, {
        licenseId: license.id, instanceId: plan.target_instance_id, databaseId: plan.database_id,
        identityJkt: target.jkt, generation: nextGeneration, entitlementRevision: license.entitlement_revision.toString(),
        plan: license.plan, subscriptionEnd: license.confirmed_subscription_end,
        requestNonce: auth.challenge.serverNonce, requestDigest: auth.requestDigest, now,
      });
      lease = signedLease.token;
    }
    const resultMode = canOperate ? 'active_lease' as const : 'binding_only' as const;
    const disasterResult = await signDisasterTransferResult(signer, {
      mode: resultMode,
      licenseId: license.id,
      databaseId: plan.database_id,
      accountReference: license.account_id,
      sourceActivationId: plan.source_activation_id,
      sourceInstanceId: plan.source_instance_id,
      sourceIdentityJkt: plan.source_identity_jkt,
      sourceGeneration: plan.source_generation.toString(),
      targetInstanceId: plan.target_instance_id,
      targetIdentityJkt: target.jkt,
      targetGeneration: nextGeneration,
      expectedBindingRevision: plan.expected_binding_revision.toString(),
      expectedRevision: plan.expected_revision.toString(),
      resultRevision: nextManagementRevision,
      entitlementRevision: license.entitlement_revision.toString(),
      operationId: input.operation_id,
      intentDigest: input.intent_digest,
      requestNonce: auth.challenge.serverNonce,
      requestDigest: auth.requestDigest,
      subscriptionEnd: license.confirmed_subscription_end,
      licenseStatus: license.status,
      ...(lease ? { lease } : {}),
      now,
    });
    await trx.insertInto('license_activations').values({
      id: randomUUID(), license_id: license.id, generation: nextGeneration,
      instance_id: plan.target_instance_id, database_id: plan.database_id,
      identity_jwk_public: target.jwk as unknown as Record<string, unknown>, identity_jkt: target.jkt,
      state: 'active', activated_at: now, retired_at: null, last_seen_at: now, origin_display: source.origin_display,
    }).execute();
    const changedLicense = await trx.updateTable('licenses').set({
      current_generation: nextGeneration, revision: nextManagementRevision, updated_at: now,
    }).where('id', '=', license.id).where('current_generation', '=', plan.source_generation)
      .where('revision', '=', plan.expected_revision).executeTakeFirst();
    if (BigInt(changedLicense.numUpdatedRows) !== 1n) throw new LicenseApiError(409, 'DISASTER_REVISION_CONFLICT');
    const outcomeCode = canOperate ? 'DISASTER_TRANSFER_COMMITTED' :
      license.status === 'revoked' ? 'DISASTER_BINDING_RESTORED_REVOKED' : 'DISASTER_BINDING_RESTORED_EXPIRED';
    const responseType = canOperate ? 'disaster_active' : 'disaster_binding';
    await insertOperation(trx, {
      operationId: input.operation_id, identityJkt: target.jkt, intentDigest: input.intent_digest,
      kind: 'disaster_transfer_commit', licenseId: license.id, databaseId: plan.database_id,
      state: 'committed', outcomeCode, responseType, resultGeneration: nextGeneration,
      resultRevision: license.entitlement_revision.toString(), responseJws: disasterResult, now,
    });
    await trx.updateTable('license_disaster_transfer_plans').set({
      state: 'committed', committed_at: now, commit_operation_id: input.operation_id,
      committed_generation: nextGeneration, result_mode: resultMode, disaster_result_jws: disasterResult,
    }).where('plan_id', '=', plan.plan_id).where('state', '=', 'prepared').execute();
    await appendAttempt(trx, auth, { operationId: input.operation_id, attemptNo: input.attempt_no,
      intentDigest: input.intent_digest, outcome: 'accepted', serverNonceHash: auth.challenge.nonceHash }, now);
    await appendAudit(trx, license.id, input.operation_id, 'disaster_transfer_committed', target.jkt, {
      request_id: plan.request_id, approval_id: plan.approval_id, plan_id: plan.plan_id,
      old_generation: plan.source_generation.toString(), new_generation: nextGeneration,
      result_revision: nextManagementRevision, entitlement_revision: license.entitlement_revision.toString(),
      result_mode: resultMode, license_status: license.status,
    }, now);
    await appendDisasterEvent(trx, { licenseId: license.id, requestId: plan.request_id, approvalId: plan.approval_id,
      prepareOperationId: plan.prepare_operation_id, commitOperationId: input.operation_id, planId: plan.plan_id,
      kind: 'committed', actor: disasterEventActor(target.jkt), details: {
        old_generation: plan.source_generation.toString(), new_generation: nextGeneration,
        result_revision: nextManagementRevision, entitlement_revision: license.entitlement_revision.toString(), result_mode: resultMode,
      }, now });
    return { kind: 'response', responseType, token: disasterResult, state: 'committed', outcomeCode };
  });
}
