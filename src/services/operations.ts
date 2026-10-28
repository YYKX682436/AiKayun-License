import { randomUUID } from 'node:crypto';
import { sql, type Kysely, type Transaction } from 'kysely';
import type { RuntimeConfig } from '../config.js';
import type {
  ActivationCodeRow,
  ActivationRow,
  Database,
  LicenseRow,
  OperationRow,
  RequestNonceRow,
} from '../db/types.js';
import { LicenseApiError } from '../errors.js';
import { sha256Base64url } from '../crypto/identity.js';
import { databaseNow, challengeClaimsMatchRow, type AuthenticatedRequest } from './common.js';
import { signLicenseLease, signOperationReceipt, signStatusReceipt, type OperationState } from '../receipts.js';

export type MutationKind = 'activation' | 'renewal' | 'recovery';
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

export type MutationResponseType = 'license' | 'status' | 'operation';
export type MutationResult =
  | { kind: 'retryable'; code: string }
  | { kind: 'response'; responseType: MutationResponseType; token: string; state: 'committed' | 'rejected' | 'cancelled'; outcomeCode: string };

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
  config: RuntimeConfig,
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
    token = await signStatusReceipt(config, {
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
    token = await signOperationReceipt(config, {
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
  config: RuntimeConfig,
  auth: AuthenticatedRequest,
  license: LicenseRow,
  input: ActivationInput,
  code: ActivationCodeRow,
  now: Date,
): Promise<string> {
  const generation = (big(license.current_generation) + 1n).toString();
  const revision = license.entitlement_revision.toString();
  const lease = await signLicenseLease(config, {
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
    const nonce = await loadAndConsumeNonce(trx, auth, now);
    if (!nonce.valid) return recordRetryable(trx, auth, input.operation_id, input.intent_digest, 'CHALLENGE_EXPIRED_OR_REPLAYED', nonce.row, now);
    if (license.status !== 'active') {
      const token = await terminalOperationReceipt(trx, config, auth, {
        kind: 'activation', licenseId: input.license_id, databaseId: input.database_id, state: 'rejected',
        outcomeCode: 'LICENSE_REVOKED', responseType: 'operation',
      }, now);
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'LICENSE_REVOKED' };
    }
    if (license.confirmed_subscription_end.getTime() <= now.getTime()) {
      const token = await terminalOperationReceipt(trx, config, auth, {
        kind: 'activation', licenseId: input.license_id, databaseId: input.database_id, state: 'rejected',
        outcomeCode: 'SUBSCRIPTION_EXPIRED', responseType: 'operation',
      }, now);
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'SUBSCRIPTION_EXPIRED' };
    }
    if (activeActivation || big(license.current_generation) !== 0n) {
      const token = await terminalOperationReceipt(trx, config, auth, {
        kind: 'activation', licenseId: input.license_id, databaseId: input.database_id, state: 'rejected',
        outcomeCode: 'ACTIVATION_CONFLICT', responseType: 'operation',
      }, now);
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'ACTIVATION_CONFLICT' };
    }
    const codeHash = sha256Base64url(input.activation_code);
    const code = await trx.selectFrom('activation_codes').selectAll()
      .where('token_hash', '=', codeHash).forUpdate().executeTakeFirst();
    if (!code || code.license_id !== input.license_id || code.consumed_at !== null || code.revoked_at !== null || code.expires_at.getTime() <= now.getTime()) {
      const token = await terminalOperationReceipt(trx, config, auth, {
        kind: 'activation', licenseId: input.license_id, databaseId: input.database_id, state: 'rejected',
        outcomeCode: 'ACTIVATION_CODE_INVALID', responseType: 'operation',
      }, now);
      return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'ACTIVATION_CODE_INVALID' };
    }
    const token = await insertSuccessfulActivation(trx, config, auth, license, input, code, now);
    return { kind: 'response', responseType: 'license', token, state: 'committed', outcomeCode: 'ACTIVATED' };
  });
}

async function signedStatus(
  trx: TransactionDatabase,
  config: RuntimeConfig,
  auth: AuthenticatedRequest,
  input: RenewalInput,
  license: LicenseRow,
  activation: ActivationRow,
  state: 'expired' | 'revoked' | 'superseded',
  outcomeCode: string,
  now: Date,
): Promise<MutationResult> {
  const token = await terminalOperationReceipt(trx, config, auth, {
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
      return signedStatus(trx, config, auth, input, license, activation, 'superseded', 'ACTIVATION_SUPERSEDED', now);
    }
    if (license.status === 'revoked') return signedStatus(trx, config, auth, input, license, activation, 'revoked', 'LICENSE_REVOKED', now);
    if (big(input.known_revision) > big(license.entitlement_revision)) throw new LicenseApiError(409, 'REVISION_AHEAD');
    if (license.confirmed_subscription_end.getTime() <= now.getTime()) {
      return signedStatus(trx, config, auth, input, license, activation, 'expired', 'SUBSCRIPTION_EXPIRED', now);
    }
    if (input.recovery_of_operation_id) {
      const sourceValid = sourceOperation?.state === 'committed' && sourceOperation.kind === 'activation' &&
        sourceOperation.license_id === input.license_id && sourceOperation.database_id === input.database_id &&
        sourceOperation.actor_jkt === auth.signature.identityJkt && sourceOperation.result_generation === activation.generation;
      if (!sourceValid) {
        const token = await terminalOperationReceipt(trx, config, auth, {
          kind: operationKind, licenseId: input.license_id, databaseId: input.database_id,
          state: 'rejected', outcomeCode: 'RECOVERY_SOURCE_INVALID', responseType: 'operation',
        }, now);
        return { kind: 'response', responseType: 'operation', token, state: 'rejected', outcomeCode: 'RECOVERY_SOURCE_INVALID' };
      }
    }
    const lease = await signLicenseLease(config, {
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

export async function queryOperation(
  db: Kysely<Database>,
  config: RuntimeConfig,
  auth: AuthenticatedRequest,
  input: OperationQueryInput,
): Promise<string | { retryable: string }> {
  bindAttemptNumber(auth, input.attempt_no);
  return db.transaction().execute(async (trx) => {
    await acquireOperationLock(trx, input.operation_id);
    const license = await lockLicense(trx, input.license_id);
    const existing = await findOperation(trx, input.operation_id);
    if (existing && existing.actor_jkt !== auth.signature.identityJkt) throw new LicenseApiError(403, 'OPERATION_ACTOR_MISMATCH');
    if (existing && (existing.intent_digest !== input.intent_digest || existing.license_id !== input.license_id || existing.database_id !== input.database_id)) {
      throw new LicenseApiError(409, 'OPERATION_INTENT_CONFLICT');
    }
    const activation = await lockActorActivation(trx, input.license_id, auth.signature.identityJkt, input.instance_id);
    if (activation && activation.database_id !== input.database_id) throw new LicenseApiError(409, 'DATABASE_BINDING_MISMATCH');
    const now = await databaseNow(trx);
    const nonce = await loadAndConsumeNonce(trx, auth, now);
    const result = async (state: OperationState, outcomeCode: string | null, resultJws: string | null,
      attempt: { attemptNo: number; nonceHash: string; requestDigest: string } | undefined) => signOperationReceipt(config, {
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
  const source = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', input.operation_id).executeTakeFirst();
  if (!source) throw new LicenseApiError(503, 'OPERATION_STATE_UNKNOWN');
  const attempt = await db.selectFrom('license_operation_attempts').selectAll()
    .where('operation_id', '=', source.operation_id).where('outcome', 'in', ['accepted', 'terminal_reject'])
    .orderBy('attempt_no', 'asc').executeTakeFirst();
  const now = await databaseNow(db);
  return signOperationReceipt(config, {
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
}
