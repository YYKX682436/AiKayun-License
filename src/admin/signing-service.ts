import { createHash, randomUUID, webcrypto } from 'node:crypto';
import canonicalize from 'canonicalize';
import { sql, type Transaction } from 'kysely';
import type { SignerRuntimeConfig } from '../config.js';
import type { Database, LicenseSignerAuthorityRow, LicenseSignerOperationRow } from '../db/types.js';
import { parseStrictJsonSegment } from '../strict-json.js';
import {
  assertTrustBundleValidAt, compareBundleVersions, getRootAuthenticatedCandidateKey,
  trustBundleArtifactDigest, verifyTrustBundleSignature,
} from '../trust/trust-bundle.js';
import type { RootAuthenticatedTrustBundleCandidate } from '../trust/trust-bundle.js';
import { validateTrustBundleTransition } from '../trust/trust-bundle-store.js';
import { lockSigningAuthorityForUpdate } from '../crypto/signing-authority.js';
import { assertCenterTimeSourceHealthy } from '../services/common.js';
import { AdminAccessError, type AdminSession } from './policy.js';
import { AdminOperationError } from './service.js';

type AdminTransaction = Transaction<Database>;
type SignerAction = LicenseSignerOperationRow['action'];
const rolloutGate = 'isolated-development-confirmed' as const;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const revisionPattern = /^(0|[1-9][0-9]{0,18})$/;

export interface SignerOperationResult {
  operationId: string;
  requestDigest: string;
  action: SignerAction;
  state: 'succeeded' | 'rejected';
  outcomeCode: string;
  expectedSignerRevision: string;
  signerRevision: string;
  activeSigningKid: string | null;
  bundleVersion: string | null;
  artifactSha256: string | null;
  result: Record<string, unknown>;
  replayed: boolean;
}

interface SignerAdminBase {
  operationId: string;
  expectedSignerRevision: string;
  reason: string;
  rolloutGate: typeof rolloutGate;
  confirmedRequestDigest: string;
}

export interface InitializeSignerRequest extends SignerAdminBase {
  activeKid: string;
  bundleJws: string;
}

export interface AcceptSignerTrustBundleRequest extends SignerAdminBase {
  bundleJws: string;
}

export interface RotateSignerRequest extends SignerAdminBase {
  targetKid: string;
  bundleVersion: string;
  artifactSha256: string;
}

export interface SignerAdminService {
  getState(): Promise<{ activeKid: string | null; signerRevision: string; bundleVersion: string | null; artifactSha256: string | null; previousKid: string | null }>;
  initialize(input: InitializeSignerRequest): Promise<SignerOperationResult>;
  acceptTrustBundle(input: AcceptSignerTrustBundleRequest): Promise<SignerOperationResult>;
  rotate(input: RotateSignerRequest): Promise<SignerOperationResult>;
}

function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('base64url');
}

function digest(action: SignerAction, value: Record<string, unknown>): string {
  const canonical = canonicalize({ action, ...value });
  if (!canonical) throw new AdminOperationError('SIGNER_REQUEST_DIGEST_FAILED');
  return sha256(canonical);
}

export function initializeSignerRequestDigest(input: Omit<InitializeSignerRequest, 'confirmedRequestDigest' | 'rolloutGate'>): string {
  return digest('initialize', {
    operation_id: input.operationId,
    expected_signer_revision: input.expectedSignerRevision,
    active_kid: input.activeKid,
    bundle_sha256: trustBundleArtifactDigest(input.bundleJws),
    reason: input.reason.trim(),
    rollout_gate: rolloutGate,
  });
}

export function acceptSignerTrustBundleRequestDigest(input: Omit<AcceptSignerTrustBundleRequest, 'confirmedRequestDigest' | 'rolloutGate'>): string {
  return digest('trust_bundle_accept', {
    operation_id: input.operationId,
    expected_signer_revision: input.expectedSignerRevision,
    bundle_sha256: trustBundleArtifactDigest(input.bundleJws),
    reason: input.reason.trim(),
    rollout_gate: rolloutGate,
  });
}

export function rotateSignerRequestDigest(input: Omit<RotateSignerRequest, 'confirmedRequestDigest' | 'rolloutGate'>): string {
  return digest('key_rotate', {
    operation_id: input.operationId,
    expected_signer_revision: input.expectedSignerRevision,
    target_kid: input.targetKid,
    bundle_version: input.bundleVersion,
    artifact_sha256: input.artifactSha256,
    reason: input.reason.trim(),
    rollout_gate: rolloutGate,
  });
}

function normalizeBase(input: SignerAdminBase, expectedDigest: string): SignerAdminBase {
  if (!uuidPattern.test(input.operationId)) throw new AdminOperationError('SIGNER_OPERATION_ID_INVALID');
  if (!revisionPattern.test(input.expectedSignerRevision) || BigInt(input.expectedSignerRevision) > 9_223_372_036_854_775_807n) {
    throw new AdminOperationError('SIGNER_REVISION_INVALID');
  }
  const reason = input.reason.trim();
  if (reason.length < 5 || reason.length > 1000 || /[\u0000-\u001f\u007f]/.test(reason)) throw new AdminOperationError('SIGNER_REASON_INVALID');
  if (input.rolloutGate !== rolloutGate) throw new AdminOperationError('SIGNER_ROLLOUT_GATE_REQUIRED');
  if (input.confirmedRequestDigest !== expectedDigest) throw new AdminOperationError('ADMIN_CONFIRMATION_DIGEST_MISMATCH');
  return { ...input, reason };
}

function actorValues(session: AdminSession) {
  return {
    actor_os_uid: session.actor.osUid,
    actor_os_username: session.actor.osUsername,
    actor_database_role: session.actor.databaseRole,
  };
}

function signerProofMessage(input: {
  issuer: string;
  operationId: string;
  requestDigest: string;
  expectedRevision: string;
  targetKid: string;
  bundleVersion: string;
  artifactSha256: string;
  reason: string;
}): Buffer {
  const value = canonicalize({
    domain: 'aikayun-license-center-signer-possession-v1',
    issuer: input.issuer,
    operation_id: input.operationId,
    request_digest: input.requestDigest,
    expected_signer_revision: input.expectedRevision,
    target_kid: input.targetKid,
    bundle_version: input.bundleVersion,
    artifact_sha256: input.artifactSha256,
    reason: input.reason,
    rollout_gate: rolloutGate,
  });
  if (!value) throw new AdminOperationError('SIGNER_PROOF_INPUT_INVALID');
  return Buffer.from(value, 'utf8');
}

function validateCandidate(token: string, candidate: RootAuthenticatedTrustBundleCandidate, now: Date, config: SignerRuntimeConfig): void {
  const nowSeconds = Math.floor(now.getTime() / 1000);
  try {
    assertTrustBundleValidAt(candidate, nowSeconds);
    if (compareBundleVersions(candidate.claims.bundle_version, config.minimumTrustBundleVersion) < 0) {
      throw new AdminOperationError('SIGNER_BUNDLE_BELOW_RELEASE_MINIMUM');
    }
    if (candidate.token !== token || candidate.claims.sub !== config.issuer || candidate.rootKid !== config.trustedOfflineRoot.kid) {
      throw new AdminOperationError('SIGNER_BUNDLE_IDENTITY_MISMATCH');
    }
  } catch (error) {
    if (error instanceof AdminOperationError) throw error;
    throw new AdminOperationError('SIGNER_BUNDLE_OUTSIDE_VALIDITY_WINDOW');
  }
}

function trustedCandidateKey(candidate: RootAuthenticatedTrustBundleCandidate, kid: string) {
  try {
    return getRootAuthenticatedCandidateKey(candidate, kid);
  } catch {
    throw new AdminOperationError('SIGNER_TARGET_KEY_NOT_TRUSTED');
  }
}

function checkedBundleTransition(input: Parameters<typeof validateTrustBundleTransition>[0]): ReturnType<typeof validateTrustBundleTransition> {
  try {
    return validateTrustBundleTransition(input);
  } catch {
    throw new AdminOperationError('SIGNER_BUNDLE_TRANSITION_INVALID');
  }
}

async function parseCandidate(token: string, config: SignerRuntimeConfig): Promise<RootAuthenticatedTrustBundleCandidate> {
  try {
    return await verifyTrustBundleSignature(token, { trustedRoot: config.trustedOfflineRoot, expectedCenterIssuer: config.issuer });
  } catch {
    throw new AdminOperationError('SIGNER_BUNDLE_SIGNATURE_INVALID');
  }
}

function mapResult(row: LicenseSignerOperationRow, replayed: boolean): SignerOperationResult {
  const result = row.result;
  const storedRevision = result['signer_revision'];
  const storedActiveKid = result['active_signing_kid'];
  return {
    operationId: row.operation_id,
    requestDigest: row.request_digest,
    action: row.action,
    state: row.state,
    outcomeCode: row.outcome_code,
    expectedSignerRevision: row.expected_signer_revision.toString(),
    signerRevision: typeof storedRevision === 'string' ? storedRevision : row.expected_signer_revision.toString(),
    activeSigningKid: typeof storedActiveKid === 'string' ? storedActiveKid : null,
    bundleVersion: row.bundle_version ?? '',
    artifactSha256: row.artifact_sha256 ?? '',
    result,
    replayed,
  };
}

function assertReplay(row: LicenseSignerOperationRow, input: { requestDigest: string; action: SignerAction; session: AdminSession }): void {
  if (row.actor_os_uid !== input.session.actor.osUid || row.actor_database_role !== input.session.actor.databaseRole) {
    throw new AdminOperationError('ADMIN_OPERATION_ACTOR_MISMATCH');
  }
  if (row.action !== input.action || row.request_digest !== input.requestDigest) throw new AdminOperationError('ADMIN_OPERATION_ID_CONFLICT');
}

async function lockOperation(trx: AdminTransaction, operationId: string): Promise<void> {
  await sql`SELECT pg_advisory_xact_lock(hashtextextended(${'license-signer-operation:' + operationId}, 0))`.execute(trx);
}

async function currentAuthority(trx: AdminTransaction): Promise<LicenseSignerAuthorityRow> {
  const authority = await trx.selectFrom('license_signer_authority').selectAll().where('singleton', '=', true).forUpdate().executeTakeFirst();
  if (!authority) throw new AdminOperationError('SIGNER_AUTHORITY_ROW_MISSING');
  return authority;
}

async function writeSignerOperation(trx: AdminTransaction, session: AdminSession, input: {
  operationId: string;
  requestDigest: string;
  action: SignerAction;
  expectedRevision: string;
  previousKid: string | null;
  targetKid: string | null;
  bundleVersion: string | null;
  artifactSha256: string | null;
  proofSha256: string | null;
  reason: string;
  state: 'succeeded' | 'rejected';
  outcomeCode: string;
  result: Record<string, unknown>;
  now: Date;
}): Promise<void> {
  await trx.insertInto('license_signer_operations').values({
    operation_id: input.operationId,
    request_digest: input.requestDigest,
    action: input.action,
    expected_signer_revision: input.expectedRevision,
    previous_signing_kid: input.previousKid,
    target_signing_kid: input.targetKid,
    bundle_version: input.bundleVersion,
    artifact_sha256: input.artifactSha256,
    proof_sha256: input.proofSha256,
    rollout_gate: rolloutGate,
    reason: input.reason,
    ...actorValues(session),
    state: input.state,
    outcome_code: input.outcomeCode,
    result: input.result,
    created_at: input.now,
    finalized_at: input.now,
  }).execute();
  await trx.insertInto('license_signer_audit_events').values({
    event_id: randomUUID(),
    operation_id: input.operationId,
    request_digest: input.requestDigest,
    action: input.action,
    expected_signer_revision: input.expectedRevision,
    previous_signing_kid: input.previousKid,
    target_signing_kid: input.targetKid,
    bundle_version: input.bundleVersion,
    artifact_sha256: input.artifactSha256,
    proof_sha256: input.proofSha256,
    rollout_gate: rolloutGate,
    reason: input.reason,
    ...actorValues(session),
    state: input.state,
    outcome_code: input.outcomeCode,
    result: input.result,
    created_at: input.now,
  }).execute();
}

function storedTicketKid(token: string, expectedTyp: string): string | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const header = parseStrictJsonSegment(parts[0]!);
    if (Object.keys(header).sort().join(',') !== 'alg,kid,typ' || header['alg'] !== 'Ed25519' ||
      header['typ'] !== expectedTyp || typeof header['kid'] !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(header['kid'])) return null;
    return header['kid'];
  } catch {
    return null;
  }
}

async function invalidatePreparedPlansForKeyPolicy(trx: AdminTransaction, affectedKids: readonly string[], now: Date): Promise<number> {
  const affected = new Set(affectedKids);
  if (affected.size === 0) return 0;
  let count = 0;
  const normalPlans = await trx.selectFrom('license_transfer_plans').selectAll().where('state', '=', 'prepared').forUpdate().execute();
  for (const plan of normalPlans) {
    const kid = storedTicketKid(plan.ticket_jws, 'aikayun-license-transfer-ticket+jwt');
    if (!kid || !affected.has(kid)) continue;
    const updated = await trx.updateTable('license_transfer_plans').set({ state: 'invalidated' })
      .where('plan_id', '=', plan.plan_id).where('state', '=', 'prepared').returning('plan_id').executeTakeFirst();
    if (!updated) continue;
    await trx.insertInto('license_transfer_events').values({
      event_id: randomUUID(), license_id: plan.license_id, approval_id: plan.approval_id,
      prepare_operation_id: plan.prepare_operation_id, commit_operation_id: null, plan_id: plan.plan_id,
      kind: 'invalidated', actor: 'license-center:signing-key-policy',
      safe_details: { reason: 'signing_key_revoked_or_retired', signer_kid: kid, ticket_digest: plan.ticket_digest },
      created_at: now,
    }).execute();
    count += 1;
  }
  const disasterPlans = await trx.selectFrom('license_disaster_transfer_plans').selectAll()
    .where('state', '=', 'prepared').forUpdate().execute();
  for (const plan of disasterPlans) {
    const kid = storedTicketKid(plan.ticket_jws, 'aikayun-license-disaster-transfer-ticket+jwt');
    if (!kid || !affected.has(kid)) continue;
    const updated = await trx.updateTable('license_disaster_transfer_plans').set({ state: 'invalidated' })
      .where('plan_id', '=', plan.plan_id).where('state', '=', 'prepared').returning('plan_id').executeTakeFirst();
    if (!updated) continue;
    await trx.insertInto('license_disaster_transfer_events').values({
      event_id: randomUUID(), license_id: plan.license_id, request_id: plan.request_id,
      approval_id: plan.approval_id, prepare_operation_id: plan.prepare_operation_id,
      commit_operation_id: null, plan_id: plan.plan_id, kind: 'invalidated',
      actor: 'license-center:signing-key-policy',
      safe_details: { reason: 'signing_key_revoked_or_retired', signer_kid: kid, ticket_digest: plan.ticket_digest },
      created_at: now,
    }).execute();
    count += 1;
  }
  return count;
}

async function recordRejectedOperation(session: AdminSession, input: {
  operationId: string;
  requestDigest: string;
  action: SignerAction;
  expectedRevision: string;
  reason: string;
  targetKid?: string | null;
  bundleToken?: string;
  bundleVersion?: string;
  artifactSha256?: string;
}, outcomeCode: string): Promise<void> {
  await session.db.transaction().execute(async (trx) => {
    await lockSigningAuthorityForUpdate(trx);
    await lockOperation(trx, input.operationId);
    const existing = await trx.selectFrom('license_signer_operations').selectAll()
      .where('operation_id', '=', input.operationId).executeTakeFirst();
    if (existing) {
      assertReplay(existing, { requestDigest: input.requestDigest, action: input.action, session });
      return;
    }
    const authority = await currentAuthority(trx);
    const nowResult = await sql<{ now: Date }>`SELECT clock_timestamp() AS now`.execute(trx);
    const now = nowResult.rows[0]!.now;
    const bundleVersion = input.bundleVersion ?? authority.bundle_version;
    const artifactSha256 = input.artifactSha256 ?? (input.bundleToken
      ? trustBundleArtifactDigest(input.bundleToken)
      : authority.artifact_sha256);
    const result = {
      signer_revision: authority.signer_revision.toString(),
      active_signing_kid: authority.active_signing_kid,
      bundle_version: authority.bundle_version,
      artifact_sha256: authority.artifact_sha256,
    };
    await writeSignerOperation(trx, session, {
      operationId: input.operationId,
      requestDigest: input.requestDigest,
      action: input.action,
      expectedRevision: input.expectedRevision,
      previousKid: authority.active_signing_kid,
      targetKid: input.targetKid ?? null,
      bundleVersion,
      artifactSha256,
      proofSha256: null,
      reason: input.reason,
      state: 'rejected',
      outcomeCode,
      result,
      now,
    });
  });
}

export function createSignerAdminService(session: AdminSession, config: SignerRuntimeConfig): SignerAdminService {
  if (config.nodeEnv !== 'development') throw new AdminAccessError('ADMIN_CLI_DISABLED_IN_PRODUCTION');

  async function execute(input: {
    operationId: string;
    requestDigest: string;
    action: SignerAction;
    expectedRevision: string;
    reason: string;
    targetKid?: string | null;
    bundleToken?: string;
    bundleVersion?: string;
    artifactSha256?: string;
    expectedActiveKid?: string | null;
    allowInitialize?: boolean;
    allowBundleAccept?: boolean;
  }): Promise<SignerOperationResult> {
    try {
      return await session.db.transaction().execute(async (trx) => {
        await lockSigningAuthorityForUpdate(trx);
        await lockOperation(trx, input.operationId);
        const existing = await trx.selectFrom('license_signer_operations').selectAll()
          .where('operation_id', '=', input.operationId).executeTakeFirst();
        if (existing) {
          assertReplay(existing, { requestDigest: input.requestDigest, action: input.action, session });
          const authority = await trx.selectFrom('license_signer_authority').selectAll().where('singleton', '=', true).executeTakeFirst();
          void authority;
          return mapResult(existing, true);
        }
        const authority = await currentAuthority(trx);
        const nowResult = await sql<{ now: Date }>`SELECT clock_timestamp() AS now`.execute(trx);
        const now = nowResult.rows[0]!.now;
        try { assertCenterTimeSourceHealthy(now); }
        catch { throw new AdminOperationError('SIGNER_TIME_SOURCE_UNHEALTHY'); }
        const actualRevision = authority.signer_revision.toString();
        if (actualRevision !== input.expectedRevision) throw new AdminOperationError('SIGNER_REVISION_CONFLICT');
        let latestCandidate: RootAuthenticatedTrustBundleCandidate | null = null;
        let previousRevoked: string[] = [];
        let previousRetired: string[] = [];
        if (authority.bundle_version && authority.artifact_sha256) {
          const previous = await trx.selectFrom('license_signer_trust_bundles').selectAll()
            .where('bundle_version', '=', authority.bundle_version)
            .where('artifact_sha256', '=', authority.artifact_sha256)
            .forShare().executeTakeFirst();
          if (!previous) throw new AdminOperationError('SIGNER_TRUST_STATE_CORRUPT');
          latestCandidate = await parseCandidate(previous.bundle_jws, config);
          validateCandidate(previous.bundle_jws, latestCandidate, now, config);
          previousRevoked = previous.revoked_kids;
          previousRetired = previous.retired_kids;
        }

        let candidate = latestCandidate;
        let bundleVersion = authority.bundle_version ?? '';
        let artifactSha256 = authority.artifact_sha256 ?? '';
        let revokedKids = previousRevoked;
        let retiredKids = previousRetired;
        let invalidatedPreparedPlans = 0;
        if (input.bundleToken) {
          candidate = await parseCandidate(input.bundleToken, config);
          validateCandidate(input.bundleToken, candidate, now, config);
          bundleVersion = candidate.claims.bundle_version;
          artifactSha256 = candidate.artifactSha256;
          if (latestCandidate) {
            const comparison = compareBundleVersions(bundleVersion, latestCandidate.claims.bundle_version);
            if (comparison < 0 || (comparison === 0 && artifactSha256 !== latestCandidate.artifactSha256)) {
              throw new AdminOperationError('SIGNER_BUNDLE_VERSION_OR_DIGEST_CONFLICT');
            }
            if (comparison === 0) {
              revokedKids = previousRevoked;
              retiredKids = previousRetired;
            } else {
              ({ revokedKids, retiredKids } = checkedBundleTransition({
                previous: latestCandidate, next: candidate, previousRevokedKids: previousRevoked,
                previousRetiredKids: previousRetired, acceptedAt: Math.floor(now.getTime() / 1000),
              }));
            }
          } else {
            ({ revokedKids, retiredKids } = checkedBundleTransition({
              previous: null, next: candidate, previousRevokedKids: [], previousRetiredKids: [],
              acceptedAt: Math.floor(now.getTime() / 1000),
            }));
          }
        }
        if (!candidate || !bundleVersion || !artifactSha256) throw new AdminOperationError('SIGNER_TRUST_BUNDLE_UNINITIALIZED');
        if (input.bundleVersion !== undefined && (input.bundleVersion !== bundleVersion || input.artifactSha256 !== artifactSha256)) {
          throw new AdminOperationError('SIGNER_BUNDLE_REFERENCE_MISMATCH');
        }
        const targetKid = input.targetKid ?? null;
        let proofSha256: string | null = null;
        if (input.action === 'initialize' || input.action === 'key_rotate') {
          if (!targetKid) throw new AdminOperationError('SIGNER_TARGET_KID_REQUIRED');
          const { record, publicKey } = trustedCandidateKey(candidate, targetKid);
          if (record.revoked_at !== null || revokedKids.includes(targetKid) || retiredKids.includes(targetKid)) {
            throw new AdminOperationError('SIGNER_TARGET_KEY_REVOKED_OR_RETIRED');
          }
          const nowSeconds = Math.floor(now.getTime() / 1000);
          if (nowSeconds < record.not_before || (record.retire_after !== null && nowSeconds >= record.retire_after) ||
            (record.verify_until !== null && nowSeconds >= record.verify_until)) {
            throw new AdminOperationError('SIGNER_TARGET_KEY_OUTSIDE_LIFECYCLE');
          }
          const material = config.signingKeyring.get(targetKid);
          if (!material) throw new AdminOperationError('SIGNER_TARGET_PRIVATE_KEY_UNAVAILABLE');
          if (material.publicJwk.x !== record.x || material.kid !== targetKid) throw new AdminOperationError('SIGNER_TARGET_PRIVATE_KEY_MISMATCH');
          const message = signerProofMessage({
            issuer: config.issuer, operationId: input.operationId, requestDigest: input.requestDigest,
            expectedRevision: input.expectedRevision, targetKid, bundleVersion, artifactSha256, reason: input.reason,
          });
          const proof = await webcrypto.subtle.sign('Ed25519', material.privateKey, message);
          if (!await webcrypto.subtle.verify('Ed25519', publicKey, proof, message)) throw new AdminOperationError('SIGNER_TARGET_POSSESSION_PROOF_FAILED');
          proofSha256 = sha256(new Uint8Array(proof));
          if (input.action === 'key_rotate') {
            if (authority.active_signing_kid !== input.expectedActiveKid || !authority.active_signing_kid) {
              throw new AdminOperationError('SIGNER_ACTIVE_IDENTITY_CHANGED');
            }
            if (targetKid === authority.active_signing_kid) throw new AdminOperationError('SIGNER_ROTATION_TARGET_MUST_BE_NEW');
            const previousUse = await trx.selectFrom('license_signer_operations').select('operation_id')
              .where('state', '=', 'succeeded').where('action', 'in', ['initialize', 'key_rotate'])
              .where('target_signing_kid', '=', targetKid).executeTakeFirst();
            if (previousUse) throw new AdminOperationError('SIGNER_KEY_IDENTITY_CANNOT_BE_REUSED');
          } else if (authority.active_signing_kid !== null || authority.signer_revision !== '0') {
            throw new AdminOperationError('SIGNER_AUTHORITY_ALREADY_INITIALIZED');
          }
        }
        if (input.action === 'trust_bundle_accept') {
          if (!input.allowBundleAccept || !authority.active_signing_kid) throw new AdminOperationError('SIGNER_TRUST_ACCEPT_ACTION_INVALID');
          if (!latestCandidate) throw new AdminOperationError('SIGNER_AUTHORITY_UNINITIALIZED');
          if (authority.active_signing_kid && !candidate.claims.keys.some((key) => key.kid === authority.active_signing_kid) &&
            !revokedKids.includes(authority.active_signing_kid) && !retiredKids.includes(authority.active_signing_kid)) {
            throw new AdminOperationError('SIGNER_ACTIVE_KEY_MUST_ROTATE_BEFORE_REMOVAL');
          }
        }
        const isNewBundle = authority.bundle_version !== bundleVersion;
        if (input.action === 'trust_bundle_accept' && isNewBundle) {
          const newlyAffected = [...revokedKids.filter((kid) => !previousRevoked.includes(kid)),
            ...retiredKids.filter((kid) => !previousRetired.includes(kid))];
          invalidatedPreparedPlans = await invalidatePreparedPlansForKeyPolicy(trx, newlyAffected, now);
        }
        const proofTarget = input.action === 'trust_bundle_accept' ? null : targetKid;
        const previousKid = input.action === 'initialize' ? null : authority.active_signing_kid;
        const nextRevision = input.action === 'initialize' || input.action === 'key_rotate'
          ? (BigInt(actualRevision) + 1n).toString()
          : actualRevision;
        const result = {
          signer_revision: nextRevision,
          active_signing_kid: input.action === 'trust_bundle_accept' ? authority.active_signing_kid : targetKid,
          previous_signing_kid: input.action === 'initialize' ? null : authority.active_signing_kid,
          bundle_version: bundleVersion,
          artifact_sha256: artifactSha256,
          proof_sha256: proofSha256,
          invalidated_prepared_plans: invalidatedPreparedPlans,
        };
        const outcomeCode = input.action === 'trust_bundle_accept' && !isNewBundle ? 'SIGNER_TRUST_BUNDLE_ALREADY_ACCEPTED'
          : input.action === 'trust_bundle_accept' ? 'SIGNER_TRUST_BUNDLE_ACCEPTED'
            : input.action === 'initialize' ? 'SIGNER_AUTHORITY_INITIALIZED' : 'SIGNER_KEY_ROTATED';
        await writeSignerOperation(trx, session, {
          operationId: input.operationId, requestDigest: input.requestDigest, action: input.action,
          expectedRevision: actualRevision, previousKid, targetKid: proofTarget, bundleVersion, artifactSha256,
          proofSha256, reason: input.reason, state: 'succeeded', outcomeCode, result, now,
        });
        if (input.bundleToken && isNewBundle) {
          await trx.insertInto('license_signer_trust_bundles').values({
            bundle_version: bundleVersion,
            artifact_sha256: artifactSha256,
            root_kid: candidate.rootKid,
            bundle_jws: candidate.token,
            revoked_kids: sql`${JSON.stringify(revokedKids)}::jsonb`,
            retired_kids: sql`${JSON.stringify(retiredKids)}::jsonb`,
            accepted_by_operation_id: input.operationId,
            accepted_at: now,
          }).execute();
        }
        if (input.action === 'initialize' || input.action === 'key_rotate') {
          await trx.updateTable('license_signer_authority').set({
            active_signing_kid: targetKid,
            signer_revision: nextRevision,
            bundle_version: bundleVersion,
            artifact_sha256: artifactSha256,
            previous_signing_kid: previousKid,
            changed_at: now,
          }).where('singleton', '=', true).execute();
        } else if (isNewBundle) {
          await trx.updateTable('license_signer_authority').set({ bundle_version: bundleVersion, artifact_sha256: artifactSha256, changed_at: now })
            .where('singleton', '=', true).execute();
        }
        return {
          operationId: input.operationId, requestDigest: input.requestDigest, action: input.action,
          state: 'succeeded', outcomeCode, expectedSignerRevision: actualRevision, signerRevision: nextRevision,
          activeSigningKid: result.active_signing_kid, bundleVersion, artifactSha256, result, replayed: false,
        };
      });
    } catch (error) {
      if (error instanceof AdminOperationError) {
        if (!['ADMIN_OPERATION_ID_CONFLICT', 'ADMIN_OPERATION_ACTOR_MISMATCH'].includes(error.code)) {
          try {
            await recordRejectedOperation(session, {
              operationId: input.operationId,
              requestDigest: input.requestDigest,
              action: input.action,
              expectedRevision: input.expectedRevision,
              reason: input.reason,
              targetKid: input.targetKid ?? null,
              ...(input.bundleToken ? { bundleToken: input.bundleToken } : {}),
              ...(input.bundleVersion ? { bundleVersion: input.bundleVersion } : {}),
              ...(input.artifactSha256 ? { artifactSha256: input.artifactSha256 } : {}),
            }, error.code);
          } catch {
            throw new AdminOperationError('SIGNER_REJECTION_AUDIT_FAILED');
          }
        }
        throw error;
      }
      if (error instanceof AdminAccessError) throw error;
      let committed: LicenseSignerOperationRow | undefined;
      try {
        committed = await session.db.selectFrom('license_signer_operations').selectAll()
          .where('operation_id', '=', input.operationId).executeTakeFirst();
      } catch {
        throw new AdminOperationError('SIGNER_COMMIT_OUTCOME_UNKNOWN');
      }
      if (!committed) throw error;
      assertReplay(committed, { requestDigest: input.requestDigest, action: input.action, session });
      const authority = await session.db.selectFrom('license_signer_authority').selectAll().where('singleton', '=', true).executeTakeFirst();
      void authority;
      return mapResult(committed, true);
    }
  }

  return {
    async getState() {
      const authority = await session.db.selectFrom('license_signer_authority').selectAll().where('singleton', '=', true).executeTakeFirst();
      if (!authority) throw new AdminOperationError('SIGNER_AUTHORITY_ROW_MISSING');
      return {
        activeKid: authority.active_signing_kid,
        signerRevision: authority.signer_revision.toString(),
        bundleVersion: authority.bundle_version,
        artifactSha256: authority.artifact_sha256,
        previousKid: authority.previous_signing_kid,
      };
    },
    async initialize(request) {
      const confirmed = normalizeBase(request, initializeSignerRequestDigest(request));
      if (!/^[A-Za-z0-9_-]{43}$/.test(request.activeKid)) throw new AdminOperationError('SIGNER_TARGET_KID_INVALID');
      return execute({
        operationId: confirmed.operationId, requestDigest: confirmed.confirmedRequestDigest,
        action: 'initialize', expectedRevision: confirmed.expectedSignerRevision, reason: confirmed.reason,
        targetKid: request.activeKid, bundleToken: request.bundleJws, allowInitialize: true,
      });
    },
    async acceptTrustBundle(request) {
      const confirmed = normalizeBase(request, acceptSignerTrustBundleRequestDigest(request));
      return execute({
        operationId: confirmed.operationId, requestDigest: confirmed.confirmedRequestDigest,
        action: 'trust_bundle_accept', expectedRevision: confirmed.expectedSignerRevision, reason: confirmed.reason,
        bundleToken: request.bundleJws, allowBundleAccept: true,
      });
    },
    async rotate(request) {
      const confirmed = normalizeBase(request, rotateSignerRequestDigest(request));
      if (!/^[A-Za-z0-9_-]{43}$/.test(request.targetKid) || !/^[1-9][0-9]{0,18}$/.test(request.bundleVersion) ||
        !/^[A-Za-z0-9_-]{43}$/.test(request.artifactSha256)) throw new AdminOperationError('SIGNER_ROTATION_INPUT_INVALID');
      return execute({
        operationId: confirmed.operationId, requestDigest: confirmed.confirmedRequestDigest,
        action: 'key_rotate', expectedRevision: confirmed.expectedSignerRevision, reason: confirmed.reason,
        targetKid: request.targetKid, bundleVersion: request.bundleVersion, artifactSha256: request.artifactSha256,
        expectedActiveKid: (await getAuthority()).active_signing_kid,
      });
    },
  };

  async function getAuthority(): Promise<LicenseSignerAuthorityRow> {
    const authority = await session.db.selectFrom('license_signer_authority').selectAll().where('singleton', '=', true).executeTakeFirst();
    if (!authority) throw new AdminOperationError('SIGNER_AUTHORITY_ROW_MISSING');
    return authority;
  }
}
