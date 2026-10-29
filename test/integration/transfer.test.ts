import { createHash, createPrivateKey, randomBytes, randomUUID, sign as cryptoSign } from 'node:crypto';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { userInfo, tmpdir } from 'node:os';
import { join } from 'node:path';
import { sql, type Kysely } from 'kysely';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import {
  approveTransferRequestDigest,
  changeLicenseStatusRequestDigest,
  createAdminService,
  revokeTransferApprovalRequestDigest,
  renewLicenseRequestDigest,
  approveTimeResetRequestDigest,
  type ApproveTransferRequest,
  type AdminOperationResult,
} from '../../src/admin/service.js';
import { acceptSignerTrustBundleRequestDigest } from '../../src/admin/signing-service.js';
import { createDatabase, migrateToLatest } from '../../src/db/database.js';
import type { Database } from '../../src/db/types.js';
import { activationIntentDigest, renewalIntentDigest, timeResetIntentDigest, transferCommitIntentDigest, transferPrepareIntentDigest } from '../../src/intent.js';
import { signTypedJwt } from '../../src/crypto/jwt.js';
import { loadTrustedSigningContext } from '../../src/crypto/signing-authority.js';
import { verifyTypedJwt } from '../../src/crypto/jwt.js';
import { verifyTimeResetReceipt } from '../../src/crypto/time-reset.js';
import { signTransferTicket, verifyLicenseLease, verifyTransferReceipt, verifyTransferTicket } from '../../src/receipts.js';
import { publishAndRotateTo } from '../support/signing-rotation.js';
import { createActivationCode, createLicense, getDbNow } from '../fixtures.js';
import { trustBundleArtifactDigest } from '../../src/trust/trust-bundle.js';
import { CommitAckDropProxy } from '../support/postgres-proxy.js';
import { HttpResponseDropProxy } from '../support/http-response-proxy.js';
import { terminatePostgresBackend, waitForLicenseRowWaiterPids, waitForLicenseRowWaiters, waitForNoLockWaiters } from '../support/pg-waits.js';
import { startChildLicenseServer } from '../support/child-server.js';
import {
  buildChallengeBoundBody, requestChallenge, signPost, startAppServer, type HttpResponse, type RunningTestServer,
} from '../support/http.js';
import { createIdentity, createTestSigningRuntime, type TestIdentity, type TestSigningRuntime } from '../support/runtime.js';

interface ActiveSource {
  licenseId: string;
  source: TestIdentity;
  instanceId: string;
  databaseId: string;
  activationOperationId: string;
  activationLease: string;
}

interface PreparedTransfer {
  active: ActiveSource;
  target: TestIdentity;
  approval: AdminOperationResult;
  approvalId: string;
  prepareOperationId: string;
  prepareIntentDigest: string;
  ticket: string;
}

interface ChallengeAttempt {
  body: Record<string, unknown>;
  nonce: string;
}

function challengeNonce(token: string): string {
  const nonce = decodeJwt(token)['server_nonce'];
  if (typeof nonce !== 'string') throw new Error('Challenge server nonce missing');
  return nonce;
}

function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('base64url');
}

function decimalPlusOne(value: string): string {
  return (BigInt(value) + 1n).toString();
}

function signRawToken(runtime: TestSigningRuntime, typ: string, claimsJson: string, alg = 'Ed25519'): string {
  const header = Buffer.from(JSON.stringify({ alg, kid: runtime.config.signingKeyId, typ })).toString('base64url');
  const payload = Buffer.from(claimsJson).toString('base64url');
  const content = `${header}.${payload}`;
  const signature = cryptoSign(null, Buffer.from(content), createPrivateKey(runtime.privatePem)).toString('base64url');
  return `${content}.${signature}`;
}

describe('normal license transfer over real PostgreSQL and HTTPS', () => {
  let db: Kysely<Database>;
  let server: RunningTestServer;
  let runtime: TestSigningRuntime;
  let admin: Awaited<ReturnType<typeof createAdminService>>;
  let scratchDirectory: string;
  let policyFile: string;

  async function verifyCenterJwt(token: string) {
    const context = (await loadTrustedSigningContext(db, runtime.config)).context;
    const header = decodeProtectedHeader(token);
    const claims = decodeJwt(token);
    const verified = await verifyTypedJwt(token, {
      ...context,
      typ: String(header['typ']),
      audience: 'aikayun-commerce',
      now: new Date(context.trustedTime * 1000),
      requiredClaims: Object.keys(claims),
    });
    return { payload: verified.claims, protectedHeader: verified.header };
  }

  async function activate(): Promise<ActiveSource> {
    const license = await createLicense(db);
    const activationCode = await createActivationCode(db, license.id);
    const source = await createIdentity();
    const instanceId = randomUUID();
    const databaseId = randomUUID();
    const activationOperationId = randomUUID();
    const origin = 'https://shop.example.test';
    const intentDigest = activationIntentDigest({
      licenseId: license.id, activationCode: activationCode.code, instanceId, databaseId,
      identityJkt: source.jkt, origin,
    });
    const challenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: source, operation: 'activation',
      operationId: activationOperationId, intentDigest, instanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId: activationOperationId, intentDigest, attemptNo: 1,
        instanceId, identity: source, licenseId: license.id, databaseId,
      }),
      activation_code: activationCode.code,
      origin,
    };
    const response = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/activations', body,
      identity: source, nonce: challengeNonce(challenge.token),
    });
    expect(response.status).toBe(200);
    if (typeof response.json['license'] !== 'string') throw new Error('Activation lease missing');
    return { licenseId: license.id, source, instanceId, databaseId, activationOperationId, activationLease: response.json['license'] };
  }

  async function approve(active: ActiveSource, target: TestIdentity, extra: Partial<ApproveTransferRequest> = {}) {
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const request: Omit<ApproveTransferRequest, 'confirmedRequestDigest'> = {
      operationId: extra.operationId ?? randomUUID(),
      licenseId: active.licenseId,
      expectedRevision: extra.expectedRevision ?? license.revision.toString(),
      reason: extra.reason ?? '经核验安排授权中心正常迁移',
      databaseId: active.databaseId,
      sourceInstanceId: active.instanceId,
      sourceIdentityJkt: active.source.jkt,
      targetInstanceId: extra.targetInstanceId ?? active.instanceId,
      targetIdentityJkt: extra.targetIdentityJkt ?? target.jkt,
      sourceGeneration: extra.sourceGeneration ?? license.current_generation.toString(),
      expectedBindingRevision: extra.expectedBindingRevision ?? '7',
    };
    return admin.approveTransfer({
      ...request,
      confirmedRequestDigest: approveTransferRequestDigest(request),
    });
  }

  async function makePrepareAttempt(active: ActiveSource, target: TestIdentity, approvalId: string, input: {
    operationId?: string;
    attemptNo?: number;
    sourceIdentity?: TestIdentity;
    targetPublicJwk?: unknown;
    targetInstanceId?: string;
    expectedRevision?: string;
    sourceGeneration?: string;
    expectedBindingRevision?: string;
    licenseId?: string;
    databaseId?: string;
    requestServer?: { port: number };
  } = {}): Promise<{ attempt: ChallengeAttempt; operationId: string; intentDigest: string }> {
    const operationId = input.operationId ?? randomUUID();
    const sourceIdentity = input.sourceIdentity ?? active.source;
    const licenseId = input.licenseId ?? active.licenseId;
    const databaseId = input.databaseId ?? active.databaseId;
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', licenseId).executeTakeFirstOrThrow();
    const sourceGeneration = input.sourceGeneration ?? license.current_generation.toString();
    const expectedRevision = input.expectedRevision ?? license.revision.toString();
    const targetInstanceId = input.targetInstanceId ?? active.instanceId;
    const targetIdentityJkt = target.jkt;
    const expectedBindingRevision = input.expectedBindingRevision ?? '7';
    const intentDigest = transferPrepareIntentDigest({
      licenseId, databaseId, instanceId: active.instanceId,
      sourceIdentityJkt: sourceIdentity.jkt, targetInstanceId, targetIdentityJkt, approvalId,
      sourceGeneration, expectedBindingRevision, expectedRevision,
    });
    const requestServer = input.requestServer ?? server;
    const challenge = await requestChallenge({
      port: requestServer.port, config: runtime.config, identity: sourceIdentity,
      operation: 'transfer_prepare', operationId, intentDigest, instanceId: active.instanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId, intentDigest, attemptNo: input.attemptNo ?? 1,
        instanceId: active.instanceId, identity: sourceIdentity, licenseId, databaseId,
      }),
      approval_id: approvalId,
      target_instance_id: targetInstanceId,
      target_identity_jkt: targetIdentityJkt,
      target_public_jwk: input.targetPublicJwk ?? target.publicJwk,
      source_generation: sourceGeneration,
      expected_binding_revision: expectedBindingRevision,
      expected_revision: expectedRevision,
    };
    return { attempt: { body, nonce: challengeNonce(challenge.token) }, operationId, intentDigest };
  }

  async function sendPrepare(attempt: ChallengeAttempt, identity: TestIdentity, requestServer: { port: number } = server): Promise<HttpResponse> {
    return signPost({
      port: requestServer.port, origin: runtime.config.publicOrigin, path: '/v1/transfers/prepare',
      body: attempt.body, identity, nonce: attempt.nonce,
    });
  }

  async function makeCommitAttempt(prepared: PreparedTransfer, input: {
    operationId?: string;
    attemptNo?: number;
    targetIdentity?: TestIdentity;
    ticket?: string;
    approvalId?: string;
    prepareOperationId?: string;
    requestServer?: { port: number };
  } = {}): Promise<{ attempt: ChallengeAttempt; operationId: string; intentDigest: string }> {
    const operationId = input.operationId ?? randomUUID();
    const targetIdentity = input.targetIdentity ?? prepared.target;
    const ticket = input.ticket ?? prepared.ticket;
    const targetInstanceId = prepared.active.instanceId;
    const approvalId = input.approvalId ?? prepared.approvalId;
    const prepareOperationId = input.prepareOperationId ?? prepared.prepareOperationId;
    const intentDigest = transferCommitIntentDigest({
      licenseId: prepared.active.licenseId, databaseId: prepared.active.databaseId,
      instanceId: targetInstanceId, targetIdentityJkt: targetIdentity.jkt,
      approvalId, prepareOperationId, ticketDigest: sha256(ticket),
    });
    const requestServer = input.requestServer ?? server;
    const challenge = await requestChallenge({
      port: requestServer.port, config: runtime.config, identity: targetIdentity,
      operation: 'transfer_commit', operationId, intentDigest, instanceId: targetInstanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId, intentDigest, attemptNo: input.attemptNo ?? 1,
        instanceId: targetInstanceId, identity: targetIdentity,
        licenseId: prepared.active.licenseId, databaseId: prepared.active.databaseId,
      }),
      approval_id: approvalId,
      prepare_operation_id: prepareOperationId,
      transfer_ticket: ticket,
    };
    return { attempt: { body, nonce: challengeNonce(challenge.token) }, operationId, intentDigest };
  }

  async function sendCommit(attempt: ChallengeAttempt, identity: TestIdentity, requestServer: { port: number } = server): Promise<HttpResponse> {
    return signPost({
      port: requestServer.port, origin: runtime.config.publicOrigin, path: '/v1/transfers/commit',
      body: attempt.body, identity, nonce: attempt.nonce,
    });
  }

  async function prepare(active: ActiveSource, target = undefined as TestIdentity | undefined): Promise<PreparedTransfer> {
    const destination = target ?? await createIdentity();
    const approval = await approve(active, destination);
    expect(approval.state).toBe('succeeded');
    const approvalId = approval.operationId;
    const { attempt, operationId, intentDigest } = await makePrepareAttempt(active, destination, approvalId);
    const response = await sendPrepare(attempt, active.source);
    expect(response.status).toBe(200);
    if (typeof response.json['transfer_ticket'] !== 'string') throw new Error('Transfer ticket missing');
    return { active, target: destination, approval, approvalId, prepareOperationId: operationId,
      prepareIntentDigest: intentDigest, ticket: response.json['transfer_ticket'] };
  }

  async function commit(prepared: PreparedTransfer, input: Parameters<typeof makeCommitAttempt>[1] = {}) {
    const { attempt, operationId, intentDigest } = await makeCommitAttempt(prepared, input);
    const response = await sendCommit(attempt, input.targetIdentity ?? prepared.target, input.requestServer ?? server);
    return { response, attempt, operationId, intentDigest };
  }

  async function queryOperation(prepared: PreparedTransfer, operationId: string, intentDigest: string, attemptNo: number) {
    const targetInstanceId = prepared.active.instanceId;
    const challenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: prepared.target, operation: 'query',
      operationId, intentDigest, instanceId: targetInstanceId,
    });
    const body = buildChallengeBoundBody({
      challenge: challenge.token, operationId, intentDigest, attemptNo,
      instanceId: targetInstanceId, identity: prepared.target,
      licenseId: prepared.active.licenseId, databaseId: prepared.active.databaseId,
    });
    return signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/operations/query', body,
      identity: prepared.target, nonce: challengeNonce(challenge.token),
    });
  }

  async function writeAdminPolicy(url: string): Promise<string> {
    const credentialFile = join(scratchDirectory, `database-${randomUUID()}.url`);
    const policyPath = join(scratchDirectory, `policy-${randomUUID()}.json`);
    await writeFile(credentialFile, `${url}\n`, { mode: 0o600 });
    await chmod(credentialFile, 0o600);
    const uid = process.geteuid?.();
    if (uid === undefined) throw new Error('POSIX UID required by isolated admin tests');
    const role = decodeURIComponent(new URL(url).username);
    await writeFile(policyPath, JSON.stringify({
      environment: 'isolated-development', allowed_os_uids: [uid], database_role: role, database_url_file: credentialFile,
    }), { mode: 0o600 });
    await chmod(policyPath, 0o600);
    return policyPath;
  }

  beforeAll(async () => {
    runtime = await createTestSigningRuntime();
    db = createDatabase(runtime.config.databaseUrl, 24);
    await migrateToLatest(db);
    await runtime.initializeAuthority(db);
    server = await startAppServer(createApp({ config: runtime.config, db }));
    scratchDirectory = await mkdtemp(join(tmpdir(), 'aikayun-license-transfer-'));
    await chmod(scratchDirectory, 0o700);
    policyFile = await writeAdminPolicy(runtime.config.databaseUrl);
    admin = await createAdminService(policyFile);
  });

  afterAll(async () => {
    await admin?.close();
    await server?.stop();
    await db?.destroy();
    await runtime?.cleanup();
    if (scratchDirectory) await rm(scratchDirectory, { recursive: true, force: true });
  });

  it('approves without changing activation and prepare is source-proof, short-lived, and idempotent', async () => {
    const active = await activate();
    const target = await createIdentity();
    const before = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const approval = await approve(active, target);
    expect(approval.state).toBe('succeeded');
    const afterApproval = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect(afterApproval.current_generation).toBe(before.current_generation);
    expect(afterApproval.revision).toBe(before.revision);
    expect((await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId).where('state', '=', 'active').execute()))
      .toHaveLength(1);
    const approvalRow = await db.selectFrom('license_transfer_approvals').selectAll().where('approval_id', '=', approval.operationId).executeTakeFirstOrThrow();
    expect(approvalRow.actor_os_uid).toBe(process.geteuid?.());
    expect(approvalRow.actor_os_username).toBe(userInfo().username);
    expect(approvalRow.expires_at.getTime() - approvalRow.approved_at.getTime()).toBe(24 * 60 * 60 * 1000);

    const reusedApprovalId = await makePrepareAttempt(active, target, approval.operationId, { operationId: approval.operationId });
    expect((await sendPrepare(reusedApprovalId.attempt, active.source)).status).toBe(409);
    const { attempt, operationId, intentDigest } = await makePrepareAttempt(active, target, approval.operationId);
    const first = await sendPrepare(attempt, active.source);
    expect(first.status).toBe(200);
    const ticket = first.json['transfer_ticket'];
    if (typeof ticket !== 'string') throw new Error('Transfer ticket missing');
    const verified = await verifyCenterJwt(ticket);
    expect(verified.protectedHeader).toMatchObject({ alg: 'Ed25519', typ: 'aikayun-license-transfer-ticket+jwt' });
    expect(verified.payload).toMatchObject({
      license_id: active.licenseId, database_id: active.databaseId,
      source_instance_id: active.instanceId, source_identity_jkt: active.source.jkt,
      target_instance_id: active.instanceId, target_identity_jkt: target.jkt,
      approval_operation_id: approval.operationId, prepare_operation_id: operationId,
      prepare_intent_digest: intentDigest, source_activation_generation: '1', expected_revision: before.revision,
    });
    expect(Number(verified.payload['exp']) - Number(verified.payload['iat'])).toBe(600);
    const afterPrepare = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect(afterPrepare.current_generation).toBe(before.current_generation);
    expect(afterPrepare.revision).toBe(before.revision);
    const activeRows = await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', active.licenseId).where('state', '=', 'active').execute();
    expect(activeRows).toHaveLength(1);
    expect(activeRows[0]!.identity_jkt).toBe(active.source.jkt);

    const commitWithApprovalId = await makeCommitAttempt({
      active, target, approval, approvalId: approval.operationId, prepareOperationId: operationId,
      prepareIntentDigest: intentDigest, ticket,
    }, { operationId: approval.operationId });
    expect((await sendCommit(commitWithApprovalId.attempt, target)).status).toBe(409);

    const repeated = await makePrepareAttempt(active, target, approval.operationId, { operationId, attemptNo: 2 });
    const replay = await sendPrepare(repeated.attempt, active.source);
    expect(replay.status).toBe(200);
    expect(replay.json['transfer_ticket']).toBe(ticket);
    expect(await db.selectFrom('license_transfer_plans').selectAll().where('license_id', '=', active.licenseId).execute())
      .toHaveLength(1);
  });

  it('rejects missing admin approval, a substituted target key, reused old identity, and wrong-target commit proof', async () => {
    const active = await activate();
    const target = await createIdentity();
    const approval = await approve(active, target);
    const missing = await makePrepareAttempt(active, target, randomUUID());
    const missingResponse = await sendPrepare(missing.attempt, active.source);
    expect(missingResponse.status).toBe(403);
    expect(missingResponse.json['error']).toEqual({ code: 'TRANSFER_PREPARE_FORBIDDEN' });
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', missing.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', missing.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', missing.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_transfer_plans').selectAll().where('license_id', '=', active.licenseId).execute()).toHaveLength(0);

    const rogue = await createIdentity();
    const wrongSource = await makePrepareAttempt(active, target, approval.operationId, { sourceIdentity: rogue });
    expect((await sendPrepare(wrongSource.attempt, rogue)).status).toBe(403);
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', wrongSource.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', wrongSource.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', wrongSource.operationId).execute()).toHaveLength(0);

    const forged = await makePrepareAttempt(active, target, approval.operationId, {
      targetPublicJwk: (await createIdentity()).publicJwk,
    });
    expect((await sendPrepare(forged.attempt, active.source)).status).toBe(409);
    const reusedKey = await makePrepareAttempt(active, active.source, approval.operationId);
    expect((await sendPrepare(reusedKey.attempt, active.source)).status).toBe(409);
    for (const operationId of [forged.operationId, reusedKey.operationId]) {
      expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', operationId).execute()).toHaveLength(0);
      expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', operationId).execute()).toHaveLength(0);
      expect(await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', operationId).execute()).toHaveLength(0);
    }
    expect(await db.selectFrom('license_transfer_plans').selectAll().where('license_id', '=', active.licenseId).execute()).toHaveLength(0);

    const { attempt: validAttempt, operationId: validOperationId, intentDigest: validIntent } =
      await makePrepareAttempt(active, target, approval.operationId);
    const validPrepare = await sendPrepare(validAttempt, active.source);
    expect(validPrepare.status).toBe(200);
    const validTicket = validPrepare.json['transfer_ticket'];
    if (typeof validTicket !== 'string') throw new Error('Transfer ticket missing');
    const prepared: PreparedTransfer = {
      active, target, approval, approvalId: approval.operationId, prepareOperationId: validOperationId,
      prepareIntentDigest: validIntent, ticket: validTicket,
    };
    const otherIdentity = await createIdentity();
    const wrongProof = await commit(prepared, { targetIdentity: otherIdentity });
    expect(wrongProof.response.status).toBe(401);
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', wrongProof.operationId).execute()).toHaveLength(0);
    const tampered = `${prepared.ticket.slice(0, -1)}${prepared.ticket.endsWith('A') ? 'B' : 'A'}`;
    const badTicket = await commit(prepared, { ticket: tampered });
    expect(badTicket.response.status).toBe(401);
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', badTicket.operationId).execute()).toHaveLength(0);
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');
    expect((await commit(prepared)).response.status).toBe(200);
  });

  it('a committed ticket cannot be consumed by a different commit operation', async () => {
    const active = await activate();
    const prepared = await prepare(active);
    const first = await commit(prepared);
    expect(first.response.status).toBe(200);
    const second = await commit(prepared);
    expect(second.operationId).not.toBe(first.operationId);
    expect(second.response.status).toBe(409);
    expect((await verifyCenterJwt(second.response.json['operation_receipt'] as string)).payload['outcome_code'])
      .toBe('TRANSFER_TICKET_CONSUMED');
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
    expect(await db.selectFrom('license_transfer_events').selectAll()
      .where('license_id', '=', active.licenseId).where('kind', '=', 'committed').execute()).toHaveLength(1);
  });

  it('commits one generation atomically, preserves the database and entitlement, and signs the new lease and transfer receipt', async () => {
    const active = await activate();
    const before = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const codesBefore = await db.selectFrom('activation_codes').selectAll().where('license_id', '=', active.licenseId).execute();
    const prepared = await prepare(active);
    const committed = await commit(prepared);
    expect(committed.response.status).toBe(200);
    const receiptToken = committed.response.json['transfer_receipt'];
    if (typeof receiptToken !== 'string') throw new Error('Transfer commit receipt missing');
    const receipt = await verifyCenterJwt(receiptToken);
    expect(receipt.protectedHeader).toMatchObject({ alg: 'Ed25519', typ: 'aikayun-license-transfer+jwt' });
    expect(receipt.payload).toMatchObject({
      iss: runtime.config.issuer, aud: 'aikayun-commerce', license_id: active.licenseId,
      database_id: active.databaseId, source_instance_id: active.instanceId, source_identity_jkt: active.source.jkt,
      source_activation_generation: '1', target_instance_id: active.instanceId, target_identity_jkt: prepared.target.jkt,
      target_activation_generation: '2', expected_binding_revision: '7', expected_revision: before.revision,
      result_revision: decimalPlusOne(before.revision), entitlement_revision: before.entitlement_revision,
      operation_id: committed.operationId, intent_digest: committed.intentDigest,
    });
    expect(receipt.payload['request_nonce']).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(receipt.payload['request_digest']).toBe(sha256(JSON.stringify(committed.attempt.body)));
    expect(Number(receipt.payload['exp']) - Number(receipt.payload['iat'])).toBeLessThanOrEqual(600);
    const leaseToken = receipt.payload['new_lease'];
    if (typeof leaseToken !== 'string') throw new Error('Nested new lease missing');
    const lease = await verifyCenterJwt(leaseToken);
    expect(lease.protectedHeader).toMatchObject({ alg: 'Ed25519', typ: 'aikayun-license+jwt' });
    expect(lease.payload).toMatchObject({
      iss: runtime.config.issuer, aud: 'aikayun-commerce', sub: active.licenseId,
      instance_id: active.instanceId, database_id: active.databaseId, identity_jkt: prepared.target.jkt,
      activation_generation: '2', entitlement_revision: before.entitlement_revision,
      request_nonce: receipt.payload['request_nonce'], request_digest: receipt.payload['request_digest'],
    });
    expect(lease.payload['exp']).toBe(Math.min(Number(lease.payload['iat']) + 7 * 24 * 60 * 60,
      Math.floor(before.confirmed_subscription_end.getTime() / 1000)));
    const validationNow = new Date();
    const strictReceipt = await verifyTransferReceipt(receiptToken, runtime.config, validationNow);
    const strictLease = await verifyLicenseLease(leaseToken, runtime.config, validationNow);
    expect(strictReceipt['subscription_end']).toBe(strictLease['subscription_end']);
    expect(strictReceipt['database_id']).toBe(strictLease['database_id']);
    expect(strictReceipt['entitlement_revision']).toBe(strictLease['entitlement_revision']);
    await expect(verifyLicenseLease(receiptToken, runtime.config, validationNow)).rejects.toThrow();
    await expect(verifyTransferReceipt(leaseToken, runtime.config, validationNow)).rejects.toThrow();

    const outerClaims = receipt.payload as Record<string, unknown>;
    const innerClaims = lease.payload as Record<string, unknown>;
    const rejectedOuter = async (claims: Record<string, unknown>) => {
      const forged = await signTypedJwt(runtime.config, 'aikayun-license-transfer+jwt', claims);
      await expect(verifyTransferReceipt(forged, runtime.config, validationNow)).rejects.toThrow();
    };
    for (const [field, value] of [
      ['sub', randomUUID()],
      ['license_id', randomUUID()],
      ['database_id', randomUUID()],
      ['entitlement_revision', decimalPlusOne(String(outerClaims['entitlement_revision']))],
      ['subscription_end', Number(outerClaims['subscription_end']) + 3600],
    ] as const) {
      await rejectedOuter({ ...outerClaims, [field]: value });
    }
    const nestedMismatches: Array<[string, unknown]> = [
      ['sub', randomUUID()], ['database_id', randomUUID()], ['instance_id', randomUUID()],
      ['identity_jkt', sha256(randomUUID())], ['activation_generation', '3'],
      ['entitlement_revision', decimalPlusOne(String(innerClaims['entitlement_revision']))],
      ['subscription_end', Number(innerClaims['subscription_end']) + 3600],
      ['request_nonce', sha256(randomUUID())], ['request_digest', sha256(randomUUID())],
    ];
    for (const [field, value] of nestedMismatches) {
      const nestedToken = await signTypedJwt(runtime.config, 'aikayun-license+jwt', { ...innerClaims, [field]: value });
      await rejectedOuter({ ...outerClaims, new_lease: nestedToken });
    }
    const nestedUnknownClaim = await signTypedJwt(runtime.config, 'aikayun-license+jwt', {
      ...innerClaims, unexpected_claim: true,
    });
    await rejectedOuter({ ...outerClaims, new_lease: nestedUnknownClaim });
    const iat = Number(outerClaims['iat']);
    await rejectedOuter({ ...outerClaims, unexpected_claim: true });
    await rejectedOuter({ ...outerClaims, iss: 'https://wrong.example.test' });
    await rejectedOuter({ ...outerClaims, aud: 'different-commerce' });
    await rejectedOuter({ ...outerClaims, exp: iat + 601 });
    await rejectedOuter({ ...outerClaims, nbf: iat - 1 });
    await rejectedOuter({ ...outerClaims, iat: iat + 600, nbf: iat + 600, exp: iat + 1200 });
    const wrongType = await signTypedJwt(runtime.config, 'aikayun-license-disaster-transfer+jwt', outerClaims);
    await expect(verifyTransferReceipt(wrongType, runtime.config, validationNow)).rejects.toThrow();
    const duplicateClaim = JSON.stringify(outerClaims).replace('"v":1', '"v":1,"v":1');
    expect(duplicateClaim).not.toBe(JSON.stringify(outerClaims));
    const duplicateToken = signRawToken(runtime, 'aikayun-license-transfer+jwt', duplicateClaim);
    await expect(verifyTransferReceipt(duplicateToken, runtime.config, validationNow)).rejects.toThrow();
    const wrongAlgorithm = signRawToken(runtime, 'aikayun-license-transfer+jwt', JSON.stringify(outerClaims), 'EdDSA');
    await expect(verifyTransferReceipt(wrongAlgorithm, runtime.config, validationNow)).rejects.toThrow();
    const after = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect(after.current_generation).toBe('2');
    expect(after.revision).toBe(decimalPlusOne(before.revision));
    expect(after.entitlement_revision).toBe(before.entitlement_revision);
    expect(after.confirmed_subscription_end).toEqual(before.confirmed_subscription_end);
    expect(await db.selectFrom('activation_codes').selectAll().where('license_id', '=', active.licenseId).execute()).toEqual(codesBefore);
    const rows = await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', active.licenseId).orderBy('generation', 'asc').execute();
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ state: 'retired', generation: '1', database_id: active.databaseId, identity_jkt: active.source.jkt });
    expect(rows[1]).toMatchObject({ state: 'active', generation: '2', database_id: active.databaseId, identity_jkt: prepared.target.jkt });
    const currentPlan = await db.selectFrom('license_transfer_plans').selectAll()
      .where('plan_id', '=', decodeJwt(prepared.ticket)['plan_id'] as string).executeTakeFirstOrThrow();
    expect(currentPlan).toMatchObject({ state: 'committed', commit_operation_id: committed.operationId, committed_generation: '2', transfer_receipt_jws: receiptToken });

    const oldRenewalOperationId = randomUUID();
    const oldRenewalDigest = renewalIntentDigest({
      kind: 'renewal', licenseId: active.licenseId, databaseId: active.databaseId,
      instanceId: active.instanceId, identityJkt: active.source.jkt, expectedGeneration: '1', knownRevision: before.entitlement_revision,
    });
    const oldChallenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: active.source, operation: 'renewal',
      operationId: oldRenewalOperationId, intentDigest: oldRenewalDigest, instanceId: active.instanceId,
    });
    const oldBody = {
      ...buildChallengeBoundBody({
        challenge: oldChallenge.token, operationId: oldRenewalOperationId, intentDigest: oldRenewalDigest,
        attemptNo: 1, instanceId: active.instanceId, identity: active.source, licenseId: active.licenseId, databaseId: active.databaseId,
      }), expected_generation: '1', known_revision: before.entitlement_revision,
    };
    const oldResponse = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/leases/renew', body: oldBody,
      identity: active.source, nonce: challengeNonce(oldChallenge.token),
    });
    expect(oldResponse.status).toBe(409);
    expect((await verifyCenterJwt(oldResponse.json['status_receipt'] as string)).payload).toMatchObject({
      status: 'superseded', identity_jkt: active.source.jkt, activation_generation: '1', current_generation: '2',
    });
    expect(oldResponse.json['license']).toBeUndefined();

    const newRenewalOperationId = randomUUID();
    const newRenewalDigest = renewalIntentDigest({
      kind: 'renewal', licenseId: active.licenseId, databaseId: active.databaseId,
      instanceId: active.instanceId, identityJkt: prepared.target.jkt, expectedGeneration: '2', knownRevision: before.entitlement_revision,
    });
    const newChallenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: prepared.target, operation: 'renewal',
      operationId: newRenewalOperationId, intentDigest: newRenewalDigest, instanceId: active.instanceId,
    });
    const newBody = {
      ...buildChallengeBoundBody({
        challenge: newChallenge.token, operationId: newRenewalOperationId, intentDigest: newRenewalDigest,
        attemptNo: 1, instanceId: active.instanceId, identity: prepared.target, licenseId: active.licenseId, databaseId: active.databaseId,
      }), expected_generation: '2', known_revision: before.entitlement_revision,
    };
    const newResponse = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/leases/renew', body: newBody,
      identity: prepared.target, nonce: challengeNonce(newChallenge.token),
    });
    expect(newResponse.status).toBe(200);
    expect((await verifyCenterJwt(newResponse.json['license'] as string)).payload).toMatchObject({
      activation_generation: '2', identity_jkt: prepared.target.jkt, entitlement_revision: before.entitlement_revision,
    });
  });

  it('commits an A-signed normal transfer ticket after B becomes authoritative and signs a B result', async () => {
    const active = await activate();
    const before = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const activationBefore = await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', active.licenseId).where('state', '=', 'active').executeTakeFirstOrThrow();
    const prepared = await prepare(active);
    const originalPrepare = await db.selectFrom('license_operations').selectAll()
      .where('operation_id', '=', prepared.prepareOperationId).executeTakeFirstOrThrow();
    expect(decodeProtectedHeader(prepared.ticket)['kid']).toBe(runtime.onlineKey.kid);

    const b = await runtime.createOnlineKey();
    const { context } = await publishAndRotateTo(db, runtime, b, '2');
    const authority = await db.selectFrom('license_signer_authority').selectAll().where('singleton', '=', true).executeTakeFirstOrThrow();
    expect(authority).toMatchObject({ active_signing_kid: b.kid, signer_revision: '2', previous_signing_kid: runtime.onlineKey.kid });
    const afterRotation = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect([afterRotation.current_generation, afterRotation.revision, afterRotation.entitlement_revision,
      afterRotation.confirmed_subscription_end]).toEqual([
      before.current_generation, before.revision, before.entitlement_revision, before.confirmed_subscription_end,
    ]);
    const verificationTime = new Date(context.trustedTime * 1000);
    const activationAfterRotation = await db.selectFrom('license_activations').selectAll()
      .where('id', '=', activationBefore.id).executeTakeFirstOrThrow();
    expect(activationAfterRotation.time_epoch).toBe(activationBefore.time_epoch);
    const verifiedOldTicket = await verifyTransferTicket(prepared.ticket, context, verificationTime);
    expect(verifiedOldTicket.expired).toBe(false);
    expect(verifiedOldTicket.claims['plan_id']).toBe(decodeJwt(originalPrepare.response_jws)['plan_id']);

    const committed = await commit(prepared);
    expect(committed.response.status).toBe(200);
    const receiptToken = committed.response.json['transfer_receipt'] as string;
    expect(decodeProtectedHeader(receiptToken)['kid']).toBe(b.kid);
    const resultContext = (await loadTrustedSigningContext(db, runtime.config)).context;
    const validationNow = new Date(resultContext.trustedTime * 1000);
    const receipt = await verifyTransferReceipt(receiptToken, resultContext, validationNow);
    const leaseToken = receipt['new_lease'] as string;
    expect(decodeProtectedHeader(leaseToken)['kid']).toBe(b.kid);
    const lease = await verifyLicenseLease(leaseToken, resultContext, validationNow);
    expect(lease['activation_generation']).toBe('2');
    expect(receipt['entitlement_revision']).toBe(before.entitlement_revision);
    const plan = await db.selectFrom('license_transfer_plans').selectAll()
      .where('plan_id', '=', decodeJwt(prepared.ticket)['plan_id'] as string).executeTakeFirstOrThrow();
    expect(plan.ticket_jws).toBe(prepared.ticket);
    expect(originalPrepare.response_jws).toBe(prepared.ticket);
    const afterCommit = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect(afterCommit.current_generation).toBe('2');
    expect(afterCommit.revision).toBe(decimalPlusOne(before.revision));
    expect(afterCommit.entitlement_revision).toBe(before.entitlement_revision);
    expect(afterCommit.confirmed_subscription_end).toEqual(before.confirmed_subscription_end);
  });

  it('invalidates and audits an unfinished A ticket when the offline root urgently revokes A', async () => {
    const previous = { db, server, runtime, admin, policyFile };
    const isolatedRuntime = await createTestSigningRuntime();
    const isolatedDb = createDatabase(isolatedRuntime.config.databaseUrl, 24);
    await migrateToLatest(isolatedDb);
    await isolatedRuntime.initializeAuthority(isolatedDb);
    const isolatedServer = await startAppServer(createApp({ config: isolatedRuntime.config, db: isolatedDb }));
    const isolatedPolicy = await writeAdminPolicy(isolatedRuntime.config.databaseUrl);
    const isolatedAdmin = await createAdminService(isolatedPolicy);
    db = isolatedDb;
    server = isolatedServer;
    runtime = isolatedRuntime;
    admin = isolatedAdmin;
    policyFile = isolatedPolicy;
    try {
    const active = await activate();
    const prepared = await prepare(active);
    const originalPrepare = await db.selectFrom('license_operations').selectAll()
      .where('operation_id', '=', prepared.prepareOperationId).executeTakeFirstOrThrow();
    const planId = decodeJwt(prepared.ticket)['plan_id'] as string;
    const b = await runtime.createOnlineKey();
    await publishAndRotateTo(db, runtime, b, '2');

    const revokedAt = Math.floor((await getDbNow(db)).getTime() / 1000);
    const revokedBundle = await runtime.createBundle('3', [
      { ...runtime.onlineKey.record, revoked_at: revokedAt }, b.record,
    ]);
    const service = runtime.createAdminService(db);
    const accept = {
      operationId: randomUUID(), expectedSignerRevision: '2', bundleJws: revokedBundle,
      reason: 'emergency revoke compromised A signing key',
    };
    const accepted = await service.acceptTrustBundle({
      ...accept,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: acceptSignerTrustBundleRequestDigest(accept),
    });
    expect(accepted).toMatchObject({ state: 'succeeded', signerRevision: '2' });
    expect(accepted.result['invalidated_prepared_plans']).toBe(1);
    const plan = await db.selectFrom('license_transfer_plans').selectAll()
      .where('plan_id', '=', planId).executeTakeFirstOrThrow();
    expect(plan).toMatchObject({ state: 'invalidated', ticket_jws: prepared.ticket });
    const events = await db.selectFrom('license_transfer_events').selectAll().where('plan_id', '=', planId).execute();
    expect(events.map((event) => event.kind)).toEqual(['prepared', 'invalidated']);
    expect(events[1]!.safe_details).toMatchObject({
      reason: 'signing_key_revoked_or_retired', signer_kid: runtime.onlineKey.kid,
    });
    expect(originalPrepare.response_jws).toBe(prepared.ticket);

    const lateCommit = await commit(prepared);
    expect(lateCommit.response.status).toBe(401);
    expect(lateCommit.response.json['error']).toEqual({ code: 'TRANSFER_TICKET_INVALID' });
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect(license.current_generation).toBe('1');
    expect((await db.selectFrom('license_operations').selectAll()
      .where('operation_id', '=', prepared.prepareOperationId).executeTakeFirstOrThrow()).response_jws).toBe(prepared.ticket);
    expect(trustBundleArtifactDigest(revokedBundle)).toBe(accepted.artifactSha256);
    } finally {
      await isolatedAdmin.close();
      await isolatedServer.stop();
      await isolatedDb.destroy();
      await isolatedRuntime.cleanup();
      db = previous.db;
      server = previous.server;
      runtime = previous.runtime;
      admin = previous.admin;
      policyFile = previous.policyFile;
    }
  });

  it('prevents A-to-B-to-A identity rollback while allowing a fresh C identity', async () => {
    const activeA = await activate();
    const identityB = await createIdentity();
    const preparedB = await prepare(activeA, identityB);
    expect((await commit(preparedB)).response.status).toBe(200);
    const activeB = { ...activeA, source: identityB };
    const identityA = activeA.source;
    const rejected = await approve(activeB, identityA);
    expect(rejected.state).toBe('rejected');
    expect(rejected.outcomeCode).toBe('TRANSFER_TARGET_IDENTITY_WAS_USED');
    const identityC = await createIdentity();
    const preparedC = await prepare(activeB, identityC);
    expect((await commit(preparedC)).response.status).toBe(200);
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', activeA.licenseId).executeTakeFirstOrThrow();
    expect(license.current_generation).toBe('3');
    expect(await db.selectFrom('license_activations').selectAll().where('license_id', '=', activeA.licenseId)
      .where('state', '=', 'active').execute()).toMatchObject([expect.objectContaining({ identity_jkt: identityC.jkt, database_id: activeA.databaseId })]);
  });

  it('revokes a prepared approval immutably, invalidates its ticket, and permits a new target approval', async () => {
    const active = await activate();
    const targetB = await createIdentity();
    const preparedB = await prepare(active, targetB);
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const request = { operationId: randomUUID(), licenseId: active.licenseId, approvalId: preparedB.approvalId,
      expectedRevision: license.revision.toString(), reason: '取消尚未提交的迁移审批' };
    const revoked = await admin.revokeTransferApproval({ ...request,
      confirmedRequestDigest: revokeTransferApprovalRequestDigest(request) });
    expect(revoked.state).toBe('succeeded');
    const lateCommit = await commit(preparedB);
    expect(lateCommit.response.status).toBe(409);
    expect((await db.selectFrom('license_transfer_plans').selectAll().where('plan_id', '=', decodeJwt(preparedB.ticket)['plan_id'] as string)
      .executeTakeFirstOrThrow()).state).toBe('invalidated');
    const targetC = await createIdentity();
    const preparedC = await prepare(active, targetC);
    expect((await commit(preparedC)).response.status).toBe(200);
    expect(await db.selectFrom('license_transfer_revocations').selectAll().where('approval_id', '=', preparedB.approvalId).execute())
      .toHaveLength(1);
    expect(await db.selectFrom('license_admin_audit_events').selectAll().where('operation_id', '=', request.operationId).execute())
      .toMatchObject([expect.objectContaining({ action: 'transfer_revoke', state: 'succeeded' })]);
  });

  it('recovers an approval revocation after COMMIT acknowledgement loss and retries a rolled-back revocation under the same operation id', async () => {
    const active = await activate();
    const target = await createIdentity();
    const prepared = await prepare(active, target);
    const before = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const proxy = new CommitAckDropProxy();
    const parsed = new URL(runtime.config.databaseUrl);
    await proxy.start(parsed.hostname, Number(parsed.port || '5432'));
    const proxyUrl = new URL(runtime.config.databaseUrl);
    proxyUrl.port = String(proxy.port);
    proxyUrl.searchParams.set('sslmode', 'disable');
    const proxyPolicy = await writeAdminPolicy(proxyUrl.toString());
    const proxyAdmin = await createAdminService(proxyPolicy);
    const request = { operationId: randomUUID(), licenseId: active.licenseId, approvalId: prepared.approvalId,
      expectedRevision: before.revision, reason: 'COMMIT确认丢失后恢复原审批撤销' };
    const digest = revokeTransferApprovalRequestDigest(request);
    try {
      const droppedAck = proxy.armNextCommitAckDrop();
      const result = await proxyAdmin.revokeTransferApproval({ ...request, confirmedRequestDigest: digest });
      await droppedAck;
      expect(result).toMatchObject({ state: 'succeeded', replayed: true, requestDigest: digest });
      expect(await db.selectFrom('license_transfer_revocations').selectAll().where('approval_id', '=', prepared.approvalId).execute()).toHaveLength(1);
      expect(await db.selectFrom('license_admin_operations').selectAll().where('operation_id', '=', request.operationId).execute()).toHaveLength(1);
      expect(await db.selectFrom('license_admin_audit_events').selectAll().where('operation_id', '=', request.operationId).execute()).toHaveLength(1);
      await expect(proxyAdmin.revokeTransferApproval({ ...request, reason: '不同摘要重复撤销',
        confirmedRequestDigest: revokeTransferApprovalRequestDigest({ ...request, reason: '不同摘要重复撤销' }) }))
        .rejects.toMatchObject({ code: 'ADMIN_OPERATION_ID_CONFLICT' });
      const staleCommit = await commit(prepared);
      expect(staleCommit.response.status).toBe(409);
      const after = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
      expect([after.revision, after.entitlement_revision, after.current_generation])
        .toEqual([before.revision, before.entitlement_revision, before.current_generation]);
      expect((await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId)
        .where('state', '=', 'active').executeTakeFirstOrThrow()).identity_jkt).toBe(active.source.jkt);
      expect((await db.selectFrom('license_transfer_plans').selectAll().where('approval_id', '=', prepared.approvalId)
        .executeTakeFirstOrThrow()).state).toBe('invalidated');
    } finally {
      await proxyAdmin.close();
      await proxy.stop();
    }

    const nextTarget = await createIdentity();
    const approval = await approve(active, nextTarget);
    const retry = { operationId: randomUUID(), licenseId: active.licenseId, approvalId: approval.operationId,
      expectedRevision: before.revision, reason: '回滚后使用原操作身份安全重试' };
    await sql`CREATE OR REPLACE FUNCTION transfer_test_fail_revocation() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'forced revocation rollback' USING ERRCODE = 'P0001'; END $$`.execute(db);
    await sql`CREATE TRIGGER transfer_test_fail_revocation BEFORE INSERT ON license_transfer_revocations
      FOR EACH ROW EXECUTE FUNCTION transfer_test_fail_revocation()`.execute(db);
    try {
      await expect(admin.revokeTransferApproval({ ...retry, confirmedRequestDigest: revokeTransferApprovalRequestDigest(retry) }))
        .rejects.toThrow();
      expect(await db.selectFrom('license_transfer_revocations').selectAll().where('approval_id', '=', approval.operationId).execute()).toHaveLength(0);
      expect(await db.selectFrom('license_admin_operations').selectAll().where('operation_id', '=', retry.operationId).execute()).toHaveLength(0);
    } finally {
      await sql`DROP TRIGGER IF EXISTS transfer_test_fail_revocation ON license_transfer_revocations`.execute(db);
      await sql`DROP FUNCTION IF EXISTS transfer_test_fail_revocation()`.execute(db);
    }
    const retried = await admin.revokeTransferApproval({ ...retry, confirmedRequestDigest: revokeTransferApprovalRequestDigest(retry) });
    expect(retried.state).toBe('succeeded');
    expect(await db.selectFrom('license_transfer_revocations').selectAll().where('approval_id', '=', approval.operationId).execute()).toHaveLength(1);
  });

  it('serializes approval revocation and commit in both forced PostgreSQL lock acquisition orders', async () => {
    async function holdLicenseRow(licenseId: string) {
      let ready!: () => void;
      let release!: () => void;
      const readySignal = new Promise<void>((resolve) => { ready = resolve; });
      const released = new Promise<void>((resolve) => { release = resolve; });
      const blocker = db.transaction().execute(async (trx) => {
        await trx.selectFrom('licenses').select('id').where('id', '=', licenseId).forUpdate().executeTakeFirstOrThrow();
        ready();
        await released;
      });
      await readySignal;
      return { blocker, release };
    }
    async function ordered(active: ActiveSource, revokeFirst: boolean) {
      const target = await createIdentity();
      const prepared = await prepare(active, target);
      const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
      const request = { operationId: randomUUID(), licenseId: active.licenseId, approvalId: prepared.approvalId,
        expectedRevision: license.revision.toString(), reason: `锁顺序场景 ${revokeFirst ? 'revoke-first' : 'commit-first'}` };
      const blocker = await holdLicenseRow(active.licenseId);
      let revokePromise: ReturnType<typeof admin.revokeTransferApproval> | undefined;
      let commitPromise: ReturnType<typeof commit> | undefined;
      try {
        if (revokeFirst) {
          revokePromise = admin.revokeTransferApproval({ ...request, confirmedRequestDigest: revokeTransferApprovalRequestDigest(request) });
          await waitForLicenseRowWaiters(db, 1);
          commitPromise = commit(prepared);
          await waitForLicenseRowWaiters(db, 2);
        } else {
          commitPromise = commit(prepared);
          await waitForLicenseRowWaiters(db, 1);
          revokePromise = admin.revokeTransferApproval({ ...request, confirmedRequestDigest: revokeTransferApprovalRequestDigest(request) });
          await waitForLicenseRowWaiters(db, 2);
        }
      } finally {
        blocker.release();
      }
      await blocker.blocker;
      const [revoked, committed] = await Promise.all([revokePromise!, commitPromise!]);
      const finalLicense = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
      const plans = await db.selectFrom('license_transfer_plans').selectAll().where('approval_id', '=', prepared.approvalId).execute();
      const activeRows = await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId).where('state', '=', 'active').execute();
      if (revokeFirst) {
        expect(revoked.state).toBe('succeeded');
        expect(committed.response.status).toBe(409);
        expect(plans[0]!.state).toBe('invalidated');
        expect(finalLicense.current_generation).toBe('1');
        expect(activeRows).toMatchObject([expect.objectContaining({ identity_jkt: active.source.jkt })]);
        expect(await db.selectFrom('license_transfer_revocations').selectAll().where('approval_id', '=', prepared.approvalId).execute()).toHaveLength(1);
        expect((await db.selectFrom('license_operations').selectAll().where('operation_id', '=', committed.operationId).executeTakeFirstOrThrow()).state).toBe('rejected');
        expect(await db.selectFrom('license_transfer_events').selectAll().where('approval_id', '=', prepared.approvalId)
          .where('kind', '=', 'approval_revoked').execute()).toHaveLength(1);
      } else {
        expect(committed.response.status).toBe(200);
        expect(revoked.state).toBe('rejected');
        expect(revoked.outcomeCode).toBe('EXPECTED_REVISION_MISMATCH');
        expect(plans[0]!.state).toBe('committed');
        expect(finalLicense.current_generation).toBe('2');
        expect(activeRows).toMatchObject([expect.objectContaining({ identity_jkt: target.jkt, generation: '2' })]);
        expect((await db.selectFrom('license_activations').selectAll().where('id', '=', plans[0]!.source_activation_id)
          .executeTakeFirstOrThrow()).state).toBe('retired');
        expect((await verifyCenterJwt(committed.response.json['transfer_receipt'] as string)).protectedHeader['typ'])
          .toBe('aikayun-license-transfer+jwt');
        expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', committed.operationId).execute()).toHaveLength(1);
        expect(await db.selectFrom('license_transfer_events').selectAll().where('approval_id', '=', prepared.approvalId)
          .where('kind', '=', 'committed').execute()).toHaveLength(1);
        expect(await db.selectFrom('license_transfer_revocations').selectAll().where('approval_id', '=', prepared.approvalId).execute()).toHaveLength(0);
        const replay = await commit(prepared, { operationId: committed.operationId, attemptNo: 2 });
        expect(replay.response.json['transfer_receipt']).toBe(committed.response.json['transfer_receipt']);
      }
    }
    await ordered(await activate(), true);
    await ordered(await activate(), false);
  });

  it('a ticket that expires before commit leaves the source activation untouched', async () => {
    const active = await activate();
    const target = await createIdentity();
    const approvalResult = await approve(active, target);
    const approval = await db.selectFrom('license_transfer_approvals').selectAll()
      .where('approval_id', '=', approvalResult.operationId).executeTakeFirstOrThrow();
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const source = await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', active.licenseId).where('state', '=', 'active').executeTakeFirstOrThrow();
    const prepareOperationId = randomUUID();
    const prepareIntentDigest = transferPrepareIntentDigest({
      licenseId: active.licenseId, databaseId: active.databaseId, instanceId: active.instanceId,
      sourceIdentityJkt: active.source.jkt, targetInstanceId: active.instanceId, targetIdentityJkt: target.jkt,
      approvalId: approval.approval_id, sourceGeneration: source.generation.toString(),
      expectedBindingRevision: approval.expected_binding_revision.toString(), expectedRevision: license.revision.toString(),
    });
    const prepareRequestNonce = randomBytes(32).toString('base64url');
    const prepareRequestDigest = sha256(randomUUID());
    const issuedAt = Math.floor((await getDbNow(db)).getTime() / 1000) - 20 * 60;
    const ticket = await signTransferTicket(runtime.config, {
      plan_id: randomUUID(), approval_operation_id: approval.approval_id, prepare_operation_id: prepareOperationId,
      prepare_intent_digest: prepareIntentDigest, prepare_request_nonce: prepareRequestNonce, prepare_request_digest: prepareRequestDigest,
      license_id: active.licenseId, database_id: active.databaseId,
      source_instance_id: active.instanceId, source_identity_jkt: active.source.jkt, source_activation_generation: '1',
      target_instance_id: active.instanceId, target_identity_jkt: target.jkt,
      expected_binding_revision: approval.expected_binding_revision.toString(), expected_revision: license.revision.toString(),
      entitlement_revision: license.entitlement_revision.toString(), now: new Date(issuedAt * 1000),
    });
    const planId = decodeJwt(ticket)['plan_id'] as string;
    const expiry = new Date((issuedAt + 600) * 1000);
    await db.insertInto('license_operations').values({
      operation_id: prepareOperationId, actor_jkt: active.source.jkt, intent_digest: prepareIntentDigest,
      kind: 'transfer_prepare', license_id: active.licenseId, database_id: active.databaseId,
      state: 'committed', outcome_code: 'TRANSFER_PREPARED', response_type: 'operation', result_generation: '1',
      result_revision: license.entitlement_revision.toString(), response_jws: ticket, result_digest: sha256(ticket),
      created_at: new Date(issuedAt * 1000), finalized_at: new Date(issuedAt * 1000),
    }).execute();
    await db.insertInto('license_operation_attempts').values({
      attempt_id: randomUUID(), operation_id: prepareOperationId, attempt_no: 1, intent_digest: prepareIntentDigest,
      body_digest: prepareRequestDigest, client_nonce_hash: sha256(randomUUID()), server_nonce_hash: sha256(prepareRequestNonce),
      identity_jkt: active.source.jkt, signature_created_at: new Date(issuedAt * 1000),
      received_at: new Date(issuedAt * 1000), outcome: 'accepted', error_code: null,
    }).execute();
    await db.insertInto('license_transfer_plans').values({
      plan_id: planId, license_id: active.licenseId, approval_id: approval.approval_id,
      prepare_operation_id: prepareOperationId, prepare_intent_digest: prepareIntentDigest,
      source_activation_id: source.id, database_id: active.databaseId, source_instance_id: active.instanceId,
      source_identity_jkt: active.source.jkt, target_instance_id: active.instanceId, target_identity_jkt: target.jkt,
      target_identity_jwk_public: target.publicJwk, source_generation: '1',
      expected_binding_revision: approval.expected_binding_revision.toString(), expected_revision: license.revision.toString(),
      entitlement_revision: license.entitlement_revision.toString(), ticket_jws: ticket, ticket_digest: sha256(ticket),
      state: 'prepared', expires_at: expiry, created_at: new Date(issuedAt * 1000), committed_at: null,
      commit_operation_id: null, committed_generation: null, transfer_receipt_jws: null,
    }).execute();
    const prepared: PreparedTransfer = {
      active, target, approval: approvalResult, approvalId: approval.approval_id,
      prepareOperationId, prepareIntentDigest, ticket,
    };
    const result = await commit(prepared);
    expect(result.response.status).toBe(409);
    expect((await verifyCenterJwt(result.response.json['operation_receipt'] as string)).payload['outcome_code']).toBe('TRANSFER_TICKET_EXPIRED');
    expect((await db.selectFrom('license_transfer_plans').selectAll().where('plan_id', '=', planId).executeTakeFirstOrThrow()).state).toBe('expired');
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');
    expect((await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', active.licenseId).where('state', '=', 'active').executeTakeFirstOrThrow()).identity_jkt).toBe(active.source.jkt);
  });

  it('one transfer plan wins when two destinations compete for the same license', async () => {
    const active = await activate();
    const targets = [await createIdentity(), await createIdentity()];
    const approvals = await Promise.all(targets.map((target) => approve(active, target)));
    expect(approvals.filter((result) => result.state === 'succeeded')).toHaveLength(1);
    expect(approvals.filter((result) => result.state === 'rejected')).toHaveLength(1);
    const winnerIndex = approvals.findIndex((result) => result.state === 'succeeded');
    const loserIndex = 1 - winnerIndex;
    const attempts = await Promise.all(targets.map(async (target, index) => {
      const prepared = await makePrepareAttempt(active, target, approvals[index]!.operationId);
      return { ...prepared, response: await sendPrepare(prepared.attempt, active.source) };
    }));
    expect(attempts[winnerIndex]!.response.status).toBe(200);
    expect(attempts[loserIndex]!.response.status).toBe(403);
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', attempts[loserIndex]!.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', attempts[loserIndex]!.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', attempts[loserIndex]!.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_transfer_plans').selectAll().where('license_id', '=', active.licenseId).execute()).toHaveLength(1);
    const winnerTicket = attempts[winnerIndex]!.response.json['transfer_ticket'];
    if (typeof winnerTicket !== 'string') throw new Error('Winning transfer ticket missing');
    const prepared: PreparedTransfer = {
      active, target: targets[winnerIndex]!, approval: approvals[winnerIndex]!, approvalId: approvals[winnerIndex]!.operationId,
      prepareOperationId: attempts[winnerIndex]!.operationId, prepareIntentDigest: attempts[winnerIndex]!.intentDigest, ticket: winnerTicket,
    };
    expect((await commit(prepared)).response.status).toBe(200);
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
  });

  it('serializes commit against revoke and rejects an approval made stale by revoke then restore', async () => {
    const active = await activate();
    const prepared = await prepare(active);
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const revokeInput = { operationId: randomUUID(), licenseId: active.licenseId, expectedRevision: license.revision.toString(), reason: '人工确认撤销竞争测试' };
    const revoke = admin.revokeLicense({ ...revokeInput, confirmedRequestDigest: changeLicenseStatusRequestDigest(revokeInput, 'license_revoke') });
    const transfer = commit(prepared);
    const [revoked, committed] = await Promise.all([revoke, transfer]);
    const afterRace = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    if (committed.response.status === 200) {
      expect(afterRace.current_generation).toBe('2');
      expect(afterRace.status).toBe('active');
      expect(revoked.state).toBe('rejected');
      expect(revoked.outcomeCode).toBe('EXPECTED_REVISION_MISMATCH');
    } else {
      expect(afterRace.current_generation).toBe('1');
      expect(afterRace.status).toBe('revoked');
      expect(revoked.state).toBe('succeeded');
      const restoreInput = { operationId: randomUUID(), licenseId: active.licenseId,
        expectedRevision: afterRace.revision.toString(), reason: '人工确认恢复竞争测试' };
      const restored = await admin.restoreLicense({ ...restoreInput,
        confirmedRequestDigest: changeLicenseStatusRequestDigest(restoreInput, 'license_restore') });
      expect(restored.state).toBe('succeeded');
      const retry = await commit(prepared);
      expect(retry.response.status).toBe(409);
      expect(['TRANSFER_TICKET_CONSUMED', 'TRANSFER_REVISION_CONFLICT']).toContain(
        (await verifyCenterJwt(retry.response.json['operation_receipt'] as string)).payload['outcome_code']);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');
    }
  });

  it('a renewal that races the commit cannot bypass the approved management revision', async () => {
    const active = await activate();
    const prepared = await prepare(active);
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const renewInput = { operationId: randomUUID(), licenseId: active.licenseId,
      expectedRevision: license.revision.toString(), reason: '人工核实续费与迁移竞争', businessReference: `test-${randomUUID()}` };
    const renewal = admin.renewLicense({ ...renewInput, confirmedRequestDigest: renewLicenseRequestDigest(renewInput) });
    const transfer = commit(prepared);
    const [renewed, committed] = await Promise.all([renewal, transfer]);
    const final = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    if (committed.response.status === 200) {
      expect(final.current_generation).toBe('2');
      expect(renewed.state).toBe('rejected');
      expect(renewed.outcomeCode).toBe('EXPECTED_REVISION_MISMATCH');
    } else {
      expect(final.current_generation).toBe('1');
      expect(renewed.state).toBe('succeeded');
      expect(final.entitlement_revision).toBe(decimalPlusOne(license.entitlement_revision));
      expect((await verifyCenterJwt(committed.response.json['operation_receipt'] as string)).payload['outcome_code'])
        .toBe('TRANSFER_REVISION_CONFLICT');
    }
  });

  it('restoring a revoked license cannot revive its pre-revoke approval or prepared ticket', async () => {
    const active = await activate();
    const prepared = await prepare(active);
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const revokeInput = { operationId: randomUUID(), licenseId: active.licenseId,
      expectedRevision: license.revision.toString(), reason: '停用测试迁移后进行恢复' };
    expect((await admin.revokeLicense({ ...revokeInput,
      confirmedRequestDigest: changeLicenseStatusRequestDigest(revokeInput, 'license_revoke') })).state).toBe('succeeded');
    const revoked = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const restoreInput = { operationId: randomUUID(), licenseId: active.licenseId,
      expectedRevision: revoked.revision.toString(), reason: '人工确认恢复，不恢复旧迁移审批' };
    const restoring = admin.restoreLicense({ ...restoreInput,
      confirmedRequestDigest: changeLicenseStatusRequestDigest(restoreInput, 'license_restore') });
    const committing = commit(prepared);
    const [restoreResult, commitResult] = await Promise.all([restoring, committing]);
    expect(restoreResult.state).toBe('succeeded');
    expect(commitResult.response.status).toBe(409);
    expect(['LICENSE_REVOKED', 'TRANSFER_REVISION_CONFLICT']).toContain(
      (await verifyCenterJwt(commitResult.response.json['operation_receipt'] as string)).payload['outcome_code']);
    const final = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect(final.status).toBe('active');
    expect(final.current_generation).toBe('1');
    expect(final.revision).toBe(decimalPlusOne(revoked.revision.toString()));
    expect((await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', active.licenseId).where('state', '=', 'active').executeTakeFirstOrThrow()).identity_jkt)
      .toBe(active.source.jkt);
  });

  it('rolls back every transfer effect when a real mid-transaction insert fails, then resumes with a new challenge', async () => {
    const active = await activate();
    const prepared = await prepare(active);
    const commitOperationId = randomUUID();
    const { attempt, intentDigest } = await makeCommitAttempt(prepared, { operationId: commitOperationId });
    await sql`CREATE OR REPLACE FUNCTION transfer_test_force_insert_failure() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'forced isolated transfer rollback' USING ERRCODE = 'P0001'; END $$`.execute(db);
    await sql`CREATE TRIGGER transfer_test_force_insert_failure BEFORE INSERT ON license_activations
      FOR EACH ROW EXECUTE FUNCTION transfer_test_force_insert_failure()`.execute(db);
    try {
      const failed = await sendCommit(attempt, prepared.target);
      expect(failed.status).toBe(500);
      expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', commitOperationId).execute()).toHaveLength(0);
      expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', commitOperationId).execute()).toHaveLength(0);
      const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
      expect(license.current_generation).toBe('1');
      expect(license.revision).toBe(prepared.approval.resultRevision);
      expect(await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId).where('state', '=', 'active').execute())
        .toMatchObject([expect.objectContaining({ identity_jkt: active.source.jkt })]);
      expect((await db.selectFrom('license_transfer_plans').selectAll().where('license_id', '=', active.licenseId).executeTakeFirstOrThrow()).state)
        .toBe('prepared');
    } finally {
      await sql`DROP TRIGGER IF EXISTS transfer_test_force_insert_failure ON license_activations`.execute(db);
      await sql`DROP FUNCTION IF EXISTS transfer_test_force_insert_failure()`.execute(db);
    }
    const resumed = await makeCommitAttempt(prepared, { operationId: commitOperationId, attemptNo: 2 });
    expect(resumed.intentDigest).toBe(intentDigest);
    expect((await sendCommit(resumed.attempt, prepared.target)).status).toBe(200);
    const attempts = await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', commitOperationId)
      .orderBy('attempt_no', 'asc').execute();
    expect(attempts.map((entry) => entry.attempt_no)).toEqual([2]);
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
  });

  it('recovers committed transfer after a dropped HTTP response and resolves a PostgreSQL COMMIT acknowledgement loss by operation query', async () => {
    const active = await activate();
    const prepared = await prepare(active);
    const httpProxy = new HttpResponseDropProxy();
    await httpProxy.start(server.port, runtime.config.tlsPrivateKey, runtime.config.tlsCertificate);
    try {
      const lostAttempt = await makeCommitAttempt(prepared, { requestServer: { port: httpProxy.port } });
      const dropped = httpProxy.armNextResponseDrop();
      const request = sendCommit(lostAttempt.attempt, prepared.target, { port: httpProxy.port }).catch((error: unknown) => error);
      await dropped;
      await request;
      const durable = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', lostAttempt.operationId).executeTakeFirstOrThrow();
      expect(durable.state).toBe('committed');
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
      const query = await queryOperation(prepared, lostAttempt.operationId, lostAttempt.intentDigest, 2);
      expect(query.status).toBe(200);
      const operationReceipt = await verifyCenterJwt(query.json['operation_receipt'] as string);
      expect(operationReceipt.payload).toMatchObject({ state: 'committed', operation_id: lostAttempt.operationId, result_jws: durable.response_jws });
    } finally {
      await httpProxy.stop();
    }

    const active2 = await activate();
    const prepared2 = await prepare(active2);
    const pgProxy = new CommitAckDropProxy();
    const databaseUrl = new URL(runtime.config.databaseUrl);
    await pgProxy.start(databaseUrl.hostname, Number(databaseUrl.port || '5432'));
    const proxyUrl = new URL(runtime.config.databaseUrl);
    proxyUrl.port = String(pgProxy.port);
    proxyUrl.searchParams.set('sslmode', 'disable');
    const proxyDb = createDatabase(proxyUrl.toString(), 4);
    const proxyServer = await startAppServer(createApp({ config: runtime.config, db: proxyDb }));
    try {
      const commitAttempt = await makeCommitAttempt(prepared2, { requestServer: proxyServer });
      const droppedAck = pgProxy.armNextCommitAckDrop(1);
      const lost = sendCommit(commitAttempt.attempt, prepared2.target, proxyServer);
      await droppedAck;
      expect((await lost).status).toBe(500);
      const committedRow = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', commitAttempt.operationId).executeTakeFirstOrThrow();
      expect(committedRow.state).toBe('committed');
      expect((await db.selectFrom('license_activations').selectAll().where('license_id', '=', active2.licenseId).where('state', '=', 'active').execute()))
        .toMatchObject([expect.objectContaining({ identity_jkt: prepared2.target.jkt, generation: '2' })]);
      await proxyServer.stop();
      await proxyDb.destroy();
      const query = await queryOperation(prepared2, commitAttempt.operationId, commitAttempt.intentDigest, 2);
      expect(query.status).toBe(200);
      expect((await verifyCenterJwt(query.json['operation_receipt'] as string)).payload['result_jws']).toBe(committedRow.response_jws);
      const replay = await commit(prepared2, { operationId: commitAttempt.operationId, attemptNo: 3 });
      expect(replay.response.status).toBe(200);
      expect(replay.response.json['transfer_receipt']).toBe(committedRow.response_jws);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active2.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
    } finally {
      await proxyServer.stop().catch(() => undefined);
      await proxyDb.destroy().catch(() => undefined);
      await pgProxy.stop();
    }
  });

  it('a killed server transaction rolls back cleanly and the same operation resumes after restart', async () => {
    const active = await activate();
    const prepared = await prepare(active);
    const blockerReady = deferred<void>();
    const releaseBlocker = deferred<void>();
    const blocker = db.transaction().execute(async (trx) => {
      await trx.selectFrom('licenses').select('id').where('id', '=', active.licenseId).forUpdate().executeTakeFirstOrThrow();
      blockerReady.resolve();
      await releaseBlocker.promise;
    });
    await blockerReady.promise;
    let child: Awaited<ReturnType<typeof startChildLicenseServer>> | undefined;
    let restarted: Awaited<ReturnType<typeof startChildLicenseServer>> | undefined;
    const commitOperationId = randomUUID();
    try {
      child = await startChildLicenseServer({
        databaseUrl: runtime.config.databaseUrl, issuer: runtime.config.issuer, publicOrigin: runtime.config.publicOrigin,
        keyringFile: runtime.keyringFile, offlineRootJwkFile: runtime.offlineRootJwkFile,
        minimumTrustBundleVersion: runtime.config.minimumTrustBundleVersion,
        tlsKeyFile: runtime.config.tlsKeyFile, tlsCertFile: runtime.config.tlsCertFile,
      });
      const first = await makeCommitAttempt(prepared, { operationId: commitOperationId, requestServer: child });
      const response = sendCommit(first.attempt, prepared.target, child).catch((error: unknown) => error);
      const [pid] = await waitForLicenseRowWaiterPids(db, 1);
      if (pid === undefined) throw new Error('Expected a PostgreSQL lock waiter for transfer commit');
      await child.stop('SIGKILL');
      await terminatePostgresBackend(db, pid);
      await waitForNoLockWaiters(db);
      const lost = await response;
      expect(lost instanceof Error || (lost as HttpResponse).status >= 500).toBe(true);
      expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', commitOperationId).execute()).toHaveLength(0);
      expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', commitOperationId).execute()).toHaveLength(0);
      expect((await db.selectFrom('request_nonces').selectAll()
        .where('nonce_hash', '=', sha256(first.attempt.nonce)).executeTakeFirstOrThrow()).consumed_at).toBeNull();
      expect((await db.selectFrom('license_transfer_plans').selectAll().where('license_id', '=', active.licenseId).executeTakeFirstOrThrow()).state)
        .toBe('prepared');
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');
      releaseBlocker.resolve();
      await blocker;
      restarted = await startChildLicenseServer({
        databaseUrl: runtime.config.databaseUrl, issuer: runtime.config.issuer, publicOrigin: runtime.config.publicOrigin,
        keyringFile: runtime.keyringFile, offlineRootJwkFile: runtime.offlineRootJwkFile,
        minimumTrustBundleVersion: runtime.config.minimumTrustBundleVersion,
        tlsKeyFile: runtime.config.tlsKeyFile, tlsCertFile: runtime.config.tlsCertFile,
      });
      const retry = await makeCommitAttempt(prepared, { operationId: commitOperationId, attemptNo: 2, requestServer: restarted });
      expect((await sendCommit(retry.attempt, prepared.target, restarted)).status).toBe(200);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
    } finally {
      releaseBlocker.resolve();
      await blocker.catch(() => undefined);
      await child?.stop().catch(() => undefined);
      await restarted?.stop().catch(() => undefined);
    }
  });

  it('cannot substitute a source identity across licenses or violate the active instance uniqueness index', async () => {
    const sourceA = await activate();
    const sourceB = await activate();
    const targetB = await createIdentity();
    const approvalB = await approve(sourceB, targetB);
    const crossLicense = await makePrepareAttempt(sourceA, targetB, approvalB.operationId, {
      licenseId: sourceB.licenseId, databaseId: sourceB.databaseId,
    });
    const response = await sendPrepare(crossLicense.attempt, sourceA.source);
    expect(response.status).toBe(403);
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', crossLicense.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', crossLicense.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', crossLicense.operationId).execute()).toHaveLength(0);
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', sourceB.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');

    const thirdLicense = await createLicense(db);
    const existing = await db.selectFrom('license_activations').selectAll().where('license_id', '=', sourceA.licenseId).executeTakeFirstOrThrow();
    await expect(db.insertInto('license_activations').values({
      id: randomUUID(), license_id: thirdLicense.id, generation: '1', instance_id: existing.instance_id,
      database_id: randomUUID(), identity_jwk_public: (await createIdentity()).publicJwk, identity_jkt: randomUUID(),
      state: 'active', activated_at: await getDbNow(db), retired_at: null, last_seen_at: await getDbNow(db), origin_display: null,
    }).execute()).rejects.toMatchObject({ code: '23505' });
  });

  it('keeps reset evidence scoped to its activation generation across a real transfer', async () => {
    const active = await activate();
    const activation = await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', active.licenseId).where('state', '=', 'active').executeTakeFirstOrThrow();
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const timeApprovalId = randomUUID();
    const resetOperationId = randomUUID();
    const oldWatermarkDigest = randomBytes(32).toString('base64url');
    const generation = activation.generation.toString();
    const revision = license.revision.toString();
    const entitlementRevision = license.entitlement_revision.toString();
    const expectedTimeEpoch = activation.time_epoch.toString();
    const intentDigest = timeResetIntentDigest({
      operationId: resetOperationId, approvalId: timeApprovalId, licenseId: active.licenseId,
      databaseId: active.databaseId, instanceId: active.instanceId, identityJkt: active.source.jkt,
      activationId: activation.id, activationGeneration: generation, expectedRevision: revision,
      entitlementRevision, expectedTimeEpoch, oldWatermarkDigest,
    });
    const timeApprovalRequest = {
      operationId: timeApprovalId,
      licenseId: active.licenseId,
      expectedRevision: revision,
      reason: '人工核验旧实例时钟并批准单次水位恢复',
      activationId: activation.id,
      databaseId: active.databaseId,
      instanceId: active.instanceId,
      identityJkt: active.source.jkt,
      activationGeneration: generation,
      entitlementRevision,
      expectedTimeEpoch,
      resetOperationId,
      intentDigest,
      oldWatermarkDigest,
    };
    const timeApproval = await admin.approveTimeReset({
      ...timeApprovalRequest,
      confirmedRequestDigest: approveTimeResetRequestDigest(timeApprovalRequest),
    });
    expect(timeApproval.state).toBe('succeeded');
    const challenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: active.source, operation: 'time_reset',
      operationId: resetOperationId, intentDigest, instanceId: active.instanceId,
    });
    const resetBody = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId: resetOperationId, intentDigest, attemptNo: 1,
        instanceId: active.instanceId, identity: active.source, licenseId: active.licenseId, databaseId: active.databaseId,
      }),
      activation_id: activation.id,
      approval_id: timeApprovalId,
      expected_generation: generation,
      expected_revision: revision,
      expected_entitlement_revision: entitlementRevision,
      expected_time_epoch: expectedTimeEpoch,
      old_watermark_digest: oldWatermarkDigest,
    };
    const resetResponse = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit',
      body: resetBody, identity: active.source, nonce: challengeNonce(challenge.token),
    });
    expect(resetResponse.status).toBe(200);
    const resetReceipt = resetResponse.json['time_reset_receipt'];
    if (typeof resetReceipt !== 'string') throw new Error('Time reset receipt missing');

    const target = await createIdentity();
    const transferApproval = await approve(active, target);
    const prepareAttempt = await makePrepareAttempt(active, target, transferApproval.operationId);
    const prepareResponse = await sendPrepare(prepareAttempt.attempt, active.source);
    expect(prepareResponse.status).toBe(200);
    const ticket = prepareResponse.json['transfer_ticket'];
    if (typeof ticket !== 'string') throw new Error('Transfer ticket missing');
    const prepared: PreparedTransfer = {
      active, target, approval: transferApproval, approvalId: transferApproval.operationId,
      prepareOperationId: prepareAttempt.operationId, prepareIntentDigest: prepareAttempt.intentDigest, ticket,
    };
    const moved = await commit(prepared);
    expect(moved.response.status).toBe(200);
    expect((await db.selectFrom('licenses').select('current_generation').where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
    const historical = await queryOperation(prepared, moved.operationId, moved.intentDigest, 2);
    expect(historical.status).toBe(200);
    const historicalReceipt = await verifyCenterJwt(historical.json['operation_receipt'] as string);
    expect(historicalReceipt.payload).toMatchObject({ state: 'committed', operation_id: moved.operationId, result_jws: moved.response.json['transfer_receipt'] });
    const transferReplay = await commit(prepared, { operationId: moved.operationId, attemptNo: 3 });
    expect(transferReplay.response.status).toBe(200);
    expect(transferReplay.response.json['transfer_receipt']).toBe(moved.response.json['transfer_receipt']);
    expect((await db.selectFrom('licenses').select('current_generation').where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
    const activationRows = await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', active.licenseId).orderBy('generation', 'asc').execute();
    expect(activationRows).toHaveLength(2);
    expect(activationRows[0]).toMatchObject({ state: 'retired', generation: '1', time_epoch: '1' });
    expect(activationRows[1]).toMatchObject({ state: 'active', generation: '2', identity_jkt: target.jkt, time_epoch: '0' });

    const trustedServerTime = Math.floor((await getDbNow(db)).getTime() / 1000);
    await expect(verifyTimeResetReceipt(resetReceipt, {
      resolver: (await loadTrustedSigningContext(db, runtime.config)).context.resolver,
      issuer: runtime.config.issuer, trustedServerTime,
      expected: {
        license_id: active.licenseId, database_id: active.databaseId, instance_id: active.instanceId,
        identity_jkt: target.jkt, activation_generation: '2', management_revision: revision,
        entitlement_revision: entitlementRevision, old_time_epoch: '0', new_time_epoch: '1',
        old_watermark_digest: oldWatermarkDigest, operation_id: resetOperationId, intent_digest: intentDigest,
        request_nonce: challengeNonce(challenge.token), client_nonce: decodeJwt(challenge.token)['client_nonce'] as string,
        request_digest: sha256(JSON.stringify(resetBody)), admin_approval_id: timeApprovalId,
        admin_operation_id: timeApproval.operationId, admin_approval_digest: timeApproval.requestDigest,
      },
    })).rejects.toThrow();

    const staleReplayChallenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: active.source, operation: 'time_reset',
      operationId: resetOperationId, intentDigest, instanceId: active.instanceId,
    });
    const staleReplayBody = { ...resetBody, challenge: staleReplayChallenge.token, attempt_no: 2 };
    const staleReplay = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit',
      body: staleReplayBody, identity: active.source, nonce: challengeNonce(staleReplayChallenge.token),
    });
    expect(staleReplay.status).toBe(403);
    expect(staleReplay.json['error']).toEqual({ code: 'TIME_RESET_INSTANCE_BINDING_MISMATCH' });
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', resetOperationId).execute()).toHaveLength(1);
  });

  it('rejects a normal transfer Commit after its approval expires while the prepared ticket is still fresh', async () => {
    const active = await activate();
    const target = await createIdentity();
    const base = await getDbNow(db);
    const historicalApprovalTime = new Date(base.getTime() - 23 * 60 * 60 * 1000 - 59 * 60 * 1000 - 40 * 1000);
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const approvalRequest: Omit<ApproveTransferRequest, 'confirmedRequestDigest'> = {
      operationId: randomUUID(), licenseId: active.licenseId, expectedRevision: license.revision.toString(),
      reason: '隔离历史fixture：审批有效期即将自然结束', databaseId: active.databaseId,
      sourceInstanceId: active.instanceId, sourceIdentityJkt: active.source.jkt,
      targetInstanceId: active.instanceId, targetIdentityJkt: target.jkt,
      sourceGeneration: license.current_generation.toString(), expectedBindingRevision: '7',
    };
    const historicalAdmin = await createAdminService(policyFile, { controlledTestNow: async () => historicalApprovalTime });
    try {
      const approval = await historicalAdmin.approveTransfer({ ...approvalRequest,
        confirmedRequestDigest: approveTransferRequestDigest(approvalRequest) });
      expect(approval.state).toBe('succeeded');
      const approvalRow = await db.selectFrom('license_transfer_approvals').selectAll()
        .where('approval_id', '=', approval.operationId).executeTakeFirstOrThrow();
      expect(approvalRow.expires_at.getTime()).toBe(base.getTime() + 20 * 1000);

      const prepareAttempt = await makePrepareAttempt(active, target, approval.operationId);
      const prepareResponse = await sendPrepare(prepareAttempt.attempt, active.source);
      expect(prepareResponse.status).toBe(200);
      const ticket = prepareResponse.json['transfer_ticket'];
      if (typeof ticket !== 'string') throw new Error('Transfer ticket missing');
      const prepared: PreparedTransfer = {
        active, target, approval, approvalId: approval.operationId,
        prepareOperationId: prepareAttempt.operationId, prepareIntentDigest: prepareAttempt.intentDigest, ticket,
      };
      await new Promise((resolve) => setTimeout(resolve, 25_000));
      const commitAttempt = await makeCommitAttempt(prepared);
      const response = await sendCommit(commitAttempt.attempt, target);
      expect(response.status).toBe(409);
      expect(typeof response.json['operation_receipt']).toBe('string');
      expect(response.json).not.toHaveProperty('transfer_receipt');
      expect(response.json).not.toHaveProperty('transfer_ticket');
      const rejected = await verifyCenterJwt(response.json['operation_receipt'] as string);
      expect(rejected.payload).toMatchObject({ state: 'rejected', outcome_code: 'TRANSFER_APPROVAL_EXPIRED' });
      const historicalReplayAttempt = await makeCommitAttempt(prepared, {
        operationId: commitAttempt.operationId, attemptNo: 2,
      });
      const historicalReplay = await sendCommit(historicalReplayAttempt.attempt, target);
      expect(historicalReplay.status).toBe(409);
      expect(historicalReplay.json['operation_receipt']).toBe(response.json['operation_receipt']);
      expect(historicalReplay.json).not.toHaveProperty('transfer_receipt');
      const plan = await db.selectFrom('license_transfer_plans').selectAll()
        .where('approval_id', '=', approval.operationId).executeTakeFirstOrThrow();
      expect(plan.state).toBe('invalidated');
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');
      expect(await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId)
        .where('state', '=', 'active').execute()).toMatchObject([expect.objectContaining({ identity_jkt: active.source.jkt })]);
      expect(await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId)
        .where('identity_jkt', '=', target.jkt).execute()).toHaveLength(0);
    } finally {
      await historicalAdmin.close();
    }
  });
});

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
