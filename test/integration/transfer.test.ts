import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { userInfo, tmpdir } from 'node:os';
import { join } from 'node:path';
import { sql, type Kysely } from 'kysely';
import { decodeJwt, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import {
  approveTransferRequestDigest,
  changeLicenseStatusRequestDigest,
  createAdminService,
  revokeTransferApprovalRequestDigest,
  renewLicenseRequestDigest,
  type ApproveTransferRequest,
  type AdminOperationResult,
} from '../../src/admin/service.js';
import { createDatabase, migrateToLatest } from '../../src/db/database.js';
import type { Database } from '../../src/db/types.js';
import { activationIntentDigest, renewalIntentDigest, transferCommitIntentDigest, transferPrepareIntentDigest } from '../../src/intent.js';
import { signTransferTicket } from '../../src/receipts.js';
import { createActivationCode, createLicense, getDbNow } from '../fixtures.js';
import { CommitAckDropProxy } from '../support/postgres-proxy.js';
import { HttpResponseDropProxy } from '../support/http-response-proxy.js';
import { terminatePostgresBackend, waitForLicenseRowWaiterPids, waitForNoLockWaiters } from '../support/pg-waits.js';
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

describe('normal license transfer over real PostgreSQL and HTTPS', () => {
  let db: Kysely<Database>;
  let server: RunningTestServer;
  let runtime: TestSigningRuntime;
  let admin: Awaited<ReturnType<typeof createAdminService>>;
  let scratchDirectory: string;
  let policyFile: string;

  async function verifyCenterJwt(token: string) {
    return jwtVerify(token, runtime.config.signingPublicKey, {
      algorithms: ['Ed25519'], issuer: runtime.config.issuer, audience: 'aikayun-commerce',
    });
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
    const approvalId = input.approvalId ?? prepared.approvalId;
    const prepareOperationId = input.prepareOperationId ?? prepared.prepareOperationId;
    const intentDigest = transferCommitIntentDigest({
      licenseId: prepared.active.licenseId, databaseId: prepared.active.databaseId,
      instanceId: prepared.active.instanceId, targetIdentityJkt: targetIdentity.jkt,
      approvalId, prepareOperationId, ticketDigest: sha256(ticket),
    });
    const requestServer = input.requestServer ?? server;
    const challenge = await requestChallenge({
      port: requestServer.port, config: runtime.config, identity: targetIdentity,
      operation: 'transfer_commit', operationId, intentDigest, instanceId: prepared.active.instanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId, intentDigest, attemptNo: input.attemptNo ?? 1,
        instanceId: prepared.active.instanceId, identity: targetIdentity,
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
    const challenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: prepared.target, operation: 'query',
      operationId, intentDigest, instanceId: prepared.active.instanceId,
    });
    const body = buildChallengeBoundBody({
      challenge: challenge.token, operationId, intentDigest, attemptNo,
      instanceId: prepared.active.instanceId, identity: prepared.target,
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
    expect(missingResponse.status).toBe(409);
    expect((await verifyCenterJwt(missingResponse.json['operation_receipt'] as string)).payload['outcome_code'])
      .toBe('TRANSFER_APPROVAL_INVALID');
    expect(await db.selectFrom('license_transfer_plans').selectAll().where('license_id', '=', active.licenseId).execute()).toHaveLength(0);

    const forged = await makePrepareAttempt(active, target, approval.operationId, {
      targetPublicJwk: (await createIdentity()).publicJwk,
    });
    expect((await sendPrepare(forged.attempt, active.source)).status).toBe(409);
    const reusedKey = await makePrepareAttempt(active, active.source, approval.operationId);
    expect((await sendPrepare(reusedKey.attempt, active.source)).status).toBe(409);
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
    expect(attempts[loserIndex]!.response.status).toBe(409);
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
      const droppedAck = pgProxy.armNextCommitAckDrop();
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
    const secretDir = await mkdtemp(join(tmpdir(), 'aikayun-license-transfer-process-'));
    const keyFile = join(secretDir, 'signing-key.pem');
    await writeFile(keyFile, runtime.privatePem, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    let child: Awaited<ReturnType<typeof startChildLicenseServer>> | undefined;
    let restarted: Awaited<ReturnType<typeof startChildLicenseServer>> | undefined;
    const commitOperationId = randomUUID();
    try {
      child = await startChildLicenseServer({
        databaseUrl: runtime.config.databaseUrl, issuer: runtime.config.issuer, publicOrigin: runtime.config.publicOrigin,
        keyFile, tlsKeyFile: runtime.config.tlsKeyFile, tlsCertFile: runtime.config.tlsCertFile,
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
        keyFile, tlsKeyFile: runtime.config.tlsKeyFile, tlsCertFile: runtime.config.tlsCertFile,
      });
      const retry = await makeCommitAttempt(prepared, { operationId: commitOperationId, attemptNo: 2, requestServer: restarted });
      expect((await sendCommit(retry.attempt, prepared.target, restarted)).status).toBe(200);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
    } finally {
      releaseBlocker.resolve();
      await blocker.catch(() => undefined);
      await child?.stop().catch(() => undefined);
      await restarted?.stop().catch(() => undefined);
      await rm(secretDir, { recursive: true, force: true });
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
    expect(response.status).toBe(409);
    expect((await verifyCenterJwt(response.json['operation_receipt'] as string)).payload['outcome_code']).toBe('TRANSFER_APPROVAL_INVALID');
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', sourceB.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');

    const thirdLicense = await createLicense(db);
    const existing = await db.selectFrom('license_activations').selectAll().where('license_id', '=', sourceA.licenseId).executeTakeFirstOrThrow();
    await expect(db.insertInto('license_activations').values({
      id: randomUUID(), license_id: thirdLicense.id, generation: '1', instance_id: existing.instance_id,
      database_id: randomUUID(), identity_jwk_public: (await createIdentity()).publicJwk, identity_jkt: randomUUID(),
      state: 'active', activated_at: await getDbNow(db), retired_at: null, last_seen_at: await getDbNow(db), origin_display: null,
    }).execute()).rejects.toMatchObject({ code: '23505' });
  });
});

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
