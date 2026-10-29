import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { userInfo, tmpdir } from 'node:os';
import { join } from 'node:path';
import { sql, type Kysely } from 'kysely';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { acceptSignerTrustBundleRequestDigest } from '../../src/admin/signing-service.js';
import {
  approveDisasterTransferRequestDigest,
  approveTransferRequestDigest,
  changeLicenseStatusRequestDigest,
  createAdminService,
  renewLicenseRequestDigest,
  revokeDisasterTransferApprovalRequestDigest,
  revokeTransferApprovalRequestDigest,
  type AdminOperationResult,
  type ApproveDisasterTransferRequest,
  type ApproveTransferRequest,
} from '../../src/admin/service.js';
import { createDatabase, migrateToLatest } from '../../src/db/database.js';
import { signTypedJwt } from '../../src/crypto/jwt.js';
import { loadTrustedSigningContext } from '../../src/crypto/signing-authority.js';
import { verifyTypedJwt } from '../../src/crypto/jwt.js';
import type { Database } from '../../src/db/types.js';
import {
  disasterTransferCommitIntentDigest,
  disasterTransferPrepareIntentDigest,
  renewalIntentDigest,
  transferCommitIntentDigest,
  transferPrepareIntentDigest,
} from '../../src/intent.js';
import {
  verifyDisasterBindingReceipt,
  verifyDisasterTransferReceipt,
  verifyDisasterTransferTicket,
  verifyLicenseLease,
  signDisasterTransferTicket,
} from '../../src/receipts.js';
import { createActivationCode, createLicense, getDbNow } from '../fixtures.js';
import { publishAndRotateTo } from '../support/signing-rotation.js';
import { CommitAckDropProxy } from '../support/postgres-proxy.js';
import { HttpResponseDropProxy } from '../support/http-response-proxy.js';
import {
  terminatePostgresBackend,
  waitForAdvisoryLockWaiters,
  waitForLicenseRowWaiterPids,
  waitForLicenseRowWaiters,
  waitForNoLockWaiters,
} from '../support/pg-waits.js';
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

interface ApprovedDisaster {
  active: ActiveSource;
  target: TestIdentity;
  approval: AdminOperationResult;
  request: Omit<ApproveDisasterTransferRequest, 'confirmedRequestDigest'>;
}

interface PreparedDisaster extends ApprovedDisaster {
  prepareOperationId: string;
  prepareIntentDigest: string;
  ticket: string;
}

interface Attempt {
  body: Record<string, unknown>;
  nonce: string;
}

function nonceFromChallenge(token: string): string {
  const value = decodeJwt(token)['server_nonce'];
  if (typeof value !== 'string') throw new Error('Challenge has no server nonce');
  return value;
}

function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('base64url');
}

function plusOne(value: string): string {
  return (BigInt(value) + 1n).toString();
}

describe('disaster license transfer over real PostgreSQL and HTTPS', () => {
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

  async function activate(input: { instanceId?: string; licenseEnd?: Date } = {}): Promise<ActiveSource> {
    const license = await createLicense(db, { ...(input.licenseEnd ? { end: input.licenseEnd } : {}) });
    const code = await createActivationCode(db, license.id);
    const source = await createIdentity();
    const instanceId = input.instanceId ?? randomUUID();
    const databaseId = randomUUID();
    const operationId = randomUUID();
    const origin = 'https://shop.example.test';
    const intentDigest = (await import('../../src/intent.js')).activationIntentDigest({
      licenseId: license.id, activationCode: code.code, instanceId, databaseId, identityJkt: source.jkt, origin,
    });
    const challenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: source, operation: 'activation',
      operationId, intentDigest, instanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId, intentDigest, attemptNo: 1,
        instanceId, identity: source, licenseId: license.id, databaseId,
      }), activation_code: code.code, origin,
    };
    const response = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/activations', body,
      identity: source, nonce: nonceFromChallenge(challenge.token),
    });
    expect(response.status).toBe(200);
    if (typeof response.json['license'] !== 'string') throw new Error('Activation lease missing');
    return { licenseId: license.id, source, instanceId, databaseId, activationOperationId: operationId,
      activationLease: response.json['license'] };
  }

  async function disasterApprovalRequest(active: ActiveSource, target: TestIdentity, overrides: Partial<ApproveDisasterTransferRequest> = {}) {
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const source = await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', active.licenseId).where('state', '=', 'active').executeTakeFirstOrThrow();
    const targetMode = overrides.targetInstanceMode ?? 'preserve';
    const request: Omit<ApproveDisasterTransferRequest, 'confirmedRequestDigest'> = {
      operationId: overrides.operationId ?? randomUUID(),
      licenseId: active.licenseId,
      expectedRevision: overrides.expectedRevision ?? license.revision.toString(),
      reason: overrides.reason ?? '独立核对恢复资料并批准灾难接管',
      accountReference: overrides.accountReference ?? license.account_id,
      sourceActivationId: overrides.sourceActivationId ?? source.id,
      databaseId: overrides.databaseId ?? active.databaseId,
      sourceInstanceId: overrides.sourceInstanceId ?? active.instanceId,
      sourceIdentityJkt: overrides.sourceIdentityJkt ?? active.source.jkt,
      targetInstanceId: overrides.targetInstanceId ?? (targetMode === 'preserve' ? active.instanceId : randomUUID()),
      targetInstanceMode: targetMode,
      targetIdentityJkt: overrides.targetIdentityJkt ?? target.jkt,
      sourceGeneration: overrides.sourceGeneration ?? license.current_generation.toString(),
      expectedBindingRevision: overrides.expectedBindingRevision ?? '7',
      incidentType: overrides.incidentType ?? 'private_key_lost',
      recoveryReason: overrides.recoveryReason ?? '旧实例私钥无法再提供可信持钥证明',
      verificationRecordRef: overrides.verificationRecordRef ?? `case:IR-${randomUUID()}`,
      backupCheckResult: overrides.backupCheckResult ?? 'database_identity_and_history_reviewed',
      oldServerIsolation: overrides.oldServerIsolation ?? 'confirmed_isolated',
      expiresInHours: overrides.expiresInHours ?? 24,
    };
    return request;
  }

  async function approveDisaster(active: ActiveSource, target: TestIdentity, overrides: Partial<ApproveDisasterTransferRequest> = {}) {
    const request = await disasterApprovalRequest(active, target, overrides);
    const result = await admin.approveDisasterTransfer({ ...request,
      confirmedRequestDigest: approveDisasterTransferRequestDigest(request) });
    return { active, target, request, approval: result };
  }

  async function makePrepareAttempt(prepared: ApprovedDisaster, overrides: {
    operationId?: string;
    attemptNo?: number;
    approvalId?: string;
    requestId?: string;
    accountReference?: string;
    databaseId?: string;
    sourceActivationId?: string;
    sourceInstanceId?: string;
    sourceIdentityJkt?: string;
    targetInstanceId?: string;
    targetIdentityJkt?: string;
    sourceGeneration?: string;
    expectedBindingRevision?: string;
    expectedRevision?: string;
    signer?: TestIdentity;
    challengePort?: number;
  } = {}): Promise<{ attempt: Attempt; operationId: string; intentDigest: string }> {
    const operationId = overrides.operationId ?? randomUUID();
    const request = prepared.request;
    const target = overrides.signer ?? prepared.target;
    const fields = {
      licenseId: prepared.active.licenseId,
      accountReference: overrides.accountReference ?? request.accountReference,
      databaseId: overrides.databaseId ?? request.databaseId,
      approvalId: overrides.approvalId ?? request.operationId,
      requestId: overrides.requestId ?? request.operationId,
      sourceActivationId: overrides.sourceActivationId ?? request.sourceActivationId,
      sourceInstanceId: overrides.sourceInstanceId ?? request.sourceInstanceId,
      sourceIdentityJkt: overrides.sourceIdentityJkt ?? request.sourceIdentityJkt,
      targetInstanceId: overrides.targetInstanceId ?? request.targetInstanceId,
      targetIdentityJkt: overrides.targetIdentityJkt ?? request.targetIdentityJkt,
      sourceGeneration: overrides.sourceGeneration ?? request.sourceGeneration,
      expectedBindingRevision: overrides.expectedBindingRevision ?? request.expectedBindingRevision,
      expectedRevision: overrides.expectedRevision ?? request.expectedRevision,
    };
    const intentDigest = disasterTransferPrepareIntentDigest(fields);
    const challenge = await requestChallenge({
      port: overrides.challengePort ?? server.port, config: runtime.config, identity: target,
      operation: 'disaster_transfer_prepare', operationId, intentDigest, instanceId: fields.targetInstanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId, intentDigest, attemptNo: overrides.attemptNo ?? 1,
        instanceId: fields.targetInstanceId, identity: target, licenseId: fields.licenseId, databaseId: fields.databaseId,
      }),
      approval_id: fields.approvalId,
      request_id: fields.requestId,
      account_reference: fields.accountReference,
      source_activation_id: fields.sourceActivationId,
      source_instance_id: fields.sourceInstanceId,
      source_identity_jkt: fields.sourceIdentityJkt,
      target_instance_id: fields.targetInstanceId,
      target_identity_jkt: fields.targetIdentityJkt,
      source_generation: fields.sourceGeneration,
      expected_binding_revision: fields.expectedBindingRevision,
      expected_revision: fields.expectedRevision,
    };
    return { attempt: { body, nonce: nonceFromChallenge(challenge.token) }, operationId, intentDigest };
  }

  async function sendPrepare(attempt: Attempt, identity: TestIdentity, port = server.port): Promise<HttpResponse> {
    return signPost({ port, origin: runtime.config.publicOrigin, path: '/v1/disaster-transfers/prepare',
      body: attempt.body, identity, nonce: attempt.nonce });
  }

  async function prepare(approved: ApprovedDisaster, input: Parameters<typeof makePrepareAttempt>[1] = {}): Promise<PreparedDisaster> {
    const { attempt, operationId, intentDigest } = await makePrepareAttempt(approved, input);
    const response = await sendPrepare(attempt, input.signer ?? approved.target);
    expect(response.status).toBe(200);
    if (typeof response.json['disaster_transfer_ticket'] !== 'string') throw new Error('Disaster ticket missing');
    return { ...approved, prepareOperationId: operationId, prepareIntentDigest: intentDigest,
      ticket: response.json['disaster_transfer_ticket'] };
  }

  async function makeCommitAttempt(prepared: PreparedDisaster, overrides: {
    operationId?: string;
    attemptNo?: number;
    signer?: TestIdentity;
    ticket?: string;
    challengePort?: number;
  } = {}): Promise<{ attempt: Attempt; operationId: string; intentDigest: string }> {
    const operationId = overrides.operationId ?? randomUUID();
    const target = overrides.signer ?? prepared.target;
    const ticket = overrides.ticket ?? prepared.ticket;
    const intentDigest = disasterTransferCommitIntentDigest({
      licenseId: prepared.active.licenseId,
      databaseId: prepared.active.databaseId,
      targetInstanceId: prepared.request.targetInstanceId,
      targetIdentityJkt: target.jkt,
      approvalId: prepared.request.operationId,
      prepareOperationId: prepared.prepareOperationId,
      disasterTicketDigest: sha256(ticket),
    });
    const challenge = await requestChallenge({
      port: overrides.challengePort ?? server.port, config: runtime.config, identity: target,
      operation: 'disaster_transfer_commit', operationId, intentDigest, instanceId: prepared.request.targetInstanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId, intentDigest, attemptNo: overrides.attemptNo ?? 1,
        instanceId: prepared.request.targetInstanceId, identity: target,
        licenseId: prepared.active.licenseId, databaseId: prepared.active.databaseId,
      }),
      approval_id: prepared.request.operationId,
      prepare_operation_id: prepared.prepareOperationId,
      disaster_ticket: ticket,
    };
    return { attempt: { body, nonce: nonceFromChallenge(challenge.token) }, operationId, intentDigest };
  }

  async function sendCommit(attempt: Attempt, identity: TestIdentity, port = server.port): Promise<HttpResponse> {
    return signPost({ port, origin: runtime.config.publicOrigin, path: '/v1/disaster-transfers/commit',
      body: attempt.body, identity, nonce: attempt.nonce });
  }

  async function commit(prepared: PreparedDisaster, overrides: Parameters<typeof makeCommitAttempt>[1] = {}, port = server.port) {
    const { attempt, operationId, intentDigest } = await makeCommitAttempt(prepared, overrides);
    return { attempt, operationId, intentDigest, response: await sendCommit(attempt, overrides.signer ?? prepared.target, port) };
  }

  async function queryOperation(input: {
    licenseId: string;
    databaseId: string;
    instanceId: string;
    identity: TestIdentity;
    operationId: string;
    intentDigest: string;
    attemptNo: number;
  }): Promise<HttpResponse> {
    const challenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: input.identity, operation: 'query',
      operationId: input.operationId, intentDigest: input.intentDigest, instanceId: input.instanceId,
    });
    const body = buildChallengeBoundBody({
      challenge: challenge.token, operationId: input.operationId, intentDigest: input.intentDigest,
      attemptNo: input.attemptNo, instanceId: input.instanceId, identity: input.identity,
      licenseId: input.licenseId, databaseId: input.databaseId,
    });
    return signPost({ port: server.port, origin: runtime.config.publicOrigin, path: '/v1/operations/query',
      body, identity: input.identity, nonce: nonceFromChallenge(challenge.token) });
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
    db = createDatabase(runtime.config.databaseUrl, 32);
    await migrateToLatest(db);
    await runtime.initializeAuthority(db);
    server = await startAppServer(createApp({ config: runtime.config, db }), runtime.config);
    scratchDirectory = await mkdtemp(join(tmpdir(), 'aikayun-license-disaster-'));
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

  it('replaces a lost source identity using only approved target proof and atomically preserves the license binding', async () => {
    const active = await activate();
    const target = await createIdentity();
    const before = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const codesBefore = await db.selectFrom('activation_codes').selectAll().where('license_id', '=', active.licenseId).execute();
    const approved = await approveDisaster(active, target);
    expect(approved.approval.state).toBe('succeeded');
    const approvalRow = await db.selectFrom('license_disaster_transfer_approvals').selectAll()
      .where('approval_id', '=', approved.approval.operationId).executeTakeFirstOrThrow();
    const adminOperation = await db.selectFrom('license_admin_operations').selectAll()
      .where('operation_id', '=', approved.approval.operationId).executeTakeFirstOrThrow();
    expect(approvalRow).toMatchObject({
      license_id: active.licenseId, account_reference: before.account_id, database_id: active.databaseId,
      source_identity_jkt: active.source.jkt, source_generation: '1', target_identity_jkt: target.jkt,
      actor_os_uid: process.geteuid?.(), actor_os_username: userInfo().username,
      actor_database_role: adminOperation.actor_database_role, request_digest: approved.approval.requestDigest,
    });
    expect(adminOperation).toMatchObject({ action: 'disaster_transfer_approve', state: 'succeeded', request_digest: approved.approval.requestDigest });
    expect(await db.selectFrom('license_disaster_recovery_requests').selectAll()
      .where('request_id', '=', approved.approval.operationId).execute()).toHaveLength(1);
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).revision).toBe(before.revision);

    const prepared = await prepare(approved);
    const ticket = await verifyDisasterTransferTicket(prepared.ticket, runtime.config, new Date());
    expect((await verifyCenterJwt(prepared.ticket)).protectedHeader['typ']).toBe('aikayun-license-disaster-transfer-ticket+jwt');
    expect(Number(ticket.claims['exp']) - Number(ticket.claims['iat'])).toBe(600);
    expect((await verifyDisasterTransferTicket(prepared.ticket, runtime.config, new Date(Date.now() + 610_000))).expired).toBe(true);
    expect(ticket.claims).toMatchObject({
      license_id: active.licenseId, account_reference: before.account_id, database_id: active.databaseId,
      source_activation_id: approvalRow.source_activation_id, source_instance_id: active.instanceId,
      source_identity_jkt: active.source.jkt, source_activation_generation: '1', target_instance_id: active.instanceId,
      target_identity_jkt: target.jkt, expected_revision: before.revision,
      expected_binding_revision: approved.request.expectedBindingRevision,
    });
    const afterPrepare = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect([afterPrepare.current_generation, afterPrepare.revision, afterPrepare.entitlement_revision])
      .toEqual([before.current_generation, before.revision, before.entitlement_revision]);

    const committed = await commit(prepared);
    expect(committed.response.status).toBe(200);
    const receiptToken = committed.response.json['transfer_receipt'];
    if (typeof receiptToken !== 'string') throw new Error('Active disaster transfer receipt missing');
    const receipt = await verifyDisasterTransferReceipt(receiptToken, runtime.config, new Date());
    expect((await verifyCenterJwt(receiptToken)).protectedHeader['typ']).toBe('aikayun-license-disaster-transfer+jwt');
    expect(receipt).toMatchObject({ result_mode: 'active_lease', license_status: 'active',
      source_identity_jkt: active.source.jkt, target_identity_jkt: target.jkt,
      source_activation_generation: '1', target_activation_generation: '2',
      expected_revision: before.revision, result_revision: plusOne(before.revision),
      entitlement_revision: before.entitlement_revision, database_id: active.databaseId });
    const leaseToken = receipt['new_lease'];
    if (typeof leaseToken !== 'string') throw new Error('Active lease missing from disaster receipt');
    const lease = await verifyCenterJwt(leaseToken);
    expect(lease.protectedHeader['typ']).toBe('aikayun-license+jwt');
    expect(lease.payload).toMatchObject({ sub: active.licenseId, instance_id: active.instanceId,
      database_id: active.databaseId, identity_jkt: target.jkt, activation_generation: '2',
      entitlement_revision: before.entitlement_revision, grants: ['create_order', 'create_top_up'] });
    const validationNow = new Date();
    const strictReceipt = await verifyDisasterTransferReceipt(receiptToken, runtime.config, validationNow);
    const strictLease = await verifyLicenseLease(leaseToken, runtime.config, validationNow);
    expect(strictReceipt['database_id']).toBe(strictLease['database_id']);
    expect(strictReceipt['entitlement_revision']).toBe(strictLease['entitlement_revision']);
    expect(strictReceipt['subscription_end']).toBe(strictLease['subscription_end']);
    const outerClaims = receipt as Record<string, unknown>;
    const innerClaims = lease.payload as Record<string, unknown>;
    const rejectedOuter = async (claims: Record<string, unknown>) => {
      const forged = await signTypedJwt(runtime.config, 'aikayun-license-disaster-transfer+jwt', claims);
      await expect(verifyDisasterTransferReceipt(forged, runtime.config, validationNow)).rejects.toThrow();
    };
    for (const [field, value] of [
      ['sub', randomUUID()],
      ['license_id', randomUUID()],
      ['database_id', randomUUID()],
      ['entitlement_revision', plusOne(String(outerClaims['entitlement_revision']))],
      ['subscription_end', Number(outerClaims['subscription_end']) + 3600],
    ] as const) {
      await rejectedOuter({ ...outerClaims, [field]: value });
    }
    const nestedMismatches: Array<[string, unknown]> = [
      ['sub', randomUUID()], ['database_id', randomUUID()], ['instance_id', randomUUID()],
      ['identity_jkt', sha256(randomUUID())], ['activation_generation', '3'],
      ['entitlement_revision', plusOne(String(innerClaims['entitlement_revision']))],
      ['subscription_end', Number(innerClaims['subscription_end']) + 3600],
      ['request_nonce', sha256(randomUUID())], ['request_digest', sha256(randomUUID())],
    ];
    for (const [field, value] of nestedMismatches) {
      const nestedToken = await signTypedJwt(runtime.config, 'aikayun-license+jwt', { ...innerClaims, [field]: value });
      await rejectedOuter({ ...outerClaims, new_lease: nestedToken });
    }
    const iat = Number(outerClaims['iat']);
    await rejectedOuter({ ...outerClaims, unexpected_claim: true });
    await rejectedOuter({ ...outerClaims, exp: iat + 601 });
    await rejectedOuter({ ...outerClaims, nbf: iat - 1 });
    await expect(verifyDisasterTransferReceipt(leaseToken, runtime.config, validationNow)).rejects.toThrow();

    const after = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect(after.current_generation).toBe('2');
    expect(after.revision).toBe(plusOne(before.revision));
    expect(after.entitlement_revision).toBe(before.entitlement_revision);
    expect(after.confirmed_subscription_end).toEqual(before.confirmed_subscription_end);
    expect(await db.selectFrom('activation_codes').selectAll().where('license_id', '=', active.licenseId).execute()).toEqual(codesBefore);
    const activations = await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId)
      .orderBy('generation', 'asc').execute();
    expect(activations).toHaveLength(2);
    expect(activations[0]).toMatchObject({ state: 'retired', generation: '1', database_id: active.databaseId, identity_jkt: active.source.jkt });
    expect(activations[1]).toMatchObject({ state: 'active', generation: '2', database_id: active.databaseId, identity_jkt: target.jkt });
    expect((await db.selectFrom('license_disaster_transfer_plans').selectAll().where('commit_operation_id', '=', committed.operationId)
      .executeTakeFirstOrThrow()).disaster_result_jws).toBe(receiptToken);
    expect(await db.selectFrom('license_disaster_transfer_events').selectAll()
      .where('license_id', '=', active.licenseId).where('kind', '=', 'committed').execute()).toHaveLength(1);
  });

  it('commits an A-signed disaster ticket after B becomes authoritative and preserves the A ticket bytes', async () => {
    const active = await activate();
    const target = await createIdentity();
    const approved = await approveDisaster(active, target);
    const before = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const activationBefore = await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', active.licenseId).where('state', '=', 'active').executeTakeFirstOrThrow();
    const prepared = await prepare(approved);
    const prepareOperation = await db.selectFrom('license_operations').selectAll()
      .where('operation_id', '=', prepared.prepareOperationId).executeTakeFirstOrThrow();
    expect(decodeProtectedHeader(prepared.ticket)['kid']).toBe(runtime.onlineKey.kid);

    const b = await runtime.createOnlineKey();
    const { context } = await publishAndRotateTo(db, runtime, b, '2');
    const verificationTime = new Date(context.trustedTime * 1000);
    const ticket = await verifyDisasterTransferTicket(prepared.ticket, context, verificationTime);
    expect(ticket.expired).toBe(false);
    expect(prepareOperation.response_jws).toBe(prepared.ticket);
    const afterRotation = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const activationAfterRotation = await db.selectFrom('license_activations').selectAll()
      .where('id', '=', activationBefore.id).executeTakeFirstOrThrow();
    expect([afterRotation.current_generation, afterRotation.revision, afterRotation.entitlement_revision,
      afterRotation.confirmed_subscription_end, activationAfterRotation.time_epoch]).toEqual([
      before.current_generation, before.revision, before.entitlement_revision,
      before.confirmed_subscription_end, activationBefore.time_epoch,
    ]);

    const committed = await commit(prepared);
    expect(committed.response.status).toBe(200);
    const receiptToken = committed.response.json['transfer_receipt'] as string;
    expect(decodeProtectedHeader(receiptToken)['kid']).toBe(b.kid);
    const resultContext = (await loadTrustedSigningContext(db, runtime.config)).context;
    const resultTime = new Date(resultContext.trustedTime * 1000);
    const receipt = await verifyDisasterTransferReceipt(receiptToken, resultContext, resultTime);
    const leaseToken = receipt['new_lease'] as string;
    expect(decodeProtectedHeader(leaseToken)['kid']).toBe(b.kid);
    const lease = await verifyLicenseLease(leaseToken, resultContext, resultTime);
    expect(lease['activation_generation']).toBe('2');
    expect(receipt['entitlement_revision']).toBe(before.entitlement_revision);
    const plan = await db.selectFrom('license_disaster_transfer_plans').selectAll()
      .where('plan_id', '=', decodeJwt(prepared.ticket)['plan_id'] as string).executeTakeFirstOrThrow();
    expect(plan.ticket_jws).toBe(prepared.ticket);
    expect(plan.disaster_result_jws).toBe(receiptToken);
    const afterCommit = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect(afterCommit.current_generation).toBe('2');
    expect(afterCommit.revision).toBe(plusOne(before.revision));
    expect(afterCommit.entitlement_revision).toBe(before.entitlement_revision);
    expect(afterCommit.confirmed_subscription_end).toEqual(before.confirmed_subscription_end);
  });

  it('invalidates and audits an unfinished A disaster ticket on emergency key revocation', async () => {
    const previous = { db, server, runtime, admin, policyFile };
    const isolatedRuntime = await createTestSigningRuntime();
    const isolatedDb = createDatabase(isolatedRuntime.config.databaseUrl, 24);
    await migrateToLatest(isolatedDb);
    await isolatedRuntime.initializeAuthority(isolatedDb);
    const isolatedServer = await startAppServer(createApp({ config: isolatedRuntime.config, db: isolatedDb }), isolatedRuntime.config);
    const isolatedPolicy = await writeAdminPolicy(isolatedRuntime.config.databaseUrl);
    const isolatedAdmin = await createAdminService(isolatedPolicy);
    db = isolatedDb;
    server = isolatedServer;
    runtime = isolatedRuntime;
    admin = isolatedAdmin;
    policyFile = isolatedPolicy;
    try {
    const active = await activate();
    const target = await createIdentity();
    const approved = await approveDisaster(active, target);
    const prepared = await prepare(approved);
    const prepareOperation = await db.selectFrom('license_operations').selectAll()
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
      reason: 'emergency revoke compromised A disaster signer',
    };
    const accepted = await service.acceptTrustBundle({
      ...accept,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: acceptSignerTrustBundleRequestDigest(accept),
    });
    expect(accepted.result['invalidated_prepared_plans']).toBe(1);
    const plan = await db.selectFrom('license_disaster_transfer_plans').selectAll()
      .where('plan_id', '=', planId).executeTakeFirstOrThrow();
    expect(plan).toMatchObject({ state: 'invalidated', ticket_jws: prepared.ticket });
    expect(prepareOperation.response_jws).toBe(prepared.ticket);
    const events = await db.selectFrom('license_disaster_transfer_events').selectAll().where('plan_id', '=', planId).execute();
    expect(events.map((event) => event.kind)).toEqual(['prepared', 'invalidated']);
    expect(events[1]!.safe_details).toMatchObject({
      reason: 'signing_key_revoked_or_retired', signer_kid: runtime.onlineKey.kid,
    });

    const lateCommit = await commit(prepared);
    expect(lateCommit.response.status).toBe(401);
    expect(lateCommit.response.json['error']).toEqual({ code: 'DISASTER_TICKET_INVALID' });
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId)
      .executeTakeFirstOrThrow()).current_generation).toBe('1');
    expect((await db.selectFrom('license_operations').selectAll()
      .where('operation_id', '=', prepared.prepareOperationId).executeTakeFirstOrThrow()).response_jws).toBe(prepared.ticket);
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

  it('rejects missing, cross-license, stale, wrong-database and substituted-target approvals', async () => {
    const active = await activate();
    const target = await createIdentity();
    const approved = await approveDisaster(active, target);
    expect(approved.approval.state).toBe('succeeded');
    const unauthorizedOperationIds: string[] = [];

    const noApproval = await makePrepareAttempt(approved, { approvalId: randomUUID(), requestId: randomUUID() });
    const noApprovalResponse = await sendPrepare(noApproval.attempt, target);
    expect(noApprovalResponse.status).toBe(403);
    expect(noApprovalResponse.json['error']).toEqual({ code: 'DISASTER_PREPARE_FORBIDDEN' });
    unauthorizedOperationIds.push(noApproval.operationId);

    const otherLicense = await activate();
    const otherTarget = await createIdentity();
    const otherApproved = await approveDisaster(otherLicense, otherTarget);
    const crossLicense = await makePrepareAttempt(approved, { approvalId: otherApproved.approval.operationId,
      requestId: otherApproved.approval.operationId });
    expect((await sendPrepare(crossLicense.attempt, target)).status).toBe(403);
    unauthorizedOperationIds.push(crossLicense.operationId);

    const wrongDatabase = await makePrepareAttempt(approved, { databaseId: randomUUID() });
    const wrongDatabaseResponse = await sendPrepare(wrongDatabase.attempt, target);
    expect(wrongDatabaseResponse.status).toBe(403);
    unauthorizedOperationIds.push(wrongDatabase.operationId);

    const staleRevision = await makePrepareAttempt(approved, { expectedRevision: '1' });
    expect((await sendPrepare(staleRevision.attempt, target)).status).toBe(403);
    unauthorizedOperationIds.push(staleRevision.operationId);

    const wrongTargetJkt = await makePrepareAttempt(approved, { targetIdentityJkt: (await createIdentity()).jkt });
    expect((await sendPrepare(wrongTargetJkt.attempt, target)).status).toBe(409);
    unauthorizedOperationIds.push(wrongTargetJkt.operationId);
    for (const operationId of unauthorizedOperationIds) {
      expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', operationId).execute()).toHaveLength(0);
      expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', operationId).execute()).toHaveLength(0);
      expect(await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', operationId).execute()).toHaveLength(0);
    }
    expect(await db.selectFrom('license_disaster_transfer_plans').selectAll().where('license_id', '=', active.licenseId).execute())
      .toHaveLength(0);
    const badAdminSnapshot = await approveDisaster(active, await createIdentity(), { databaseId: randomUUID() });
    expect(badAdminSnapshot.approval.state).toBe('rejected');
    expect(badAdminSnapshot.approval.outcomeCode).toBe('DISASTER_SOURCE_BINDING_MISMATCH');
  });

  it('rejects active target-instance collisions and every historical JKT for the license', async () => {
    const source = await activate();
    const occupiedInstanceId = randomUUID();
    await activate({ instanceId: occupiedInstanceId });
    const target = await createIdentity();
    const conflict = await approveDisaster(source, target, { targetInstanceMode: 'replace', targetInstanceId: occupiedInstanceId });
    expect(conflict.approval.state).toBe('rejected');
    expect(conflict.approval.outcomeCode).toBe('DISASTER_TARGET_INSTANCE_ALREADY_ACTIVE');

    const targetB = await createIdentity();
    const approvedB = await approveDisaster(source, targetB);
    const preparedB = await prepare(approvedB);
    expect((await commit(preparedB)).response.status).toBe(200);
    const rollbackToOldKey = await approveDisaster({ ...source, source: targetB }, source.source);
    expect(rollbackToOldKey.approval.state).toBe('rejected');
    expect(rollbackToOldKey.approval.outcomeCode).toBe('DISASTER_TARGET_IDENTITY_WAS_USED');
  });

  it('requires explicit normal-transfer approval handling and uses append-only disaster revocation for target changes', async () => {
    const active = await activate();
    const target = await createIdentity();
    const before = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const normalPrepared = await prepareNormal(active, target);
    const normalApproval = normalPrepared.approval;
    expect(normalApproval.state).toBe('succeeded');
    const blocked = await approveDisaster(active, await createIdentity());
    expect(blocked.approval.state).toBe('rejected');
    expect(blocked.approval.outcomeCode).toBe('NORMAL_TRANSFER_REQUIRES_EXPLICIT_REVOCATION');

    const revokeNormalBase = { operationId: randomUUID(), licenseId: active.licenseId,
      approvalId: normalApproval.operationId, expectedRevision: before.revision, reason: '显式撤销正常迁移审批后转灾难流程' };
    expect((await admin.revokeTransferApproval({ ...revokeNormalBase,
      confirmedRequestDigest: revokeTransferApprovalRequestDigest(revokeNormalBase) })).state).toBe('succeeded');
    const approved = await approveDisaster(active, target);
    expect(approved.approval.state).toBe('succeeded');

    const postDisasterTarget = await createIdentity();
    const normalAfterRequest: Omit<ApproveTransferRequest, 'confirmedRequestDigest'> = {
      operationId: randomUUID(), licenseId: active.licenseId, expectedRevision: before.revision,
      reason: '灾难审批有效期间拒绝普通迁移审批', databaseId: active.databaseId,
      sourceInstanceId: active.instanceId, sourceIdentityJkt: active.source.jkt,
      targetInstanceId: active.instanceId, targetIdentityJkt: postDisasterTarget.jkt,
      sourceGeneration: before.current_generation, expectedBindingRevision: '7',
    };
    const normalAfterDisaster = await admin.approveTransfer({ ...normalAfterRequest,
      confirmedRequestDigest: approveTransferRequestDigest(normalAfterRequest) });
    expect(normalAfterDisaster.state).toBe('rejected');
    expect(normalAfterDisaster.outcomeCode).toBe('DISASTER_TRANSFER_REQUIRES_EXPLICIT_REVOCATION');

    const secondTarget = await createIdentity();
    const prepared = await prepare(approved);
    const current = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const revokeBase = { operationId: randomUUID(), licenseId: active.licenseId, approvalId: approved.approval.operationId,
      expectedRevision: current.revision, reason: '取消旧目标审批并保留历史事实' };
    expect((await admin.revokeDisasterTransferApproval({ ...revokeBase,
      confirmedRequestDigest: revokeDisasterTransferApprovalRequestDigest(revokeBase) })).state).toBe('succeeded');
    const lateCommit = await commit(prepared);
    expect(lateCommit.response.status).toBe(409);
    expect((await db.selectFrom('license_disaster_transfer_plans').selectAll()
      .where('prepare_operation_id', '=', prepared.prepareOperationId).executeTakeFirstOrThrow()).state).toBe('invalidated');
    const revoked = await db.selectFrom('license_disaster_transfer_revocations').selectAll()
      .where('approval_id', '=', approved.approval.operationId).executeTakeFirstOrThrow();
    expect(revoked.actor_os_uid).toBe(process.geteuid?.());
    const replacement = await approveDisaster(active, secondTarget);
    expect(replacement.approval.state).toBe('succeeded');
    expect(await db.selectFrom('license_disaster_recovery_requests').selectAll()
      .where('license_id', '=', active.licenseId).execute()).toHaveLength(2);
    const replacementCommit = await commit(await prepare(replacement));
    expect(replacementCommit.response.status).toBe(200);
    const oldNormalTicketCommit = await commitNormalTicket(active, normalPrepared);
    expect(oldNormalTicketCommit.status).toBe(409);
    expect((await verifyCenterJwt(oldNormalTicketCommit.json['operation_receipt'] as string)).payload['outcome_code'])
      .toBe('TRANSFER_TICKET_CONSUMED');
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation)
      .toBe('2');
    await expect(db.updateTable('license_disaster_transfer_approvals').set({ expires_at: new Date() })
      .where('approval_id', '=', approved.approval.operationId).execute()).rejects.toMatchObject({ code: '55000' });
  });

  it('serializes normal and disaster approval competition on the license row in both orders', async () => {
    async function race(disasterFirst: boolean) {
      const active = await activate();
      const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
      const normalTarget = await createIdentity();
      const disasterTarget = await createIdentity();
      const normalRequest: Omit<ApproveTransferRequest, 'confirmedRequestDigest'> = {
        operationId: randomUUID(), licenseId: active.licenseId, expectedRevision: license.revision.toString(),
        reason: '并发审批竞争中的正常迁移目标', databaseId: active.databaseId,
        sourceInstanceId: active.instanceId, sourceIdentityJkt: active.source.jkt,
        targetInstanceId: active.instanceId, targetIdentityJkt: normalTarget.jkt,
        sourceGeneration: license.current_generation.toString(), expectedBindingRevision: '7',
      };
      const disasterRequest = await disasterApprovalRequest(active, disasterTarget);
      let locked!: () => void;
      let release!: () => void;
      const lockedPromise = new Promise<void>((resolve) => { locked = resolve; });
      const releasePromise = new Promise<void>((resolve) => { release = resolve; });
      const blocker = db.transaction().execute(async (trx) => {
        await trx.selectFrom('licenses').select('id').where('id', '=', active.licenseId).forUpdate().executeTakeFirstOrThrow();
        locked();
        await releasePromise;
      });
      await lockedPromise;
      let normalPromise: ReturnType<typeof admin.approveTransfer>;
      let disasterPromise: ReturnType<typeof admin.approveDisasterTransfer>;
      try {
        if (disasterFirst) {
          disasterPromise = admin.approveDisasterTransfer({ ...disasterRequest,
            confirmedRequestDigest: approveDisasterTransferRequestDigest(disasterRequest) });
          await waitForLicenseRowWaiters(db, 1);
          normalPromise = admin.approveTransfer({ ...normalRequest,
            confirmedRequestDigest: approveTransferRequestDigest(normalRequest) });
        } else {
          normalPromise = admin.approveTransfer({ ...normalRequest,
            confirmedRequestDigest: approveTransferRequestDigest(normalRequest) });
          await waitForLicenseRowWaiters(db, 1);
          disasterPromise = admin.approveDisasterTransfer({ ...disasterRequest,
            confirmedRequestDigest: approveDisasterTransferRequestDigest(disasterRequest) });
        }
        await waitForLicenseRowWaiters(db, 2);
        release();
        await blocker;
      } finally {
        release();
        await blocker.catch(() => undefined);
      }
      const [normalResult, disasterResult] = await Promise.all([normalPromise!, disasterPromise!]);
      if (disasterFirst) {
        expect(disasterResult.state).toBe('succeeded');
        expect(normalResult.state).toBe('rejected');
        expect(normalResult.outcomeCode).toBe('DISASTER_TRANSFER_REQUIRES_EXPLICIT_REVOCATION');
      } else {
        expect(normalResult.state).toBe('succeeded');
        expect(disasterResult.state).toBe('rejected');
        expect(disasterResult.outcomeCode).toBe('NORMAL_TRANSFER_REQUIRES_EXPLICIT_REVOCATION');
      }
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow())
        .revision).toBe(license.revision);
      expect((await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId)
        .where('state', '=', 'active').executeTakeFirstOrThrow()).identity_jkt).toBe(active.source.jkt);
      expect(await db.selectFrom('license_transfer_approvals').selectAll().where('license_id', '=', active.licenseId).execute())
        .toHaveLength(disasterFirst ? 0 : 1);
      expect(await db.selectFrom('license_disaster_transfer_approvals').selectAll().where('license_id', '=', active.licenseId).execute())
        .toHaveLength(disasterFirst ? 1 : 0);
    }
    await race(false);
    await race(true);
  });

  it('serializes normal prepare against disaster approval on the license row in both orders', async () => {
    async function race(disasterApprovalFirst: boolean) {
      const active = await activate();
      const normalTarget = await createIdentity();
      const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
      const approvalRequest: Omit<ApproveTransferRequest, 'confirmedRequestDigest'> = {
        operationId: randomUUID(), licenseId: active.licenseId, expectedRevision: license.revision.toString(),
        reason: '并发Prepare与灾难审批的正常目标', databaseId: active.databaseId,
        sourceInstanceId: active.instanceId, sourceIdentityJkt: active.source.jkt,
        targetInstanceId: active.instanceId, targetIdentityJkt: normalTarget.jkt,
        sourceGeneration: license.current_generation.toString(), expectedBindingRevision: '7',
      };
      const normalApproval = await admin.approveTransfer({ ...approvalRequest,
        confirmedRequestDigest: approveTransferRequestDigest(approvalRequest) });
      expect(normalApproval.state).toBe('succeeded');

      const prepareOperationId = randomUUID();
      const prepareIntent = transferPrepareIntentDigest({
        licenseId: active.licenseId, databaseId: active.databaseId, instanceId: active.instanceId,
        sourceIdentityJkt: active.source.jkt, targetInstanceId: active.instanceId,
        targetIdentityJkt: normalTarget.jkt, approvalId: normalApproval.operationId,
        sourceGeneration: license.current_generation.toString(), expectedBindingRevision: '7',
        expectedRevision: license.revision.toString(),
      });
      const challenge = await requestChallenge({ port: server.port, config: runtime.config, identity: active.source,
        operation: 'transfer_prepare', operationId: prepareOperationId, intentDigest: prepareIntent, instanceId: active.instanceId });
      const prepareBody = {
        ...buildChallengeBoundBody({ challenge: challenge.token, operationId: prepareOperationId, intentDigest: prepareIntent,
          attemptNo: 1, instanceId: active.instanceId, identity: active.source,
          licenseId: active.licenseId, databaseId: active.databaseId }),
        approval_id: normalApproval.operationId, target_instance_id: active.instanceId,
        target_identity_jkt: normalTarget.jkt, target_public_jwk: normalTarget.publicJwk,
        source_generation: license.current_generation.toString(), expected_binding_revision: '7',
        expected_revision: license.revision.toString(),
      };
      const disasterRequest = await disasterApprovalRequest(active, await createIdentity());

      let locked!: () => void;
      let release!: () => void;
      const lockedPromise = new Promise<void>((resolve) => { locked = resolve; });
      const releasePromise = new Promise<void>((resolve) => { release = resolve; });
      const blocker = db.transaction().execute(async (trx) => {
        await trx.selectFrom('licenses').select('id').where('id', '=', active.licenseId).forUpdate().executeTakeFirstOrThrow();
        locked();
        await releasePromise;
      });
      await lockedPromise;
      let preparePromise: Promise<HttpResponse>;
      let disasterPromise: ReturnType<typeof admin.approveDisasterTransfer>;
      try {
        if (disasterApprovalFirst) {
          disasterPromise = admin.approveDisasterTransfer({ ...disasterRequest,
            confirmedRequestDigest: approveDisasterTransferRequestDigest(disasterRequest) });
          await waitForLicenseRowWaiters(db, 1);
          preparePromise = signPost({ port: server.port, origin: runtime.config.publicOrigin, path: '/v1/transfers/prepare',
            body: prepareBody, identity: active.source, nonce: nonceFromChallenge(challenge.token) });
        } else {
          preparePromise = signPost({ port: server.port, origin: runtime.config.publicOrigin, path: '/v1/transfers/prepare',
            body: prepareBody, identity: active.source, nonce: nonceFromChallenge(challenge.token) });
          await waitForLicenseRowWaiters(db, 1);
          disasterPromise = admin.approveDisasterTransfer({ ...disasterRequest,
            confirmedRequestDigest: approveDisasterTransferRequestDigest(disasterRequest) });
        }
        await waitForLicenseRowWaiters(db, 2);
        release();
        await blocker;
      } finally {
        release();
        await blocker.catch(() => undefined);
      }
      const [prepared, disasterApproval] = await Promise.all([preparePromise!, disasterPromise!]);
      expect(prepared.status).toBe(200);
      expect(disasterApproval.state).toBe('rejected');
      expect(disasterApproval.outcomeCode).toBe('NORMAL_TRANSFER_REQUIRES_EXPLICIT_REVOCATION');
      expect(await db.selectFrom('license_disaster_transfer_approvals').selectAll()
        .where('license_id', '=', active.licenseId).execute()).toHaveLength(0);
      expect(await db.selectFrom('license_transfer_plans').selectAll()
        .where('license_id', '=', active.licenseId).where('state', '=', 'prepared').execute()).toHaveLength(1);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow())
        .current_generation).toBe('1');
      expect(await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId)
        .where('state', '=', 'active').execute()).toMatchObject([expect.objectContaining({ identity_jkt: active.source.jkt })]);
      expect(await db.selectFrom('license_operation_attempts').selectAll()
        .where('operation_id', '=', prepareOperationId).execute()).toMatchObject([expect.objectContaining({ outcome: 'accepted' })]);
    }
    await race(false);
    await race(true);
  });

  it('serializes disaster approval revocation and commit in both PostgreSQL lock orders', async () => {
    async function race(revokeFirst: boolean) {
      const active = await activate();
      const target = await createIdentity();
      const approved = await approveDisaster(active, target);
      const prepared = await prepare(approved);
      const before = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
      const revokeRequest = { operationId: randomUUID(), licenseId: active.licenseId,
        approvalId: approved.approval.operationId, expectedRevision: before.revision.toString(),
        reason: '并发测试中撤销灾难迁移审批' };
      const commitAttempt = await makeCommitAttempt(prepared);
      let locked!: () => void;
      let release!: () => void;
      const lockedPromise = new Promise<void>((resolve) => { locked = resolve; });
      const releasePromise = new Promise<void>((resolve) => { release = resolve; });
      const blocker = db.transaction().execute(async (trx) => {
        await trx.selectFrom('licenses').select('id').where('id', '=', active.licenseId).forUpdate().executeTakeFirstOrThrow();
        locked();
        await releasePromise;
      });
      await lockedPromise;
      let revokePromise: ReturnType<typeof admin.revokeDisasterTransferApproval>;
      let commitPromise: Promise<HttpResponse>;
      try {
        if (revokeFirst) {
          revokePromise = admin.revokeDisasterTransferApproval({ ...revokeRequest,
            confirmedRequestDigest: revokeDisasterTransferApprovalRequestDigest(revokeRequest) });
          await waitForLicenseRowWaiters(db, 1);
          commitPromise = sendCommit(commitAttempt.attempt, target);
        } else {
          commitPromise = sendCommit(commitAttempt.attempt, target);
          await waitForLicenseRowWaiters(db, 1);
          revokePromise = admin.revokeDisasterTransferApproval({ ...revokeRequest,
            confirmedRequestDigest: revokeDisasterTransferApprovalRequestDigest(revokeRequest) });
        }
        await waitForLicenseRowWaiters(db, 2);
        release();
        await blocker;
      } finally {
        release();
        await blocker.catch(() => undefined);
      }
      const [revoked, committed] = await Promise.all([revokePromise!, commitPromise!]);
      const finalLicense = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
      const plan = await db.selectFrom('license_disaster_transfer_plans').selectAll()
        .where('approval_id', '=', approved.approval.operationId).executeTakeFirstOrThrow();
      const activeRows = await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId)
        .where('state', '=', 'active').execute();
      if (revokeFirst) {
        expect(revoked.state).toBe('succeeded');
        expect(committed.status).toBe(409);
        expect((await verifyCenterJwt(committed.json['operation_receipt'] as string)).payload['outcome_code'])
          .toBe('DISASTER_TICKET_CONSUMED');
        expect(plan.state).toBe('invalidated');
        expect(finalLicense.current_generation).toBe('1');
        expect(finalLicense.revision).toBe(before.revision);
        expect(activeRows).toMatchObject([expect.objectContaining({ identity_jkt: active.source.jkt })]);
        expect(await db.selectFrom('license_disaster_transfer_revocations').selectAll()
          .where('approval_id', '=', approved.approval.operationId).execute()).toHaveLength(1);
        expect(await db.selectFrom('license_disaster_transfer_events').selectAll()
          .where('approval_id', '=', approved.approval.operationId).where('kind', '=', 'approval_revoked').execute()).toHaveLength(1);
      } else {
        expect(committed.status).toBe(200);
        expect(revoked.state).toBe('rejected');
        expect(revoked.outcomeCode).toBe('EXPECTED_REVISION_MISMATCH');
        expect(plan.state).toBe('committed');
        expect(finalLicense.current_generation).toBe('2');
        expect(finalLicense.revision).toBe(plusOne(before.revision));
        expect(finalLicense.entitlement_revision).toBe(before.entitlement_revision);
        expect(activeRows).toMatchObject([expect.objectContaining({ identity_jkt: target.jkt, generation: '2' })]);
        expect(await db.selectFrom('license_disaster_transfer_revocations').selectAll()
          .where('approval_id', '=', approved.approval.operationId).execute()).toHaveLength(0);
        expect(await db.selectFrom('license_disaster_transfer_events').selectAll()
          .where('approval_id', '=', approved.approval.operationId).where('kind', '=', 'committed').execute()).toHaveLength(1);
        const replay = await makeCommitAttempt(prepared, { operationId: commitAttempt.operationId, attemptNo: 2 });
        expect((await sendCommit(replay.attempt, target)).json['transfer_receipt']).toBe(committed.json['transfer_receipt']);
        expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation)
          .toBe('2');
      }
      expect(activeRows).toHaveLength(1);
      expect(finalLicense.current_generation).toBe(revokeFirst ? '1' : '2');
    }
    await race(true);
    await race(false);
  });

  it('supports a newly approved logical instance id while retaining the original database id', async () => {
    const active = await activate();
    const target = await createIdentity();
    const targetInstanceId = randomUUID();
    const approved = await approveDisaster(active, target, { targetInstanceMode: 'replace', targetInstanceId });
    expect(approved.approval.state).toBe('succeeded');
    const prepared = await prepare(approved);
    const committed = await commit(prepared);
    expect(committed.response.status).toBe(200);
    const current = await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId)
      .where('state', '=', 'active').executeTakeFirstOrThrow();
    expect(current).toMatchObject({ instance_id: targetInstanceId, database_id: active.databaseId, identity_jkt: target.jkt, generation: '2' });
  });

  it('serializes disaster replacements from different licenses to the same target instance', async () => {
    const activeA = await activate();
    const activeB = await activate();
    const targetInstanceId = randomUUID();
    const targetA = await createIdentity();
    const targetB = await createIdentity();
    const preparedA = await prepare(await approveDisaster(activeA, targetA, {
      targetInstanceMode: 'replace', targetInstanceId,
    }));
    const preparedB = await prepare(await approveDisaster(activeB, targetB, {
      targetInstanceMode: 'replace', targetInstanceId,
    }));
    const attemptA = await makeCommitAttempt(preparedA);
    const attemptB = await makeCommitAttempt(preparedB);
    let acquired!: () => void;
    let release!: () => void;
    const acquiredPromise = new Promise<void>((resolve) => { acquired = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    const blocker = db.transaction().execute(async (trx) => {
      await sql`SELECT pg_advisory_xact_lock(hashtextextended(${'activation-instance:' + targetInstanceId}, 0))`.execute(trx);
      acquired();
      await releasePromise;
    });
    await acquiredPromise;
    try {
      const first = sendCommit(attemptA.attempt, targetA);
      await waitForAdvisoryLockWaiters(db, 1);
      const second = sendCommit(attemptB.attempt, targetB);
      await waitForAdvisoryLockWaiters(db, 2);
      release();
      const [responseA, responseB] = await Promise.all([first, second]);
      expect(responseA.status).toBe(200);
      expect(responseB.status).toBe(409);
      expect((await verifyCenterJwt(responseB.json['operation_receipt'] as string)).payload['outcome_code'])
        .toBe('DISASTER_TARGET_INSTANCE_ALREADY_ACTIVE');
    } finally {
      release();
      await blocker;
    }
    const activeAtTarget = await db.selectFrom('license_activations').selectAll()
      .where('instance_id', '=', targetInstanceId).where('state', '=', 'active').execute();
    expect(activeAtTarget).toHaveLength(1);
    expect(activeAtTarget[0]!.license_id).toBe(activeA.licenseId);
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', activeA.licenseId).executeTakeFirstOrThrow()).current_generation)
      .toBe('2');
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', activeB.licenseId).executeTakeFirstOrThrow()).current_generation)
      .toBe('1');
    expect((await db.selectFrom('license_operations').selectAll().where('operation_id', '=', attemptA.operationId).executeTakeFirstOrThrow()).state)
      .toBe('committed');
    expect((await db.selectFrom('license_operations').selectAll().where('operation_id', '=', attemptB.operationId).executeTakeFirstOrThrow()).state)
      .toBe('rejected');
  });

  it('does not authorize a revoked disaster target to append business history for an unknown operation', async () => {
    const active = await activate();
    const target = await createIdentity();
    const approved = await approveDisaster(active, target);
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const revokeRequest = {
      operationId: randomUUID(), licenseId: active.licenseId, approvalId: approved.approval.operationId,
      expectedRevision: license.revision.toString(), reason: '撤销后目标不再是当前有效审批身份',
    };
    const revoked = await admin.revokeDisasterTransferApproval({ ...revokeRequest,
      confirmedRequestDigest: revokeDisasterTransferApprovalRequestDigest(revokeRequest) });
    expect(revoked.state).toBe('succeeded');

    const unknownOperationId = randomUUID();
    const unknownIntentDigest = sha256(randomUUID());
    const response = await queryOperation({
      licenseId: active.licenseId, databaseId: active.databaseId,
      instanceId: approved.request.targetInstanceId, identity: target,
      operationId: unknownOperationId, intentDigest: unknownIntentDigest, attemptNo: 1,
    });
    expect(response.status).toBe(200);
    expect((await verifyCenterJwt(response.json['operation_receipt'] as string)).payload['state']).toBe('not_found');
    expect(await db.selectFrom('license_operations').selectAll()
      .where('operation_id', '=', unknownOperationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_operation_attempts').selectAll()
      .where('operation_id', '=', unknownOperationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_audit_events').selectAll()
      .where('license_id', '=', active.licenseId).where('operation_id', '=', unknownOperationId).execute()).toHaveLength(0);
  });

  it('expired and revoked licenses get only the strict historical binding JWT, then require a new entitlement lease', async () => {
    const expired = await activate();
    const past = new Date((await getDbNow(db)).getTime() - 60_000);
    await db.updateTable('licenses').set({ confirmed_subscription_end: past }).where('id', '=', expired.licenseId).execute();
    const expiredTarget = await createIdentity();
    const expiredPrepared = await prepare(await approveDisaster(expired, expiredTarget));
    const expiredCommit = await commit(expiredPrepared);
    expect(expiredCommit.response.status).toBe(200);
    const expiredBinding = expiredCommit.response.json['binding_receipt'];
    if (typeof expiredBinding !== 'string') throw new Error('Expired binding receipt missing');
    const expiredContext = (await loadTrustedSigningContext(db, runtime.config)).context;
    const expiredValidationNow = new Date(expiredContext.trustedTime * 1000);
    const expiredClaims = await verifyDisasterBindingReceipt(expiredBinding, expiredContext, expiredValidationNow);
    expect((await verifyCenterJwt(expiredBinding)).protectedHeader['typ']).toBe('aikayun-license-disaster-binding+jwt');
    expect(expiredClaims).toMatchObject({ result_mode: 'binding_only', entitlement_state: 'expired', license_status: 'active',
      purpose: 'historical_obligations_identity_rebinding' });
    expect(expiredClaims['new_lease']).toBeUndefined();
    expect(expiredClaims['grants']).toBeUndefined();
    await expect(verifyLicenseLease(expiredBinding, expiredContext, expiredValidationNow)).rejects.toThrow();
    const expiredClaimsRecord = expiredClaims as Record<string, unknown>;
    const bindingWithLease = await signTypedJwt(runtime.config, 'aikayun-license-disaster-binding+jwt', {
      ...expiredClaimsRecord, new_lease: 'forbidden',
    });
    await expect(verifyDisasterBindingReceipt(bindingWithLease, expiredContext, expiredValidationNow)).rejects.toThrow();
    const bindingOverlong = await signTypedJwt(runtime.config, 'aikayun-license-disaster-binding+jwt', {
      ...expiredClaimsRecord, exp: Number(expiredClaimsRecord['iat']) + 601,
    });
    await expect(verifyDisasterBindingReceipt(bindingOverlong, expiredContext, expiredValidationNow)).rejects.toThrow();
    const expiredRevision = await db.selectFrom('licenses').selectAll().where('id', '=', expired.licenseId).executeTakeFirstOrThrow();
    const renewal = { operationId: randomUUID(), licenseId: expired.licenseId, expectedRevision: expiredRevision.revision,
      businessReference: `verified-renewal-${randomUUID()}`, reason: '独立确认续费后恢复新订单权限' };
    const renewalResult = await admin.renewLicense({ ...renewal, confirmedRequestDigest: renewLicenseRequestDigest(renewal) });
    expect(renewalResult.state).toBe('succeeded');
    const renewed = await db.selectFrom('licenses').selectAll().where('id', '=', expired.licenseId).executeTakeFirstOrThrow();
    const postRenewal = await renewAs(expired, expiredTarget, renewed.current_generation.toString(), renewed.entitlement_revision.toString());
    expect(postRenewal.status).toBe(200);
    expect((await verifyCenterJwt(postRenewal.json['license'] as string)).payload['grants']).toEqual(['create_order', 'create_top_up']);

    const revoked = await activate();
    let revokedLicense = await db.selectFrom('licenses').selectAll().where('id', '=', revoked.licenseId).executeTakeFirstOrThrow();
    const revokeBase = { operationId: randomUUID(), licenseId: revoked.licenseId, expectedRevision: revokedLicense.revision,
      reason: '独立确认license撤销状态保持有效' };
    expect((await admin.revokeLicense({ ...revokeBase,
      confirmedRequestDigest: changeLicenseStatusRequestDigest(revokeBase, 'license_revoke') })).state).toBe('succeeded');
    const revokedTarget = await createIdentity();
    const revokedPrepared = await prepare(await approveDisaster(revoked, revokedTarget));
    const revokedCommit = await commit(revokedPrepared);
    expect(revokedCommit.response.status).toBe(200);
    const revokedBinding = revokedCommit.response.json['binding_receipt'];
    if (typeof revokedBinding !== 'string') throw new Error('Revoked binding receipt missing');
    const revokedContext = (await loadTrustedSigningContext(db, runtime.config)).context;
    const revokedValidationNow = new Date(revokedContext.trustedTime * 1000);
    const revokedClaims = await verifyDisasterBindingReceipt(revokedBinding, revokedContext, revokedValidationNow);
    expect((await verifyCenterJwt(revokedBinding)).protectedHeader['typ']).toBe('aikayun-license-disaster-binding+jwt');
    expect(revokedClaims).toMatchObject({ result_mode: 'binding_only', entitlement_state: 'revoked', license_status: 'revoked' });
    expect(revokedClaims['grants']).toBeUndefined();
    revokedLicense = await db.selectFrom('licenses').selectAll().where('id', '=', revoked.licenseId).executeTakeFirstOrThrow();
    const restoreBase = { operationId: randomUUID(), licenseId: revoked.licenseId, expectedRevision: revokedLicense.revision,
      reason: '权益经正常管理流程恢复后重新申请经营凭证' };
    expect((await admin.restoreLicense({ ...restoreBase,
      confirmedRequestDigest: changeLicenseStatusRequestDigest(restoreBase, 'license_restore') })).state).toBe('succeeded');
    const restored = await db.selectFrom('licenses').selectAll().where('id', '=', revoked.licenseId).executeTakeFirstOrThrow();
    const postRestore = await renewAs(revoked, revokedTarget, restored.current_generation.toString(), restored.entitlement_revision.toString());
    expect(postRestore.status).toBe(200);
    expect((await verifyCenterJwt(postRestore.json['license'] as string)).payload['entitlement_revision']).toBe(restored.entitlement_revision);
  });

  async function renewAs(active: ActiveSource, identity: TestIdentity, generation: string, knownRevision: string): Promise<HttpResponse> {
    const operationId = randomUUID();
    const intentDigest = renewalIntentDigest({ kind: 'renewal', licenseId: active.licenseId, databaseId: active.databaseId,
      instanceId: identity === active.source ? active.instanceId : identityInstance(identity, active),
      identityJkt: identity.jkt, expectedGeneration: generation, knownRevision });
    const instanceId = identityInstance(identity, active);
    const challenge = await requestChallenge({ port: server.port, config: runtime.config, identity, operation: 'renewal',
      operationId, intentDigest, instanceId });
    const body = {
      ...buildChallengeBoundBody({ challenge: challenge.token, operationId, intentDigest, attemptNo: 1,
        instanceId, identity, licenseId: active.licenseId, databaseId: active.databaseId }),
      expected_generation: generation, known_revision: knownRevision,
    };
    return signPost({ port: server.port, origin: runtime.config.publicOrigin, path: '/v1/leases/renew', body,
      identity, nonce: nonceFromChallenge(challenge.token) });
  }

  function identityInstance(identity: TestIdentity, active: ActiveSource): string {
    const key = identity.publicJwk.x;
    const cached = committedInstances.get(key);
    return cached ?? active.instanceId;
  }

  const committedInstances = new Map<string, string>();

  it('returns superseded to the retired source and lets the target renew under current rights', async () => {
    const active = await activate();
    const target = await createIdentity();
    const prepared = await prepare(await approveDisaster(active, target));
    expect((await commit(prepared)).response.status).toBe(200);
    committedInstances.set(target.publicJwk.x, active.instanceId);
    const current = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const old = await renewAs(active, active.source, '1', current.entitlement_revision.toString());
    expect(old.status).toBe(409);
    expect((await verifyCenterJwt(old.json['status_receipt'] as string)).payload['status']).toBe('superseded');
    expect(old.json['license']).toBeUndefined();
    const fresh = await renewAs(active, target, '2', current.entitlement_revision.toString());
    expect(fresh.status).toBe(200);
    expect((await verifyCenterJwt(fresh.json['license'] as string)).payload['identity_jkt']).toBe(target.jkt);
  });

  it('recovers prepare and commit after dropped HTTP responses and COMMIT acknowledgement loss by replaying the same operation', async () => {
    const active = await activate();
    const target = await createIdentity();
    const approved = await approveDisaster(active, target);
    const httpProxy = new HttpResponseDropProxy();
    await httpProxy.start(server.port, runtime.config.tlsPrivateKey, runtime.config.tlsCertificate);
    try {
      const lostPrepare = await makePrepareAttempt(approved);
      const dropPrepare = httpProxy.armNextResponseDrop();
      const firstPrepare = sendPrepare(lostPrepare.attempt, target, httpProxy.port).catch((error: unknown) => error);
      await dropPrepare;
      await firstPrepare;
      const durablePrepare = await db.selectFrom('license_operations').selectAll()
        .where('operation_id', '=', lostPrepare.operationId).executeTakeFirstOrThrow();
      const prepareQuery = await queryOperation({ licenseId: active.licenseId, databaseId: active.databaseId,
        instanceId: approved.request.targetInstanceId, identity: target, operationId: lostPrepare.operationId,
        intentDigest: lostPrepare.intentDigest, attemptNo: 2 });
      expect(prepareQuery.status).toBe(200);
      const prepareQueryReceipt = await verifyCenterJwt(prepareQuery.json['operation_receipt'] as string);
      expect(prepareQueryReceipt.payload['state']).toBe('committed');
      expect(prepareQueryReceipt.payload['result_jws']).toBe(durablePrepare.response_jws);
      expect(await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId)
        .where('state', '=', 'active').executeTakeFirstOrThrow()).toMatchObject({ identity_jkt: active.source.jkt });
      const retryPrepare = await makePrepareAttempt(approved, { operationId: lostPrepare.operationId, attemptNo: 3 });
      expect(retryPrepare.intentDigest).toBe(lostPrepare.intentDigest);
      const replayPrepare = await sendPrepare(retryPrepare.attempt, target);
      expect(replayPrepare.status).toBe(200);
      expect(replayPrepare.json['disaster_transfer_ticket']).toBe(durablePrepare.response_jws);
      const prepared: PreparedDisaster = { ...approved, prepareOperationId: lostPrepare.operationId,
        prepareIntentDigest: lostPrepare.intentDigest, ticket: durablePrepare.response_jws };

      const lostCommit = await makeCommitAttempt(prepared);
      const dropCommit = httpProxy.armNextResponseDrop();
      const firstCommit = sendCommit(lostCommit.attempt, target, httpProxy.port).catch((error: unknown) => error);
      await dropCommit;
      await firstCommit;
      const durableCommit = await db.selectFrom('license_operations').selectAll()
        .where('operation_id', '=', lostCommit.operationId).executeTakeFirstOrThrow();
      const commitQuery = await queryOperation({ licenseId: active.licenseId, databaseId: active.databaseId,
        instanceId: approved.request.targetInstanceId, identity: target, operationId: lostCommit.operationId,
        intentDigest: lostCommit.intentDigest, attemptNo: 2 });
      expect(commitQuery.status).toBe(200);
      const commitQueryReceipt = await verifyCenterJwt(commitQuery.json['operation_receipt'] as string);
      expect(commitQueryReceipt.payload['state']).toBe('committed');
      expect(commitQueryReceipt.payload['result_jws']).toBe(durableCommit.response_jws);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation)
        .toBe('2');
      const replayCommit = await commit(prepared, { operationId: lostCommit.operationId, attemptNo: 3 });
      expect(replayCommit.response.status).toBe(200);
      expect(replayCommit.response.json['transfer_receipt']).toBe(durableCommit.response_jws);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
      expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', lostCommit.operationId).execute()).toHaveLength(1);
      expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', lostCommit.operationId)
        .where('outcome', '=', 'accepted').execute()).toHaveLength(1);
    } finally {
      await httpProxy.stop();
    }

    const active2 = await activate();
    const target2 = await createIdentity();
    const prepared2 = await prepare(await approveDisaster(active2, target2));
    const proxy = new CommitAckDropProxy();
    const databaseUrl = new URL(runtime.config.databaseUrl);
    await proxy.start(databaseUrl.hostname, Number(databaseUrl.port || '5432'));
    const proxyUrl = new URL(runtime.config.databaseUrl);
    proxyUrl.port = String(proxy.port);
    proxyUrl.searchParams.set('sslmode', 'disable');
    const proxyDb = createDatabase(proxyUrl.toString(), 4);
    const proxyServer = await startAppServer(createApp({ config: runtime.config, db: proxyDb }), runtime.config);
    try {
      const lost = await makeCommitAttempt(prepared2, { challengePort: server.port });
      const ack = proxy.armNextCommitAckDrop(1);
      expect((await sendCommit(lost.attempt, target2, proxyServer.port)).status).toBe(500);
      await ack;
      const saved = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', lost.operationId).executeTakeFirstOrThrow();
      const replay = await commit(prepared2, { operationId: lost.operationId, attemptNo: 2 });
      expect(replay.response.status).toBe(200);
      expect(replay.response.json['transfer_receipt']).toBe(saved.response_jws);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active2.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
    } finally {
      await proxyServer.stop();
      await proxyDb.destroy();
      await proxy.stop();
    }
  });

  it('rolls back trigger failures and SIGKILL transactions, then resumes the same commit operation', async () => {
    const active = await activate();
    const target = await createIdentity();
    const prepared = await prepare(await approveDisaster(active, target));
    const operationId = randomUUID();
    const first = await makeCommitAttempt(prepared, { operationId });
    await sql`CREATE OR REPLACE FUNCTION disaster_test_force_activation_failure() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'forced disaster transfer rollback' USING ERRCODE = 'P0001'; END $$`.execute(db);
    await sql`CREATE TRIGGER disaster_test_force_activation_failure BEFORE INSERT ON license_activations
      FOR EACH ROW EXECUTE FUNCTION disaster_test_force_activation_failure()`.execute(db);
    try {
      expect((await sendCommit(first.attempt, target)).status).toBe(500);
      expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', operationId).execute()).toHaveLength(0);
      expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', operationId).execute()).toHaveLength(0);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');
      expect((await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId)
        .where('state', '=', 'active').executeTakeFirstOrThrow()).identity_jkt).toBe(active.source.jkt);
    } finally {
      await sql`DROP TRIGGER IF EXISTS disaster_test_force_activation_failure ON license_activations`.execute(db);
      await sql`DROP FUNCTION IF EXISTS disaster_test_force_activation_failure()`.execute(db);
    }
    const retried = await makeCommitAttempt(prepared, { operationId, attemptNo: 2 });
    expect(retried.intentDigest).toBe(first.intentDigest);
    expect((await sendCommit(retried.attempt, target)).status).toBe(200);

    const active2 = await activate();
    const target2 = await createIdentity();
    const prepared2 = await prepare(await approveDisaster(active2, target2));
    const blockerReady = deferred<void>();
    const releaseBlocker = deferred<void>();
    const blocker = db.transaction().execute(async (trx) => {
      await trx.selectFrom('licenses').select('id').where('id', '=', active2.licenseId).forUpdate().executeTakeFirstOrThrow();
      blockerReady.resolve();
      await releaseBlocker.promise;
    });
    await blockerReady.promise;
    let child: Awaited<ReturnType<typeof startChildLicenseServer>> | undefined;
    let restarted: Awaited<ReturnType<typeof startChildLicenseServer>> | undefined;
    const killedOperationId = randomUUID();
    try {
      child = await startChildLicenseServer({ databaseUrl: runtime.config.databaseUrl, issuer: runtime.config.issuer,
        publicOrigin: runtime.config.publicOrigin, keyringFile: runtime.keyringFile,
        offlineRootJwkFile: runtime.offlineRootJwkFile, minimumTrustBundleVersion: runtime.config.minimumTrustBundleVersion,
        tlsKeyFile: runtime.config.tlsKeyFile, tlsCertFile: runtime.config.tlsCertFile });
      const attempt = await makeCommitAttempt(prepared2, { operationId: killedOperationId, challengePort: server.port });
      const response = sendCommit(attempt.attempt, target2, child.port).catch((error: unknown) => error);
      const [pid] = await waitForLicenseRowWaiterPids(db, 1);
      if (pid === undefined) throw new Error('Expected a PostgreSQL row-lock waiter for disaster commit');
      await child.stop('SIGKILL');
      await terminatePostgresBackend(db, pid);
      await waitForNoLockWaiters(db);
      const lost = await response;
      expect(lost instanceof Error || (lost as HttpResponse).status >= 500).toBe(true);
      expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', killedOperationId).execute()).toHaveLength(0);
      expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', killedOperationId).execute()).toHaveLength(0);
      expect((await db.selectFrom('request_nonces').selectAll().where('nonce_hash', '=', sha256(attempt.attempt.nonce))
        .executeTakeFirstOrThrow()).consumed_at).toBeNull();
      expect((await db.selectFrom('license_disaster_transfer_plans').selectAll()
        .where('prepare_operation_id', '=', prepared2.prepareOperationId).executeTakeFirstOrThrow()).state).toBe('prepared');
      releaseBlocker.resolve();
      await blocker;
      restarted = await startChildLicenseServer({ databaseUrl: runtime.config.databaseUrl, issuer: runtime.config.issuer,
        publicOrigin: runtime.config.publicOrigin, keyringFile: runtime.keyringFile,
        offlineRootJwkFile: runtime.offlineRootJwkFile, minimumTrustBundleVersion: runtime.config.minimumTrustBundleVersion,
        tlsKeyFile: runtime.config.tlsKeyFile, tlsCertFile: runtime.config.tlsCertFile });
      const retry = await makeCommitAttempt(prepared2, { operationId: killedOperationId, attemptNo: 2, challengePort: server.port });
      expect((await sendCommit(retry.attempt, target2, restarted.port)).status).toBe(200);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active2.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
    } finally {
      releaseBlocker.resolve();
      await blocker.catch(() => undefined);
      await child?.stop().catch(() => undefined);
      await restarted?.stop().catch(() => undefined);
    }
  });

  it('requires fresh signed challenges, rejects wrong signatures and cross-purpose tickets, and never consumes one ticket twice', async () => {
    const active = await activate();
    const target = await createIdentity();
    const prepared = await prepare(await approveDisaster(active, target));
    const wrongSigner = await createIdentity();
    expect((await sendPrepare((await makePrepareAttempt(prepared)).attempt, wrongSigner)).status).toBe(401);

    const committed = await commit(prepared);
    expect(committed.response.status).toBe(200);
    const replay = await commit(prepared, { operationId: committed.operationId, attemptNo: 2 });
    expect(replay.response.status).toBe(200);
    expect(replay.response.json['transfer_receipt']).toBe(committed.response.json['transfer_receipt']);
    const staleNonceAttempt = { ...committed.attempt, body: { ...committed.attempt.body, attempt_no: 2 } };
    const staleNonceReplay = await sendCommit(staleNonceAttempt, target);
    expect(staleNonceReplay.status).toBe(409);
    expect(staleNonceReplay.json['error']).toMatchObject({ code: 'ATTEMPT_NUMBER_REUSED' });
    const secondOperation = await commit(prepared);
    expect(secondOperation.response.status).toBe(409);
    expect((await verifyCenterJwt(secondOperation.response.json['operation_receipt'] as string)).payload['outcome_code'])
      .toBe('DISASTER_TICKET_CONSUMED');
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');

    const normal = await activate();
    const normalTarget = await createIdentity();
    const normalPlan = await prepareNormal(normal, normalTarget);
    const disasterTarget = await createIdentity();
    const disasterApproval = await approveDisaster(normal, disasterTarget);
    expect(disasterApproval.approval.state).toBe('rejected');
    const forgedDisaster = { ...prepared, ticket: normalPlan.ticket };
    const wrongPurpose = await makeCommitAttempt(forgedDisaster);
    expect((await sendCommit(wrongPurpose.attempt, prepared.target)).status).toBe(401);
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', wrongPurpose.operationId).execute()).toHaveLength(0);
  });

  it('rejects an expired disaster ticket at the real HTTPS commit boundary without changing the source', async () => {
    const active = await activate();
    const target = await createIdentity();
    const approved = await approveDisaster(active, target);
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const source = await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', active.licenseId).where('state', '=', 'active').executeTakeFirstOrThrow();
    const prepareOperationId = randomUUID();
    const prepareIntentDigest = disasterTransferPrepareIntentDigest({
      licenseId: active.licenseId, accountReference: approved.request.accountReference, databaseId: active.databaseId,
      approvalId: approved.approval.operationId, requestId: approved.request.operationId,
      sourceActivationId: source.id, sourceInstanceId: active.instanceId, sourceIdentityJkt: active.source.jkt,
      targetInstanceId: approved.request.targetInstanceId, targetIdentityJkt: target.jkt,
      sourceGeneration: license.current_generation.toString(), expectedBindingRevision: approved.request.expectedBindingRevision,
      expectedRevision: license.revision.toString(),
    });
    const prepareRequestNonce = randomBytes(32).toString('base64url');
    const prepareRequestDigest = sha256(randomUUID());
    const issuedAt = Math.floor((await getDbNow(db)).getTime() / 1000) - 20 * 60;
    const planId = randomUUID();
    const ticket = await signDisasterTransferTicket(runtime.config, {
      plan_id: planId, request_id: approved.request.operationId, approval_id: approved.approval.operationId,
      approval_request_digest: approved.approval.requestDigest, prepare_operation_id: prepareOperationId,
      prepare_intent_digest: prepareIntentDigest, prepare_request_nonce: prepareRequestNonce,
      prepare_request_digest: prepareRequestDigest, license_id: active.licenseId,
      account_reference: approved.request.accountReference, database_id: active.databaseId,
      source_activation_id: source.id, source_instance_id: active.instanceId, source_identity_jkt: active.source.jkt,
      source_activation_generation: license.current_generation.toString(),
      target_instance_id: approved.request.targetInstanceId, target_identity_jkt: target.jkt,
      expected_binding_revision: approved.request.expectedBindingRevision, expected_revision: license.revision.toString(),
      entitlement_revision: license.entitlement_revision.toString(), now: new Date(issuedAt * 1000),
    });
    const expiresAt = new Date((issuedAt + 600) * 1000);
    await db.insertInto('license_operations').values({
      operation_id: prepareOperationId, actor_jkt: target.jkt, intent_digest: prepareIntentDigest,
      kind: 'disaster_transfer_prepare', license_id: active.licenseId, database_id: active.databaseId,
      state: 'committed', outcome_code: 'DISASTER_TRANSFER_PREPARED', response_type: 'disaster_ticket',
      result_generation: license.current_generation.toString(), result_revision: license.entitlement_revision.toString(),
      response_jws: ticket, result_digest: sha256(ticket), created_at: new Date(issuedAt * 1000),
      finalized_at: new Date(issuedAt * 1000),
    }).execute();
    await db.insertInto('license_operation_attempts').values({
      attempt_id: randomUUID(), operation_id: prepareOperationId, attempt_no: 1,
      intent_digest: prepareIntentDigest, body_digest: prepareRequestDigest,
      client_nonce_hash: sha256(randomUUID()), server_nonce_hash: sha256(prepareRequestNonce), identity_jkt: target.jkt,
      signature_created_at: new Date(issuedAt * 1000), received_at: new Date(issuedAt * 1000),
      outcome: 'accepted', error_code: null,
    }).execute();
    await db.insertInto('license_disaster_transfer_plans').values({
      plan_id: planId, request_id: approved.request.operationId, approval_id: approved.approval.operationId,
      license_id: active.licenseId, prepare_operation_id: prepareOperationId, prepare_intent_digest: prepareIntentDigest,
      source_activation_id: source.id, database_id: active.databaseId, source_instance_id: active.instanceId,
      source_identity_jkt: active.source.jkt, target_instance_id: approved.request.targetInstanceId,
      target_identity_jkt: target.jkt, target_identity_jwk_public: target.publicJwk,
      source_generation: license.current_generation.toString(), expected_binding_revision: approved.request.expectedBindingRevision,
      expected_revision: license.revision.toString(), entitlement_revision: license.entitlement_revision.toString(),
      ticket_jws: ticket, ticket_digest: sha256(ticket), state: 'prepared', expires_at: expiresAt,
      created_at: new Date(issuedAt * 1000), committed_at: null, commit_operation_id: null,
      committed_generation: null, result_mode: null, disaster_result_jws: null,
    }).execute();

    const result = await commit({ ...approved, prepareOperationId, prepareIntentDigest, ticket });
    expect(result.response.status).toBe(409);
    expect((await verifyCenterJwt(result.response.json['operation_receipt'] as string)).payload['outcome_code'])
      .toBe('DISASTER_TICKET_EXPIRED');
    expect((await db.selectFrom('license_disaster_transfer_plans').selectAll()
      .where('plan_id', '=', planId).executeTakeFirstOrThrow()).state).toBe('expired');
    const after = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect(after.current_generation).toBe(license.current_generation);
    expect(after.revision).toBe(license.revision);
    expect(await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId)
      .where('state', '=', 'active').execute()).toMatchObject([expect.objectContaining({ identity_jkt: active.source.jkt })]);
  });

  async function prepareNormal(active: ActiveSource, target: TestIdentity) {
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const approvalRequest: Omit<ApproveTransferRequest, 'confirmedRequestDigest'> = {
      operationId: randomUUID(), licenseId: active.licenseId, expectedRevision: license.revision.toString(),
      reason: '测试正常迁移与灾难迁移互斥', databaseId: active.databaseId, sourceInstanceId: active.instanceId,
      sourceIdentityJkt: active.source.jkt, targetInstanceId: active.instanceId, targetIdentityJkt: target.jkt,
      sourceGeneration: license.current_generation.toString(), expectedBindingRevision: '7',
    };
    const approval = await admin.approveTransfer({ ...approvalRequest,
      confirmedRequestDigest: approveTransferRequestDigest(approvalRequest) });
    expect(approval.state).toBe('succeeded');
    const operationId = randomUUID();
    const intentDigest = transferPrepareIntentDigest({
      licenseId: active.licenseId, databaseId: active.databaseId, instanceId: active.instanceId,
      sourceIdentityJkt: active.source.jkt, targetInstanceId: active.instanceId, targetIdentityJkt: target.jkt,
      approvalId: approval.operationId, sourceGeneration: license.current_generation.toString(),
      expectedBindingRevision: '7', expectedRevision: license.revision.toString(),
    });
    const challenge = await requestChallenge({ port: server.port, config: runtime.config, identity: active.source,
      operation: 'transfer_prepare', operationId, intentDigest, instanceId: active.instanceId });
    const body = {
      ...buildChallengeBoundBody({ challenge: challenge.token, operationId, intentDigest, attemptNo: 1,
        instanceId: active.instanceId, identity: active.source, licenseId: active.licenseId, databaseId: active.databaseId }),
      approval_id: approval.operationId, target_instance_id: active.instanceId, target_identity_jkt: target.jkt,
      target_public_jwk: target.publicJwk, source_generation: license.current_generation.toString(),
      expected_binding_revision: '7', expected_revision: license.revision.toString(),
    };
    const response = await signPost({ port: server.port, origin: runtime.config.publicOrigin, path: '/v1/transfers/prepare',
      body, identity: active.source, nonce: nonceFromChallenge(challenge.token) });
    expect(response.status).toBe(200);
    return { approval, target, operationId, intentDigest, ticket: response.json['transfer_ticket'] as string };
  }

  async function commitNormalTicket(active: ActiveSource, prepared: {
    approval: AdminOperationResult;
    target: TestIdentity;
    operationId: string;
    ticket: string;
  }): Promise<HttpResponse> {
    const operationId = randomUUID();
    const intentDigest = transferCommitIntentDigest({
      licenseId: active.licenseId, databaseId: active.databaseId, instanceId: active.instanceId,
      targetIdentityJkt: prepared.target.jkt, approvalId: prepared.approval.operationId,
      prepareOperationId: prepared.operationId, ticketDigest: sha256(prepared.ticket),
    });
    const challenge = await requestChallenge({ port: server.port, config: runtime.config, identity: prepared.target,
      operation: 'transfer_commit', operationId, intentDigest, instanceId: active.instanceId });
    const body = {
      ...buildChallengeBoundBody({ challenge: challenge.token, operationId, intentDigest, attemptNo: 1,
        instanceId: active.instanceId, identity: prepared.target, licenseId: active.licenseId, databaseId: active.databaseId }),
      approval_id: prepared.approval.operationId,
      prepare_operation_id: prepared.operationId,
      transfer_ticket: prepared.ticket,
    };
    return signPost({ port: server.port, origin: runtime.config.publicOrigin, path: '/v1/transfers/commit',
      body, identity: prepared.target, nonce: nonceFromChallenge(challenge.token) });
  }

  it('serializes disaster commit with revoke, restore and renewal whichever transaction obtains the license row first', async () => {
    async function gate(licenseId: string) {
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

    async function runRace(kind: 'revoke' | 'restore' | 'renew', commitFirst: boolean) {
      const active = await activate();
      if (kind === 'restore') {
        const beforeRevoke = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
        const revoke = { operationId: randomUUID(), licenseId: active.licenseId, expectedRevision: beforeRevoke.revision,
          reason: '为恢复锁顺序测试先建立revoked状态' };
        await admin.revokeLicense({ ...revoke, confirmedRequestDigest: changeLicenseStatusRequestDigest(revoke, 'license_revoke') });
      }
      const target = await createIdentity();
      const approved = await approveDisaster(active, target);
      expect(approved.approval.state).toBe('succeeded');
      const prepared = await prepare(approved);
      const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
      const operationId = randomUUID();
      const commitAttempt = await makeCommitAttempt(prepared, { operationId });
      const adminRequest = {
        operationId: randomUUID(), licenseId: active.licenseId, expectedRevision: license.revision.toString(),
        reason: `按许可证锁串行化测试${kind}`,
      };
      const adminCall = () => kind === 'revoke'
        ? admin.revokeLicense({ ...adminRequest, confirmedRequestDigest: changeLicenseStatusRequestDigest(adminRequest, 'license_revoke') })
        : kind === 'restore'
          ? admin.restoreLicense({ ...adminRequest, confirmedRequestDigest: changeLicenseStatusRequestDigest(adminRequest, 'license_restore') })
          : admin.renewLicense({ ...adminRequest, businessReference: `race-${randomUUID()}`,
            confirmedRequestDigest: renewLicenseRequestDigest({ ...adminRequest, businessReference: `race-${randomUUID()}` }) });
      // Keep the business reference and its digest identical on the renewal branch.
      let call = adminCall;
      if (kind === 'renew') {
        const renewal = { ...adminRequest, businessReference: `race-${randomUUID()}` };
        const digest = renewLicenseRequestDigest(renewal);
        call = () => admin.renewLicense({ ...renewal, confirmedRequestDigest: digest });
      }
      const lock = await gate(active.licenseId);
      let commitPromise: Promise<HttpResponse>;
      let adminPromise: ReturnType<typeof admin.revokeLicense>;
      if (commitFirst) {
        commitPromise = sendCommit(commitAttempt.attempt, target);
        await waitForLicenseRowWaiters(db, 1);
        adminPromise = call();
      } else {
        adminPromise = call();
        await waitForLicenseRowWaiters(db, 1);
        commitPromise = sendCommit(commitAttempt.attempt, target);
      }
      await waitForLicenseRowWaiters(db, 2);
      lock.release();
      await lock.blocker;
      const [commitResponse, adminResult] = await Promise.all([commitPromise, adminPromise]);
      if (commitFirst) {
        expect(commitResponse.status).toBe(200);
        expect(adminResult.state).toBe('rejected');
        expect(adminResult.outcomeCode).toBe('EXPECTED_REVISION_MISMATCH');
      } else {
        expect(adminResult.state).toBe('succeeded');
        expect(commitResponse.status).toBe(409);
      }
      const final = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
      expect(final.current_generation).toBe(commitFirst ? '2' : '1');
      expect(final.revision).toBe(commitFirst ? plusOne(license.revision.toString()) : plusOne(license.revision.toString()));
      expect(await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId)
        .where('state', '=', 'active').execute()).toHaveLength(1);
    }

    for (const kind of ['revoke', 'restore', 'renew'] as const) {
      await runRace(kind, true);
      await runRace(kind, false);
    }
  });

  it('serializes normal-transfer commit against a disaster approval; no second migration can pass the shared license lock', async () => {
    const previous = { db, server, runtime, admin, policyFile };
    const isolatedRuntime = await createTestSigningRuntime();
    const isolatedDb = createDatabase(isolatedRuntime.config.databaseUrl, 32);
    await migrateToLatest(isolatedDb);
    await isolatedRuntime.initializeAuthority(isolatedDb);
    const isolatedServer = await startAppServer(createApp({ config: isolatedRuntime.config, db: isolatedDb }), isolatedRuntime.config);
    const isolatedPolicy = await writeAdminPolicy(isolatedRuntime.config.databaseUrl);
    const isolatedAdmin = await createAdminService(isolatedPolicy);
    db = isolatedDb;
    server = isolatedServer;
    runtime = isolatedRuntime;
    admin = isolatedAdmin;
    policyFile = isolatedPolicy;
    try {
    async function race(disasterApprovalFirst: boolean) {
      const active = await activate();
      const normalTarget = await createIdentity();
      const normal = await prepareNormal(active, normalTarget);
      const disasterTarget = await createIdentity();
      const disasterRequest = await disasterApprovalRequest(active, disasterTarget);
      const digest = approveDisasterTransferRequestDigest(disasterRequest);
      const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
      const normalCommitOperationId = randomUUID();
      const normalCommitIntent = transferCommitIntentDigest({ licenseId: active.licenseId, databaseId: active.databaseId,
        instanceId: active.instanceId, targetIdentityJkt: normalTarget.jkt, approvalId: normal.approval.operationId,
        prepareOperationId: normal.operationId, ticketDigest: sha256(normal.ticket) });
      const challenge = await requestChallenge({ port: server.port, config: runtime.config, identity: normalTarget,
        operation: 'transfer_commit', operationId: normalCommitOperationId, intentDigest: normalCommitIntent, instanceId: active.instanceId });
      const normalCommitBody = {
        ...buildChallengeBoundBody({ challenge: challenge.token, operationId: normalCommitOperationId, intentDigest: normalCommitIntent,
          attemptNo: 1, instanceId: active.instanceId, identity: normalTarget, licenseId: active.licenseId, databaseId: active.databaseId }),
        approval_id: normal.approval.operationId, prepare_operation_id: normal.operationId, transfer_ticket: normal.ticket,
      };
      const ticketKid = String(decodeProtectedHeader(normal.ticket)['kid']);
      let expectedResultKid = (await db.selectFrom('license_signer_authority').select('active_signing_kid')
        .where('singleton', '=', true).executeTakeFirstOrThrow()).active_signing_kid!;
      if (disasterApprovalFirst) {
        expect(ticketKid).toBe(runtime.onlineKey.kid);
        expect(decodeProtectedHeader(challenge.token)['kid']).toBe(ticketKid);
        const b = await runtime.createOnlineKey();
        await publishAndRotateTo(db, runtime, b, '2');
        expectedResultKid = b.kid;
      } else {
        expect(ticketKid).toBe(expectedResultKid);
        expect(decodeProtectedHeader(challenge.token)['kid']).toBe(ticketKid);
      }
      // A deterministic barrier decides which contender queues on the license row first.
      let release!: () => void;
      let ready!: () => void;
      const entered = new Promise<void>((resolve) => { ready = resolve; });
      const blocked = new Promise<void>((resolve) => { release = resolve; });
      const blocker = db.transaction().execute(async (trx) => {
        await trx.selectFrom('licenses').select('id').where('id', '=', active.licenseId).forUpdate().executeTakeFirstOrThrow();
        ready();
        await blocked;
      });
      await entered;
      const sendNormal = () => signPost({ port: server.port, origin: runtime.config.publicOrigin, path: '/v1/transfers/commit',
        body: normalCommitBody, identity: normalTarget, nonce: nonceFromChallenge(challenge.token) });
      const adminCall = () => admin.approveDisasterTransfer({ ...disasterRequest, confirmedRequestDigest: digest });
      let normalPromise: Promise<HttpResponse>;
      let disasterPromise: ReturnType<typeof admin.approveDisasterTransfer>;
      if (disasterApprovalFirst) {
        disasterPromise = adminCall();
        await waitForLicenseRowWaiters(db, 1);
        normalPromise = sendNormal();
      } else {
        normalPromise = sendNormal();
        await waitForLicenseRowWaiters(db, 1);
        disasterPromise = adminCall();
      }
      await waitForLicenseRowWaiters(db, 2);
      release();
      await blocker;
      const [normalResponse, disasterResult] = await Promise.all([normalPromise, disasterPromise]);
      expect(normalResponse.status).toBe(200);
      expect(decodeProtectedHeader(normal.ticket)['kid']).toBe(ticketKid);
      expect(decodeProtectedHeader(normalResponse.json['transfer_receipt'] as string)['kid']).toBe(expectedResultKid);
      if (disasterApprovalFirst) {
        expect(decodeProtectedHeader(challenge.token)['kid']).not.toBe(expectedResultKid);
      }
      expect(disasterResult.state).toBe('rejected');
      expect(disasterResult.outcomeCode).toMatch(/NORMAL_TRANSFER_REQUIRES_EXPLICIT_REVOCATION|DISASTER_SOURCE_BINDING_MISMATCH|EXPECTED_REVISION_MISMATCH/);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('2');
      expect(await db.selectFrom('license_activations').selectAll().where('license_id', '=', active.licenseId).where('state', '=', 'active').execute())
        .toMatchObject([expect.objectContaining({ identity_jkt: normalTarget.jkt })]);
      expect(license.current_generation).toBe('1');
    }
    await race(true);
    await race(false);
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

  it('rejects unverifiable backup claims and keeps the CLI two-step confirmation boundary', async () => {
    const active = await activate();
    const target = await createIdentity();
    const unverified = await approveDisaster(active, target, { backupCheckResult: 'unable_to_verify' });
    expect(unverified.approval.state).toBe('rejected');
    expect(unverified.approval.outcomeCode).toBe('DISASTER_BACKUP_NOT_VERIFIED');
    expect(await db.selectFrom('license_disaster_transfer_approvals').selectAll()
      .where('license_id', '=', active.licenseId).execute()).toHaveLength(0);
  });

  it('rejects a disaster-transfer Commit after approval expiry while its prepared ticket remains fresh', async () => {
    const active = await activate();
    const target = await createIdentity();
    const base = await getDbNow(db);
    const historicalApprovalTime = new Date(base.getTime() - 59 * 60 * 1000 - 50 * 1000);
    const request = await disasterApprovalRequest(active, target, { expiresInHours: 1 });
    const historicalAdmin = await createAdminService(policyFile, { controlledTestNow: async () => historicalApprovalTime });
    try {
      const approval = await historicalAdmin.approveDisasterTransfer({ ...request,
        confirmedRequestDigest: approveDisasterTransferRequestDigest(request) });
      expect(approval.state).toBe('succeeded');
      const approvalRow = await db.selectFrom('license_disaster_transfer_approvals').selectAll()
        .where('approval_id', '=', approval.operationId).executeTakeFirstOrThrow();
      expect(approvalRow.expires_at.getTime()).toBe(base.getTime() + 10 * 1000);
      const approved: ApprovedDisaster = { active, target, request, approval };
      const prepared = await prepare(approved);
      await new Promise((resolve) => setTimeout(resolve, 15_000));
      const rejectedCommit = await commit(prepared);
      expect(rejectedCommit.response.status).toBe(409);
      expect(typeof rejectedCommit.response.json['operation_receipt']).toBe('string');
      expect(rejectedCommit.response.json).not.toHaveProperty('transfer_receipt');
      expect(rejectedCommit.response.json).not.toHaveProperty('binding_receipt');
      expect(rejectedCommit.response.json).not.toHaveProperty('disaster_transfer_ticket');
      const rejected = await verifyCenterJwt(rejectedCommit.response.json['operation_receipt'] as string);
      expect(rejected.payload).toMatchObject({ state: 'rejected', outcome_code: 'DISASTER_APPROVAL_INVALID' });
      const plan = await db.selectFrom('license_disaster_transfer_plans').selectAll()
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

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((innerResolve) => { resolve = innerResolve; });
  return { promise, resolve };
}
