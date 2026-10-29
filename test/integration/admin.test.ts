import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { userInfo, tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as httpsRequest } from 'node:https';
import { sql, type Kysely } from 'kysely';
import { decodeJwt, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { createAdminService, createLicenseRequestDigest, issueActivationCodeRequestDigest,
  renewLicenseRequestDigest, changeLicenseStatusRequestDigest } from '../../src/admin/service.js';
import { createDatabase, migrateToLatest } from '../../src/db/database.js';
import type { Database } from '../../src/db/types.js';
import { activationIntentDigest, renewalIntentDigest } from '../../src/intent.js';
import { addCalendarPeriod } from '../../src/entitlements/calendar.js';
import { createActivationCode, createExpiredActivationFixture, createLicense, getDbNow } from '../fixtures.js';
import { CommitAckDropProxy } from '../support/postgres-proxy.js';
import { buildChallengeBoundBody, requestChallenge, signPost, startAppServer, type RunningTestServer } from '../support/http.js';
import { createIdentity, createTestSigningRuntime, type TestIdentity, type TestSigningRuntime } from '../support/runtime.js';

interface ActivatedLicense {
  licenseId: string;
  identity: TestIdentity;
  instanceId: string;
  databaseId: string;
  activationOperationId: string;
  activationLease: string;
}

function challengeNonce(token: string): string {
  const nonce = decodeJwt(token)['server_nonce'];
  if (typeof nonce !== 'string') throw new Error('Challenge nonce missing');
  return nonce;
}

describe('local admin operations on PostgreSQL and the real HTTPS protocol', () => {
  let db: Kysely<Database>;
  let server: RunningTestServer;
  let runtime: TestSigningRuntime;
  let service: Awaited<ReturnType<typeof createAdminService>>;
  let scratchDirectory: string;
  let policyFile: string;
  let databaseRole: string;
  let databaseUrl: string;
  let previousActorEnv: string | undefined;

  async function writePolicy(url: string, role = databaseRole): Promise<string> {
    const credentialFile = join(scratchDirectory, `database-${randomUUID()}.url`);
    const policyPath = join(scratchDirectory, `policy-${randomUUID()}.json`);
    await writeFile(credentialFile, `${url}\n`, { mode: 0o600 });
    await chmod(credentialFile, 0o600);
    const uid = process.geteuid?.();
    if (uid === undefined) throw new Error('POSIX uid is required for admin CLI tests');
    await writeFile(policyPath, JSON.stringify({
      environment: 'isolated-development',
      allowed_os_uids: [uid],
      database_role: role,
      database_url_file: credentialFile,
    }), { mode: 0o600 });
    await chmod(policyPath, 0o600);
    return policyPath;
  }

  function makeCreateRequest(plan: 'monthly' | 'yearly' = 'monthly') {
    const input = {
      operationId: randomUUID(),
      licenseId: randomUUID(),
      expectedRevision: '0' as const,
      plan,
      accountId: `account-${randomUUID()}`,
      reason: '人工确认授权业务资料',
    };
    return { ...input, confirmedRequestDigest: createLicenseRequestDigest(input) };
  }

  async function createManagedLicense(plan: 'monthly' | 'yearly' = 'monthly') {
    const input = makeCreateRequest(plan);
    const created = await service.createLicense(input);
    expect(created.state).toBe('succeeded');
    return { input, created };
  }

  function makeIssueRequest(licenseId: string, expectedRevision: string, extra: {
    replaceCodeId?: string;
    expiresInHours?: number;
    reason?: string;
  } = {}) {
    const input = {
      operationId: randomUUID(),
      licenseId,
      expectedRevision,
      reason: extra.reason ?? '人工核对并签发激活码',
      ...(extra.replaceCodeId ? { replaceCodeId: extra.replaceCodeId } : {}),
      ...(extra.expiresInHours ? { expiresInHours: extra.expiresInHours } : {}),
    };
    return { ...input, confirmedRequestDigest: issueActivationCodeRequestDigest(input) };
  }

  async function activate(licenseId: string, code: string, identity = undefined as TestIdentity | undefined): Promise<{
    response: Awaited<ReturnType<typeof signPost>>;
    identity: TestIdentity;
    instanceId: string;
    databaseId: string;
    operationId: string;
  }> {
    const instanceIdentity = identity ?? await createIdentity();
    const instanceId = randomUUID();
    const databaseId = randomUUID();
    const operationId = randomUUID();
    const origin = 'https://shop.example.test';
    const intentDigest = activationIntentDigest({
      licenseId, activationCode: code, instanceId, databaseId, identityJkt: instanceIdentity.jkt, origin,
    });
    const challenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: instanceIdentity,
      operation: 'activation', operationId, intentDigest, instanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId, intentDigest, attemptNo: 1,
        instanceId, identity: instanceIdentity, licenseId, databaseId,
      }),
      activation_code: code,
      origin,
    };
    const response = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/activations',
      body, identity: instanceIdentity, nonce: challengeNonce(challenge.token),
    });
    return { response, identity: instanceIdentity, instanceId, databaseId, operationId };
  }

  async function renew(input: {
    licenseId: string;
    identity: TestIdentity;
    instanceId: string;
    databaseId: string;
    operationId: string;
    expectedGeneration: string;
    knownRevision: string;
    attemptNo?: number;
  }) {
    const intentDigest = renewalIntentDigest({
      kind: 'renewal', licenseId: input.licenseId, databaseId: input.databaseId,
      instanceId: input.instanceId, identityJkt: input.identity.jkt,
      expectedGeneration: input.expectedGeneration, knownRevision: input.knownRevision,
    });
    const challenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: input.identity,
      operation: 'renewal', operationId: input.operationId, intentDigest, instanceId: input.instanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId: input.operationId, intentDigest,
        attemptNo: input.attemptNo ?? 1, instanceId: input.instanceId, identity: input.identity,
        licenseId: input.licenseId, databaseId: input.databaseId,
      }),
      expected_generation: input.expectedGeneration,
      known_revision: input.knownRevision,
    };
    const response = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/leases/renew',
      body, identity: input.identity, nonce: challengeNonce(challenge.token),
    });
    return { response, intentDigest };
  }

  async function createAndActivate(plan: 'monthly' | 'yearly' = 'monthly'): Promise<ActivatedLicense> {
    const { created } = await createManagedLicense(plan);
    const codeOperation = await service.issueActivationCode(makeIssueRequest(created.licenseId, '1'));
    if (!codeOperation.activationCode) throw new Error('New activation code was not returned');
    const activation = await activate(created.licenseId, codeOperation.activationCode);
    expect(activation.response.status).toBe(200);
    const lease = activation.response.json['license'];
    if (typeof lease !== 'string') throw new Error('Activation lease missing');
    return {
      licenseId: created.licenseId, identity: activation.identity, instanceId: activation.instanceId,
      databaseId: activation.databaseId, activationOperationId: activation.operationId, activationLease: lease,
    };
  }

  beforeAll(async () => {
    runtime = await createTestSigningRuntime();
    databaseUrl = runtime.config.databaseUrl;
    const parsedDatabaseUrl = new URL(databaseUrl);
    databaseRole = decodeURIComponent(parsedDatabaseUrl.username);
    scratchDirectory = await mkdtemp(join(tmpdir(), 'aikayun-license-admin-'));
    await chmod(scratchDirectory, 0o700);
    policyFile = await writePolicy(databaseUrl);
    previousActorEnv = process.env['LICENSE_ADMIN_ACTOR'];
    process.env['LICENSE_ADMIN_ACTOR'] = 'spoofed-actor-from-environment';
    db = createDatabase(databaseUrl, 24);
    await migrateToLatest(db);
    server = await startAppServer(createApp({ config: runtime.config, db }));
    service = await createAdminService(policyFile);
  });

  afterAll(async () => {
    await service?.close();
    await server?.stop();
    await db?.destroy();
    await runtime?.cleanup();
    if (previousActorEnv === undefined) delete process.env['LICENSE_ADMIN_ACTOR'];
    else process.env['LICENSE_ADMIN_ACTOR'] = previousActorEnv;
    if (scratchDirectory) await rm(scratchDirectory, { recursive: true, force: true });
  });

  it('creates monthly and yearly licenses with UTC anchors and revision 1', async () => {
    for (const plan of ['monthly', 'yearly'] as const) {
      const { input, created } = await createManagedLicense(plan);
      const license = await db.selectFrom('licenses').selectAll().where('id', '=', input.licenseId).executeTakeFirstOrThrow();
      expect(license.status).toBe('active');
      expect(license.plan).toBe(plan);
      expect(license.current_generation).toBe('0');
      expect(license.entitlement_revision).toBe('1');
      expect(license.revision).toBe('1');
      expect(license.anchor_day).toBe(license.billing_anchor_utc.getUTCDate());
      expect(license.confirmed_subscription_end).toEqual(addCalendarPeriod(license.billing_anchor_utc, plan, license.anchor_day));
      expect(created.result['subscription_end']).toBe(license.confirmed_subscription_end.toISOString());
      const audit = await db.selectFrom('license_admin_audit_events').selectAll()
        .where('operation_id', '=', input.operationId).executeTakeFirstOrThrow();
      expect(audit.actor_os_uid).toBe(process.geteuid?.());
      expect(audit.actor_os_username).toBe(userInfo().username);
      expect(audit.actor_database_role).toBe(databaseRole);
      expect(audit.reason).toBe(input.reason);
    }
  });

  it('issues one-time codes, hides secrets on replay, and safely revokes/reissues codes', async () => {
    const { created } = await createManagedLicense();
    const firstInput = makeIssueRequest(created.licenseId, '1');
    const first = await service.issueActivationCode(firstInput);
    expect(first.state).toBe('succeeded');
    expect(first.resultRevision).toBe('2');
    expect(first.activationCode).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const firstCode = first.activationCode!;
    const firstCodeId = String(first.result['code_id']);
    const firstCodeRow = await db.selectFrom('activation_codes').selectAll().where('id', '=', firstCodeId).executeTakeFirstOrThrow();
    expect(firstCodeRow.token_hash).toBe(createHash('sha256').update(firstCode).digest('base64url'));
    expect(JSON.stringify(await service.getOperation(first.operationId))).not.toContain(firstCode);

    const replay = await service.issueActivationCode(firstInput);
    expect(replay.replayed).toBe(true);
    expect(replay.activationCode).toBeUndefined();
    expect(JSON.stringify(replay)).not.toContain(firstCode);

    const changedSameId = {
      ...firstInput,
      reason: '以不同原因重放同一操作',
    };
    const changedDigest = issueActivationCodeRequestDigest(changedSameId);
    await expect(service.issueActivationCode({ ...changedSameId, confirmedRequestDigest: changedDigest }))
      .rejects.toMatchObject({ code: 'ADMIN_OPERATION_ID_CONFLICT' });

    const replacementInput = makeIssueRequest(created.licenseId, '2', { replaceCodeId: firstCodeId, reason: '作废未知发码后人工重发' });
    const replacement = await service.issueActivationCode(replacementInput);
    expect(replacement.state).toBe('succeeded');
    expect(replacement.resultRevision).toBe('3');
    expect(replacement.activationCode).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(replacement.activationCode).not.toBe(firstCode);
    expect((await db.selectFrom('activation_codes').selectAll().where('id', '=', firstCodeId).executeTakeFirstOrThrow()).revoked_at).toBeInstanceOf(Date);
    const unresolved = await db.selectFrom('activation_codes').selectAll()
      .where('license_id', '=', created.licenseId).where('consumed_at', 'is', null).where('revoked_at', 'is', null).execute();
    expect(unresolved).toHaveLength(1);
    await expect(db.insertInto('activation_codes').values({
      id: randomUUID(), license_id: created.licenseId, token_hash: randomBytes(32).toString('base64url'),
      expires_at: new Date(Date.now() + 60_000), consumed_at: null, revoked_at: null, created_at: new Date(),
    }).execute()).rejects.toMatchObject({ code: '23505' });

    const revokedAttempt = await activate(created.licenseId, firstCode);
    expect(revokedAttempt.response.status).toBe(403);
    expect(await db.selectFrom('license_operations').selectAll()
      .where('operation_id', '=', revokedAttempt.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_operation_attempts').selectAll()
      .where('operation_id', '=', revokedAttempt.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_audit_events').selectAll()
      .where('license_id', '=', created.licenseId).where('operation_id', '=', revokedAttempt.operationId).execute()).toHaveLength(0);

    const successfulActivation = await activate(created.licenseId, replacement.activationCode!);
    expect(successfulActivation.response.status).toBe(200);
    const consumedCode = await db.selectFrom('activation_codes').selectAll()
      .where('id', '=', String(replacement.result['code_id'])).executeTakeFirstOrThrow();
    expect(consumedCode.consumed_at).toBeInstanceOf(Date);
    expect(consumedCode.revoked_at).toBeNull();
    const afterActivation = await service.issueActivationCode(makeIssueRequest(created.licenseId, '4'));
    expect(afterActivation.state).toBe('rejected');
    expect(afterActivation.outcomeCode).toBe('LICENSE_ALREADY_ACTIVATED');
  });

  it('rejects expired codes and retires them before a controlled replacement', async () => {
    const { created } = await createManagedLicense();
    const expiredCode = randomBytes(32).toString('base64url');
    const now = await getDbNow(db);
    const expiredId = randomUUID();
    await db.insertInto('activation_codes').values({
      id: expiredId, license_id: created.licenseId,
      token_hash: createHash('sha256').update(expiredCode).digest('base64url'),
      expires_at: new Date(now.getTime() - 1000), consumed_at: null, revoked_at: null, created_at: now,
    }).execute();
    const rejected = await activate(created.licenseId, expiredCode);
    expect(rejected.response.status).toBe(403);
    expect(await db.selectFrom('license_operations').selectAll()
      .where('operation_id', '=', rejected.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_operation_attempts').selectAll()
      .where('operation_id', '=', rejected.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_audit_events').selectAll()
      .where('license_id', '=', created.licenseId).where('operation_id', '=', rejected.operationId).execute()).toHaveLength(0);
    expect((await db.selectFrom('license_activations').selectAll().where('license_id', '=', created.licenseId).execute())).toHaveLength(0);
    const codeIssue = await service.issueActivationCode(makeIssueRequest(created.licenseId, '1'));
    expect(codeIssue.state).toBe('succeeded');
    expect((await db.selectFrom('activation_codes').selectAll().where('id', '=', expiredId).executeTakeFirstOrThrow()).revoked_at).toBeInstanceOf(Date);
    expect(codeIssue.activationCode).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('revoke, renewal, and explicit restore are revisioned atomically and drive signed HTTPS status/leases', async () => {
    const activated = await createAndActivate();
    const before = await db.selectFrom('licenses').selectAll().where('id', '=', activated.licenseId).executeTakeFirstOrThrow();
    const beforeActivationCount = await db.selectFrom('license_activations').selectAll().where('license_id', '=', activated.licenseId).execute();
    const beforeCodeRows = await db.selectFrom('activation_codes').selectAll().where('license_id', '=', activated.licenseId).execute();
    expect(before.revision).toBe('3');
    expect(before.entitlement_revision).toBe('1');

    const revokeBase = { operationId: randomUUID(), licenseId: activated.licenseId, expectedRevision: '3', reason: '人工确认账户需要暂停授权' };
    const revokeDigest = changeLicenseStatusRequestDigest(revokeBase, 'license_revoke');
    const revoked = await service.revokeLicense({ ...revokeBase, confirmedRequestDigest: revokeDigest });
    expect(revoked.state).toBe('succeeded');
    expect(revoked.resultRevision).toBe('4');
    const afterRevoke = await db.selectFrom('licenses').selectAll().where('id', '=', activated.licenseId).executeTakeFirstOrThrow();
    expect(afterRevoke.status).toBe('revoked');
    expect(afterRevoke.entitlement_revision).toBe('2');
    expect(afterRevoke.revision).toBe('4');
    expect(afterRevoke.confirmed_subscription_end).toEqual(before.confirmed_subscription_end);
    expect(afterRevoke.current_generation).toBe(before.current_generation);
    expect(await db.selectFrom('license_activations').selectAll().where('license_id', '=', activated.licenseId).execute()).toEqual(beforeActivationCount);
    expect(await db.selectFrom('activation_codes').selectAll().where('license_id', '=', activated.licenseId).execute()).toEqual(beforeCodeRows);
    expect(await db.selectFrom('entitlement_events').selectAll().where('license_id', '=', activated.licenseId).execute()).toHaveLength(0);

    const revokedOperationId = randomUUID();
    const revokedRenewal = await renew({
      licenseId: activated.licenseId, identity: activated.identity, instanceId: activated.instanceId,
      databaseId: activated.databaseId, operationId: revokedOperationId, expectedGeneration: '1', knownRevision: '1',
    });
    expect(revokedRenewal.response.status).toBe(409);
    const revokedReceipt = await jwtVerify(revokedRenewal.response.json['status_receipt'] as string, runtime.config.signingPublicKey, {
      algorithms: ['Ed25519'], issuer: runtime.config.issuer, audience: 'aikayun-commerce',
    });
    expect(revokedReceipt.protectedHeader['typ']).toBe('aikayun-license-status+jwt');
    expect(revokedReceipt.payload['status']).toBe('revoked');
    expect(revokedReceipt.payload['entitlement_revision']).toBe('2');

    const renewalBase = {
      operationId: randomUUID(), licenseId: activated.licenseId, expectedRevision: '4',
      businessReference: `manual-confirmation-${randomUUID()}`,
      reason: '人工核实服务周期并确认续费事实',
    };
    const renewalDigest = renewLicenseRequestDigest(renewalBase);
    const renewedWhileRevoked = await service.renewLicense({ ...renewalBase, confirmedRequestDigest: renewalDigest });
    expect(renewedWhileRevoked.state).toBe('succeeded');
    const afterRenewal = await db.selectFrom('licenses').selectAll().where('id', '=', activated.licenseId).executeTakeFirstOrThrow();
    expect(afterRenewal.status).toBe('revoked');
    expect(afterRenewal.revision).toBe('5');
    expect(afterRenewal.entitlement_revision).toBe('3');
    expect(afterRenewal.confirmed_subscription_end.getTime()).toBeGreaterThan(before.confirmed_subscription_end.getTime());
    const renewalEvents = await db.selectFrom('entitlement_events').selectAll().where('license_id', '=', activated.licenseId).execute();
    expect(renewalEvents).toHaveLength(1);
    expect(renewalEvents[0]!.new_end.getTime()).toBeGreaterThan(renewalEvents[0]!.previous_end.getTime());

    const restoreBase = { operationId: randomUUID(), licenseId: activated.licenseId, expectedRevision: '5', reason: '人工复核后明确恢复原实例授权' };
    const restoreDigest = changeLicenseStatusRequestDigest(restoreBase, 'license_restore');
    const restored = await service.restoreLicense({ ...restoreBase, confirmedRequestDigest: restoreDigest });
    expect(restored.state).toBe('succeeded');
    const afterRestore = await db.selectFrom('licenses').selectAll().where('id', '=', activated.licenseId).executeTakeFirstOrThrow();
    expect(afterRestore.status).toBe('active');
    expect(afterRestore.revision).toBe('6');
    expect(afterRestore.entitlement_revision).toBe('4');
    expect(afterRestore.confirmed_subscription_end).toEqual(afterRenewal.confirmed_subscription_end);
    expect(afterRestore.current_generation).toBe('1');
    expect(await db.selectFrom('entitlement_events').selectAll().where('license_id', '=', activated.licenseId).execute()).toEqual(renewalEvents);
    expect(await db.selectFrom('license_activations').selectAll().where('license_id', '=', activated.licenseId).execute()).toHaveLength(1);
    expect(await db.selectFrom('activation_codes').selectAll().where('license_id', '=', activated.licenseId).execute()).toHaveLength(1);

    const activeRenewal = await renew({
      licenseId: activated.licenseId, identity: activated.identity, instanceId: activated.instanceId,
      databaseId: activated.databaseId, operationId: randomUUID(), expectedGeneration: '1', knownRevision: '3',
    });
    expect(activeRenewal.response.status).toBe(200);
    const newLease = await jwtVerify(activeRenewal.response.json['license'] as string, runtime.config.signingPublicKey, {
      algorithms: ['Ed25519'], issuer: runtime.config.issuer, audience: 'aikayun-commerce',
    });
    const oldLease = await jwtVerify(activated.activationLease, runtime.config.signingPublicKey, {
      algorithms: ['Ed25519'], issuer: runtime.config.issuer, audience: 'aikayun-commerce',
    });
    expect(newLease.protectedHeader['typ']).toBe('aikayun-license+jwt');
    expect(newLease.payload['activation_generation']).toBe(oldLease.payload['activation_generation']);
    expect(newLease.payload['entitlement_revision']).toBe('4');
    expect(newLease.payload['subscription_end']).toBe(Math.floor(afterRenewal.confirmed_subscription_end.getTime() / 1000));
    expect(newLease.payload['jti']).not.toBe(oldLease.payload['jti']);

    const replayedOldStatus = await renew({
      licenseId: activated.licenseId, identity: activated.identity, instanceId: activated.instanceId,
      databaseId: activated.databaseId, operationId: revokedOperationId, expectedGeneration: '1', knownRevision: '1', attemptNo: 2,
    });
    expect(replayedOldStatus.response.status).toBe(409);
    const staleStatus = await jwtVerify(replayedOldStatus.response.json['status_receipt'] as string, runtime.config.signingPublicKey, {
      algorithms: ['Ed25519'], issuer: runtime.config.issuer, audience: 'aikayun-commerce',
    });
    expect(staleStatus.payload['status']).toBe('revoked');
    expect(staleStatus.payload['entitlement_revision']).toBe('2');
    expect(BigInt(String(staleStatus.payload['entitlement_revision']))).toBeLessThan(BigInt(String(newLease.payload['entitlement_revision'])));
    const stillRestored = await db.selectFrom('licenses').selectAll().where('id', '=', activated.licenseId).executeTakeFirstOrThrow();
    expect(stillRestored.status).toBe('active');
    expect(stillRestored.entitlement_revision).toBe('4');
  });

  it('restoring an expired subscription never signs a new lease and superseded remains fenced', async () => {
    const expiredLicense = await createAndActivate();
    const beforeExpiry = await db.selectFrom('licenses').selectAll().where('id', '=', expiredLicense.licenseId).executeTakeFirstOrThrow();
    const past = new Date(Date.now() - 60_000);
    await db.updateTable('licenses').set({ confirmed_subscription_end: past }).where('id', '=', expiredLicense.licenseId).execute();
    const expiredResponse = await renew({
      licenseId: expiredLicense.licenseId, identity: expiredLicense.identity, instanceId: expiredLicense.instanceId,
      databaseId: expiredLicense.databaseId, operationId: randomUUID(), expectedGeneration: '1', knownRevision: '1',
    });
    expect(expiredResponse.response.status).toBe(409);
    const expiredReceipt = await jwtVerify(expiredResponse.response.json['status_receipt'] as string, runtime.config.signingPublicKey, {
      algorithms: ['Ed25519'], issuer: runtime.config.issuer, audience: 'aikayun-commerce',
    });
    expect(expiredReceipt.payload['status']).toBe('expired');
    expect(expiredReceipt.payload['subscription_end']).toBe(Math.floor(past.getTime() / 1000));
    const revokeBase = { operationId: randomUUID(), licenseId: expiredLicense.licenseId, expectedRevision: '3', reason: '人工确认已到期许可证需要撤销' };
    const revokeDigest = changeLicenseStatusRequestDigest(revokeBase, 'license_revoke');
    expect((await service.revokeLicense({ ...revokeBase, confirmedRequestDigest: revokeDigest })).state).toBe('succeeded');
    const restoreBase = { operationId: randomUUID(), licenseId: expiredLicense.licenseId, expectedRevision: '4', reason: '人工复核后恢复状态但不延长已结束订阅' };
    const restoreDigest = changeLicenseStatusRequestDigest(restoreBase, 'license_restore');
    const restoreResult = await service.restoreLicense({ ...restoreBase, confirmedRequestDigest: restoreDigest });
    expect(restoreResult.state).toBe('succeeded');
    const restoredExpiredLicense = await db.selectFrom('licenses').selectAll().where('id', '=', expiredLicense.licenseId).executeTakeFirstOrThrow();
    expect(restoredExpiredLicense.status).toBe('active');
    expect(restoredExpiredLicense.confirmed_subscription_end.getTime()).toBe(past.getTime());
    const stillExpired = await renew({
      licenseId: expiredLicense.licenseId, identity: expiredLicense.identity, instanceId: expiredLicense.instanceId,
      databaseId: expiredLicense.databaseId, operationId: randomUUID(), expectedGeneration: '1', knownRevision: '2',
    });
    expect(stillExpired.response.status).toBe(409);
    const afterRestoreReceipt = await jwtVerify(stillExpired.response.json['status_receipt'] as string, runtime.config.signingPublicKey, {
      algorithms: ['Ed25519'], issuer: runtime.config.issuer, audience: 'aikayun-commerce',
    });
    expect(afterRestoreReceipt.payload['status']).toBe('expired');
    expect(afterRestoreReceipt.payload['entitlement_revision']).toBe('3');
    expect(beforeExpiry.confirmed_subscription_end.getTime()).toBeGreaterThan(past.getTime());

    const fixtureIdentity = await createIdentity();
    const superseded = await createExpiredActivationFixture(db, runtime.config, fixtureIdentity);
    const replacementIdentity = await createIdentity();
    const changedAt = await getDbNow(db);
    const oldActivation = await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', superseded.id).where('identity_jkt', '=', fixtureIdentity.jkt).executeTakeFirstOrThrow();
    await db.updateTable('license_activations').set({ state: 'retired', retired_at: changedAt }).where('id', '=', oldActivation.id).execute();
    await db.updateTable('licenses').set({ current_generation: '2', revision: '3', updated_at: changedAt }).where('id', '=', superseded.id).execute();
    await db.insertInto('license_activations').values({
      id: randomUUID(), license_id: superseded.id, generation: '2', instance_id: randomUUID(), database_id: randomUUID(),
      identity_jwk_public: replacementIdentity.publicJwk, identity_jkt: replacementIdentity.jkt, state: 'active',
      activated_at: changedAt, retired_at: null, last_seen_at: changedAt, origin_display: 'https://replacement.example.test',
    }).execute();
    const response = await renew({
      licenseId: superseded.id, identity: fixtureIdentity, instanceId: superseded.instanceId,
      databaseId: superseded.databaseId, operationId: randomUUID(), expectedGeneration: '1', knownRevision: '1',
    });
    expect(response.response.status).toBe(409);
    const receipt = await jwtVerify(response.response.json['status_receipt'] as string, runtime.config.signingPublicKey, {
      algorithms: ['Ed25519'], issuer: runtime.config.issuer, audience: 'aikayun-commerce',
    });
    expect(receipt.payload['status']).toBe('superseded');
    expect(receipt.payload['current_generation']).toBe('2');
    expect(response.response.json['license']).toBeUndefined();
  });

  it('concurrent admin operations honor expected revision with one winner', async () => {
    const { created } = await createManagedLicense();
    const renewBase = {
      operationId: randomUUID(), licenseId: created.licenseId, expectedRevision: '1',
      businessReference: `reference-${randomUUID()}`, reason: '人工确认当前续费事实',
    };
    const renewDigest = renewLicenseRequestDigest(renewBase);
    const revokeBase = { operationId: randomUUID(), licenseId: created.licenseId, expectedRevision: '1', reason: '人工确认暂停授权' };
    const revokeDigest = changeLicenseStatusRequestDigest(revokeBase, 'license_revoke');
    const results = await Promise.all([
      service.renewLicense({ ...renewBase, confirmedRequestDigest: renewDigest }),
      service.revokeLicense({ ...revokeBase, confirmedRequestDigest: revokeDigest }),
    ]);
    expect(results.filter((result) => result.state === 'succeeded')).toHaveLength(1);
    expect(results.filter((result) => result.outcomeCode === 'EXPECTED_REVISION_MISMATCH')).toHaveLength(1);
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', created.licenseId).executeTakeFirstOrThrow();
    expect(license.revision).toBe('2');
    if (license.status === 'revoked') expect(license.entitlement_revision).toBe('2');
    else expect(license.status).toBe('active');
    const operations = await db.selectFrom('license_admin_operations').selectAll().where('license_id', '=', created.licenseId).execute();
    expect(operations).toHaveLength(3); // create, renewal/revoke winner, and expected-revision rejection
  });

  it('serializes code issuance against another admin mutation at the same expected revision', async () => {
    const { created } = await createManagedLicense();
    const issueRequest = makeIssueRequest(created.licenseId, '1');
    const revokeBase = {
      operationId: randomUUID(), licenseId: created.licenseId, expectedRevision: '1',
      reason: '人工确认暂停尚未激活的许可证',
    };
    const revokeDigest = changeLicenseStatusRequestDigest(revokeBase, 'license_revoke');
    const results = await Promise.all([
      service.issueActivationCode(issueRequest),
      service.revokeLicense({ ...revokeBase, confirmedRequestDigest: revokeDigest }),
    ]);
    expect(results.filter((result) => result.state === 'succeeded')).toHaveLength(1);
    expect(results.filter((result) => result.outcomeCode === 'EXPECTED_REVISION_MISMATCH')).toHaveLength(1);
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', created.licenseId).executeTakeFirstOrThrow();
    expect(license.revision).toBe('2');
    const codes = await db.selectFrom('activation_codes').selectAll().where('license_id', '=', created.licenseId).execute();
    if (license.status === 'revoked') expect(codes).toHaveLength(0);
    else expect(codes).toHaveLength(1);
  });

  it('recovers a dropped COMMIT acknowledgement by querying the same operation id', async () => {
    const { created } = await createManagedLicense();
    const proxy = new CommitAckDropProxy();
    const parsed = new URL(databaseUrl);
    await proxy.start(parsed.hostname, Number(parsed.port || '5432'));
    const proxyUrl = new URL(databaseUrl);
    proxyUrl.port = String(proxy.port);
    proxyUrl.searchParams.set('sslmode', 'disable');
    const proxyPolicy = await writePolicy(proxyUrl.toString());
    const proxyService = await createAdminService(proxyPolicy);
    const revokeBase = { operationId: randomUUID(), licenseId: created.licenseId, expectedRevision: '1', reason: '人工确认COMMIT未知时按原操作查询' };
    const digest = changeLicenseStatusRequestDigest(revokeBase, 'license_revoke');
    const droppedCommitAck = proxy.armNextCommitAckDrop();
    try {
      const result = await proxyService.revokeLicense({ ...revokeBase, confirmedRequestDigest: digest });
      await droppedCommitAck;
      expect(result.state).toBe('succeeded');
      expect(result.replayed).toBe(true);
      const savedOperation = await db.selectFrom('license_admin_operations').selectAll()
        .where('operation_id', '=', revokeBase.operationId).execute();
      expect(savedOperation).toHaveLength(1);
      expect(await db.selectFrom('license_admin_audit_events').selectAll()
        .where('operation_id', '=', revokeBase.operationId).execute()).toHaveLength(1);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', created.licenseId).executeTakeFirstOrThrow()).status).toBe('revoked');
    } finally {
      await proxyService.close();
      await proxy.stop();
    }
  });

  it('separates OS identity from database role and rejects actor spoofing and admin HTTP access', async () => {
    expect(process.env['LICENSE_ADMIN_ACTOR']).toBe('spoofed-actor-from-environment');
    const wrongUidPolicy = join(scratchDirectory, `wrong-uid-${randomUUID()}.json`);
    const uid = process.geteuid?.();
    if (uid === undefined) throw new Error('POSIX uid required');
    const credentialPath = join(scratchDirectory, `wrong-uid-db-${randomUUID()}.url`);
    await writeFile(credentialPath, `${databaseUrl}\n`, { mode: 0o600 });
    await chmod(credentialPath, 0o600);
    await writeFile(wrongUidPolicy, JSON.stringify({
      environment: 'isolated-development', allowed_os_uids: [uid + 100_000],
      database_role: databaseRole, database_url_file: credentialPath,
    }), { mode: 0o600 });
    await chmod(wrongUidPolicy, 0o600);
    await expect(createAdminService(wrongUidPolicy)).rejects.toMatchObject({ code: 'ADMIN_OS_IDENTITY_DENIED' });

    const wrongRolePolicy = await writePolicy(databaseUrl, `${databaseRole}_forged`);
    await expect(createAdminService(wrongRolePolicy)).rejects.toMatchObject({ code: 'ADMIN_DATABASE_ROLE_MISMATCH' });

    const created = await createManagedLicense();
    const operation = await db.selectFrom('license_admin_operations').selectAll()
      .where('operation_id', '=', created.input.operationId).executeTakeFirstOrThrow();
    expect(operation.actor_os_uid).toBe(uid);
    expect(operation.actor_os_username).toBe(userInfo().username);
    expect(operation.actor_database_role).toBe(databaseRole);
    expect(`${operation.actor_os_username}/${operation.actor_database_role}`).not.toContain('spoofed-actor-from-environment');

    const routeCheckApp = createApp({ config: runtime.config, db });
    expect(routeCheckApp.printRoutes()).not.toContain('/v1/admin');
    await routeCheckApp.close();
    const noAdminRoute = await new Promise<number>((resolve, reject) => {
      const request = httpsRequest({
        host: '127.0.0.1', port: server.port, path: '/v1/admin/licenses', method: 'POST',
        rejectUnauthorized: false, headers: { 'content-type': 'application/json' },
      }, (response) => {
        response.resume();
        response.on('end', () => resolve(response.statusCode ?? 0));
      });
      request.on('error', reject);
      request.end('{}');
    });
    expect(noAdminRoute).toBe(404);
  });

  it('keeps admin operation and audit rows immutable and forbids TRUNCATE', async () => {
    const input = makeCreateRequest();
    await service.createLicense(input);
    await expect(db.updateTable('license_admin_operations').set({ outcome_code: 'changed' })
      .where('operation_id', '=', input.operationId).execute()).rejects.toMatchObject({ code: '55000' });
    await expect(db.deleteFrom('license_admin_operations').where('operation_id', '=', input.operationId).execute())
      .rejects.toMatchObject({ code: '55000' });
    const audit = await db.selectFrom('license_admin_audit_events').selectAll()
      .where('operation_id', '=', input.operationId).executeTakeFirstOrThrow();
    await expect(db.updateTable('license_admin_audit_events').set({ outcome_code: 'changed' })
      .where('event_id', '=', audit.event_id).execute()).rejects.toMatchObject({ code: '55000' });
    await expect(db.deleteFrom('license_admin_audit_events').where('event_id', '=', audit.event_id).execute())
      .rejects.toMatchObject({ code: '55000' });
    await expect(sql`TRUNCATE TABLE license_admin_operations CASCADE`.execute(db)).rejects.toMatchObject({ code: '55000' });
    await expect(sql`TRUNCATE TABLE license_admin_audit_events CASCADE`.execute(db)).rejects.toMatchObject({ code: '55000' });
    await expect(db.updateTable('license_audit_events').set({ kind: 'overwritten' })
      .where('operation_id', '=', input.operationId).execute()).rejects.toMatchObject({ code: '55000' });
  });
});
