import { createHash, randomUUID } from 'node:crypto';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { request as httpsRequest } from 'node:https';
import { join } from 'node:path';
import { decodeJwt } from 'jose';
import { sql, type Kysely } from 'kysely';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import {
  approveTimeResetRequestDigest,
  changeLicenseStatusRequestDigest,
  createAdminService,
  revokeTimeResetApprovalRequestDigest,
} from '../../src/admin/service.js';
import { createDatabase, migrateToLatest } from '../../src/db/database.js';
import type { Database } from '../../src/db/types.js';
import { verifyTimeAnchor, verifyTimeResetReceipt } from '../../src/crypto/time-reset.js';
import { activationIntentDigest, timeResetIntentDigest } from '../../src/intent.js';
import { createActivationCode, createLicense } from '../fixtures.js';
import { CommitAckDropProxy } from '../support/postgres-proxy.js';
import { HttpResponseDropProxy } from '../support/http-response-proxy.js';
import { terminatePostgresBackend, waitForAdvisoryLockWaiterPids, waitForNoLockWaiters } from '../support/pg-waits.js';
import { startChildLicenseServer } from '../support/child-server.js';
import {
  buildChallengeBoundBody,
  requestChallenge,
  signPost,
  startAppServer,
  type HttpResponse,
  type RunningTestServer,
} from '../support/http.js';
import { createIdentity, createTestSigningRuntime, newClientNonce, type TestIdentity, type TestSigningRuntime } from '../support/runtime.js';

interface ActiveLicense {
  licenseId: string;
  activationId: string;
  identity: TestIdentity;
  instanceId: string;
  databaseId: string;
}

interface ResetApproval {
  approvalId: string;
  resetOperationId: string;
  intentDigest: string;
  oldWatermarkDigest: string;
  requestDigest: string;
  adminOperationId: string;
  active: ActiveLicense;
  generation: string;
  revision: string;
  entitlementRevision: string;
  expectedTimeEpoch: string;
}

interface ResetAttempt {
  body: Record<string, unknown>;
  clientNonce: string;
  serverNonce: string;
  intentDigest: string;
  operationId: string;
}

interface AnchorSample {
  token: string;
  clientNonce: string;
  serverTime: number;
  roundTripMs: number;
  receivedAt: number;
}

function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('base64url');
}

function nonceFromChallenge(token: string, name: 'server_nonce' | 'client_nonce' = 'server_nonce'): string {
  const value = decodeJwt(token)[name];
  if (typeof value !== 'string') throw new Error(`Challenge ${name} missing`);
  return value;
}

async function postJson(port: number, path: string, body: unknown): Promise<HttpResponse> {
  const wireBody = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const request = httpsRequest({
      host: '127.0.0.1', port, path, method: 'POST', rejectUnauthorized: false,
      headers: { host: 'license.example.test', 'content-type': 'application/json', 'content-length': String(wireBody.byteLength), connection: 'close' },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      response.on('end', () => {
        const buffer = Buffer.concat(chunks);
        let json: Record<string, unknown> = {};
        try { json = JSON.parse(buffer.toString('utf8')) as Record<string, unknown>; } catch { /* raw body stays available */ }
        resolve({ status: response.statusCode ?? 0, headers: response.headers, json, body: buffer });
      });
    });
    request.on('error', reject);
    request.end(wireBody);
  });
}

async function requestAnchor(port: number, runtime: TestSigningRuntime): Promise<AnchorSample> {
  const clientNonce = newClientNonce();
  const startedAt = performance.now();
  const response = await postJson(port, '/v1/time-anchor', { client_nonce: clientNonce });
  const receivedAt = performance.now();
  const roundTripMs = receivedAt - startedAt;
  if (response.status !== 200 || typeof response.json['time_anchor'] !== 'string') {
    throw new Error(`Time anchor failed: HTTP ${response.status} ${JSON.stringify(response.json)}`);
  }
  const token = response.json['time_anchor'];
  const verified = await verifyTimeAnchor(token, {
    publicKey: runtime.config.signingPublicKey,
    issuer: runtime.config.issuer,
    keyId: runtime.config.signingKeyId,
    clientNonce,
    roundTripMs,
  });
  return { token, clientNonce, serverTime: verified.serverTime, roundTripMs, receivedAt };
}

function anchorCreatedAt(sample: AnchorSample): number {
  const responseElapsedMs = sample.roundTripMs / 2 + performance.now() - sample.receivedAt;
  return Math.floor(sample.serverTime + responseElapsedMs / 1000);
}

describe('trusted center time bootstrap and audited time reset over HTTPS/PostgreSQL', () => {
  let db: Kysely<Database>;
  let server: RunningTestServer;
  let runtime: TestSigningRuntime;
  let admin: Awaited<ReturnType<typeof createAdminService>>;
  let scratchDirectory: string;
  let policyFile: string;

  async function activate(): Promise<ActiveLicense> {
    const license = await createLicense(db);
    const code = await createActivationCode(db, license.id);
    const identity = await createIdentity();
    const instanceId = randomUUID();
    const databaseId = randomUUID();
    const operationId = randomUUID();
    const intentDigest = activationIntentDigest({
      licenseId: license.id, activationCode: code.code, instanceId, databaseId,
      identityJkt: identity.jkt, origin: 'https://shop.example.test',
    });
    const challenge = await requestChallenge({
      port: server.port, config: runtime.config, identity, operation: 'activation',
      operationId, intentDigest, instanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId, intentDigest, attemptNo: 1,
        instanceId, identity, licenseId: license.id, databaseId,
      }),
      activation_code: code.code,
      origin: 'https://shop.example.test',
    };
    const response = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/activations', body,
      identity, nonce: nonceFromChallenge(challenge.token),
    });
    expect(response.status).toBe(200);
    const activation = await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', license.id).where('state', '=', 'active').executeTakeFirstOrThrow();
    return { licenseId: license.id, activationId: activation.id, identity, instanceId, databaseId };
  }

  async function approveReset(active: ActiveLicense): Promise<ResetApproval> {
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const activation = await db.selectFrom('license_activations').selectAll().where('id', '=', active.activationId).executeTakeFirstOrThrow();
    const approvalId = randomUUID();
    const resetOperationId = randomUUID();
    const oldWatermarkDigest = newClientNonce();
    const generation = activation.generation.toString();
    const revision = license.revision.toString();
    const entitlementRevision = license.entitlement_revision.toString();
    const expectedTimeEpoch = activation.time_epoch.toString();
    const intentDigest = timeResetIntentDigest({
      operationId: resetOperationId, approvalId, licenseId: active.licenseId,
      databaseId: active.databaseId, instanceId: active.instanceId, identityJkt: active.identity.jkt,
      activationId: active.activationId, activationGeneration: generation, expectedRevision: revision,
      entitlementRevision, expectedTimeEpoch, oldWatermarkDigest,
    });
    const request: Parameters<typeof approveTimeResetRequestDigest>[0] = {
      operationId: approvalId,
      licenseId: active.licenseId,
      expectedRevision: revision,
      reason: '人工核验本机时间异常并批准单次水位恢复',
      activationId: active.activationId,
      databaseId: active.databaseId,
      instanceId: active.instanceId,
      identityJkt: active.identity.jkt,
      activationGeneration: generation,
      entitlementRevision,
      expectedTimeEpoch,
      resetOperationId,
      intentDigest,
      oldWatermarkDigest,
    };
    const result = await admin.approveTimeReset({
      ...request,
      confirmedRequestDigest: approveTimeResetRequestDigest(request),
    });
    expect(result.state).toBe('succeeded');
    return {
      approvalId, resetOperationId, intentDigest, oldWatermarkDigest,
      requestDigest: result.requestDigest, adminOperationId: result.operationId,
      active, generation, revision, entitlementRevision, expectedTimeEpoch,
    };
  }

  async function makeResetAttempt(
    approval: ResetApproval,
    attemptNo: number,
    options: { created?: number; port?: number } = {},
  ): Promise<ResetAttempt> {
    const operationId = approval.resetOperationId;
    const challenge = await requestChallenge({
      port: options.port ?? server.port,
      config: runtime.config,
      identity: approval.active.identity,
      operation: 'time_reset',
      operationId,
      intentDigest: approval.intentDigest,
      instanceId: approval.active.instanceId,
      ...(options.created === undefined ? {} : { created: options.created }),
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId, intentDigest: approval.intentDigest,
        attemptNo, instanceId: approval.active.instanceId, identity: approval.active.identity,
        licenseId: approval.active.licenseId, databaseId: approval.active.databaseId,
      }),
      activation_id: approval.active.activationId,
      approval_id: approval.approvalId,
      expected_generation: approval.generation,
      expected_revision: approval.revision,
      expected_entitlement_revision: approval.entitlementRevision,
      expected_time_epoch: approval.expectedTimeEpoch,
      old_watermark_digest: approval.oldWatermarkDigest,
    };
    return {
      body,
      clientNonce: challenge.clientNonce,
      serverNonce: nonceFromChallenge(challenge.token),
      intentDigest: approval.intentDigest,
      operationId,
    };
  }

  async function sendApprovedReset(approval: ResetApproval, attemptNo: number, options: { created?: number; port?: number } = {}) {
    const attempt = await makeResetAttempt(approval, attemptNo, options);
    const response = await signPost({
      port: options.port ?? server.port, origin: runtime.config.publicOrigin,
      path: '/v1/time-resets/commit', body: attempt.body, identity: approval.active.identity,
      nonce: attempt.serverNonce, ...(options.created === undefined ? {} : { created: options.created }),
    });
    return { attempt, response };
  }

  async function writeAdminPolicy(databaseUrl: string): Promise<string> {
    const credentialFile = join(scratchDirectory, `database-${randomUUID()}.url`);
    const policyPath = join(scratchDirectory, `policy-${randomUUID()}.json`);
    const role = decodeURIComponent(new URL(databaseUrl).username);
    await writeFile(credentialFile, `${databaseUrl}\n`, { mode: 0o600 });
    await chmod(credentialFile, 0o600);
    const uid = process.geteuid?.();
    if (uid === undefined) throw new Error('POSIX UID required by isolated admin tests');
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
    scratchDirectory = await mkdtemp(join(tmpdir(), 'aikayun-license-time-reset-'));
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

  it('bootstraps pinned center time despite a multi-year client wall-clock error without touching business state', async () => {
    const identity = await createIdentity();
    const operationId = randomUUID();
    const clientNonce = newClientNonce();
    const intentDigest = newClientNonce();
    const before = await Promise.all([
      db.selectFrom('licenses').select(({ fn }) => fn.countAll<number>().as('n')).executeTakeFirstOrThrow(),
      db.selectFrom('activation_codes').select(({ fn }) => fn.countAll<number>().as('n')).executeTakeFirstOrThrow(),
      db.selectFrom('license_operations').select(({ fn }) => fn.countAll<number>().as('n')).executeTakeFirstOrThrow(),
      db.selectFrom('license_audit_events').select(({ fn }) => fn.countAll<number>().as('n')).executeTakeFirstOrThrow(),
      db.selectFrom('request_nonces').select(({ fn }) => fn.countAll<number>().as('n')).executeTakeFirstOrThrow(),
    ]);
    const wrongClockChallenge = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/challenges',
      body: {
        operation: 'activation', operation_id: operationId, intent_digest: intentDigest,
        instance_id: randomUUID(), public_jwk: identity.publicJwk, client_nonce: clientNonce,
      },
      identity, nonce: clientNonce, created: Math.floor(Date.now() / 1000) + 5 * 365 * 24 * 60 * 60,
    });
    expect(wrongClockChallenge.status).toBe(401);
    expect(wrongClockChallenge.json['error']).toEqual({ code: 'HTTP_SIGNATURE_INVALID' });
    const rollbackNonce = newClientNonce();
    const rolledBackClockChallenge = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/challenges',
      body: {
        operation: 'activation', operation_id: randomUUID(), intent_digest: newClientNonce(),
        instance_id: randomUUID(), public_jwk: identity.publicJwk, client_nonce: rollbackNonce,
      },
      identity, nonce: rollbackNonce, created: Math.floor(Date.now() / 1000) - 5 * 365 * 24 * 60 * 60,
    });
    expect(rolledBackClockChallenge.status).toBe(401);
    expect(rolledBackClockChallenge.json['error']).toEqual({ code: 'HTTP_SIGNATURE_INVALID' });

    const anchor = await requestAnchor(server.port, runtime);
    expect(anchor.roundTripMs).toBeLessThanOrEqual(5_000);
    const distinctAnchor = await requestAnchor(server.port, runtime);
    expect(distinctAnchor.token).not.toBe(anchor.token);
    expect(decodeJwt(distinctAnchor.token)['jti']).not.toBe(decodeJwt(anchor.token)['jti']);
    await expect(verifyTimeAnchor(anchor.token, {
      publicKey: runtime.config.signingPublicKey, issuer: runtime.config.issuer,
      keyId: runtime.config.signingKeyId, clientNonce: newClientNonce(), roundTripMs: anchor.roundTripMs,
    })).rejects.toThrow();
    await expect(verifyTimeAnchor(anchor.token, {
      publicKey: runtime.config.signingPublicKey, issuer: runtime.config.issuer,
      keyId: 'not-the-pinned-key', clientNonce: anchor.clientNonce, roundTripMs: anchor.roundTripMs,
    })).rejects.toThrow();
    await expect(verifyTimeAnchor(anchor.token, {
      publicKey: runtime.config.signingPublicKey, issuer: runtime.config.issuer,
      keyId: runtime.config.signingKeyId, clientNonce: anchor.clientNonce, roundTripMs: 5_001,
    })).rejects.toThrow();
    const afterAnchor = await Promise.all([
      db.selectFrom('licenses').select(({ fn }) => fn.countAll<number>().as('n')).executeTakeFirstOrThrow(),
      db.selectFrom('activation_codes').select(({ fn }) => fn.countAll<number>().as('n')).executeTakeFirstOrThrow(),
      db.selectFrom('license_operations').select(({ fn }) => fn.countAll<number>().as('n')).executeTakeFirstOrThrow(),
      db.selectFrom('license_audit_events').select(({ fn }) => fn.countAll<number>().as('n')).executeTakeFirstOrThrow(),
      db.selectFrom('request_nonces').select(({ fn }) => fn.countAll<number>().as('n')).executeTakeFirstOrThrow(),
    ]);
    expect(afterAnchor).toEqual(before);

    const anchoredChallenge = await requestChallenge({
      port: server.port, config: runtime.config, identity, operation: 'activation',
      operationId: randomUUID(), intentDigest: newClientNonce(), instanceId: randomUUID(),
      created: anchorCreatedAt(anchor),
    });
    expect(anchoredChallenge.token.split('.')).toHaveLength(3);
    expect(anchorCreatedAt(anchor)).toBeGreaterThan(Math.floor(Date.now() / 1000) - 60);
    expect(anchorCreatedAt(anchor)).toBeLessThan(Math.floor(Date.now() / 1000) + 60);

    const unhealthyCenter = await startAppServer(createApp({
      config: runtime.config,
      db,
      now: async () => new Date(Date.now() + 5 * 365 * 24 * 60 * 60 * 1000),
    }));
    try {
      const rejected = await postJson(unhealthyCenter.port, '/v1/time-anchor', { client_nonce: newClientNonce() });
      expect(rejected.status).toBe(503);
      expect(rejected.json['error']).toEqual({ code: 'TIME_SOURCE_UNHEALTHY' });
    } finally {
      await unhealthyCenter.stop();
    }
  });

  it('enforces the isolated anchor body limit and its own request-rate ceiling over HTTPS', async () => {
    const bodyLimitServer = await startAppServer(createApp({ config: runtime.config, db }));
    try {
      const oversized = JSON.stringify({ client_nonce: newClientNonce(), extra: 'x'.repeat(600) });
      const response = await new Promise<number>((resolve, reject) => {
        const request = httpsRequest({
          host: '127.0.0.1', port: bodyLimitServer.port, path: '/v1/time-anchor', method: 'POST', rejectUnauthorized: false,
          headers: { host: 'license.example.test', 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(oversized)), connection: 'close' },
        }, (incoming) => { incoming.resume(); incoming.on('end', () => resolve(incoming.statusCode ?? 0)); });
        request.on('error', reject);
        request.end(oversized);
      });
      expect(response).toBe(413);
    } finally {
      await bodyLimitServer.stop();
    }

    const rateServer = await startAppServer(createApp({ config: runtime.config, db }));
    try {
      for (let index = 0; index < 12; index += 1) {
        const anchor = await postJson(rateServer.port, '/v1/time-anchor', { client_nonce: newClientNonce() });
        expect(anchor.status).toBe(200);
      }
      const limited = await postJson(rateServer.port, '/v1/time-anchor', { client_nonce: newClientNonce() });
      expect(limited.status).toBe(429);
      expect(limited.json['error']).toEqual({ code: 'RATE_LIMITED' });
    } finally {
      await rateServer.stop();
    }
  });

  it('commits only a single approved epoch and returns a pinned, exact, non-commercial reset receipt', async () => {
    const active = await activate();
    const beforeLicense = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    const approval = await approveReset(active);
    const anchor = await requestAnchor(server.port, runtime);
    const first = await sendApprovedReset(approval, 1, { created: anchorCreatedAt(anchor) });
    expect(first.response.status).toBe(200);
    const token = first.response.json['time_reset_receipt'];
    expect(typeof token).toBe('string');
    const confirmationAnchor = await requestAnchor(server.port, runtime);
    const claims = await verifyTimeResetReceipt(token, {
      publicKey: runtime.config.signingPublicKey,
      issuer: runtime.config.issuer,
      keyId: runtime.config.signingKeyId,
      trustedServerTime: confirmationAnchor.serverTime,
      expected: {
        license_id: active.licenseId,
        database_id: active.databaseId,
        instance_id: active.instanceId,
        identity_jkt: active.identity.jkt,
        activation_generation: approval.generation,
        management_revision: approval.revision,
        entitlement_revision: approval.entitlementRevision,
        old_time_epoch: '0',
        new_time_epoch: '1',
        old_watermark_digest: approval.oldWatermarkDigest,
        operation_id: approval.resetOperationId,
        intent_digest: approval.intentDigest,
        request_nonce: first.attempt.serverNonce,
        client_nonce: first.attempt.clientNonce,
        request_digest: sha256(JSON.stringify(first.attempt.body)),
        admin_approval_id: approval.approvalId,
        admin_operation_id: approval.adminOperationId,
        admin_approval_digest: approval.requestDigest,
      },
    });
    expect(claims.admin_reason).toBe('人工核验本机时间异常并批准单次水位恢复');
    expect(claims.admin_os_uid).toBe(process.geteuid?.());
    expect(claims.admin_database_role).toBe(decodeURIComponent(new URL(runtime.config.databaseUrl).username));
    expect(claims.admin_audit_reference).toBe(`license_admin_audit_events:${approval.approvalId}`);
    expect(claims).not.toHaveProperty('grants');
    expect(claims).not.toHaveProperty('new_lease');
    expect(claims).not.toHaveProperty('subscription_end');

    const replay = await sendApprovedReset(approval, 2);
    expect(replay.response.status).toBe(200);
    expect(replay.response.json['time_reset_receipt']).toBe(token);
    const activation = await db.selectFrom('license_activations').selectAll().where('id', '=', active.activationId).executeTakeFirstOrThrow();
    const afterLicense = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect(activation.time_epoch).toBe('1');
    expect(afterLicense.revision).toBe(beforeLicense.revision);
    expect(afterLicense.entitlement_revision).toBe(beforeLicense.entitlement_revision);
    expect(afterLicense.confirmed_subscription_end).toEqual(beforeLicense.confirmed_subscription_end);
    expect(afterLicense.status).toBe(beforeLicense.status);
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', approval.resetOperationId).execute()).toHaveLength(1);
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', approval.resetOperationId).execute()).toHaveLength(2);
    expect(await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', approval.resetOperationId).execute()).toHaveLength(2);
    expect(await db.selectFrom('license_time_reset_events').selectAll().where('operation_id', '=', approval.resetOperationId).where('kind', '=', 'committed').execute()).toHaveLength(1);
    await expect(verifyTimeResetReceipt(token, {
      publicKey: runtime.config.signingPublicKey, issuer: runtime.config.issuer, keyId: runtime.config.signingKeyId,
      trustedServerTime: confirmationAnchor.serverTime,
      expected: {
        license_id: active.licenseId, database_id: active.databaseId, instance_id: active.instanceId,
        identity_jkt: active.identity.jkt, activation_generation: approval.generation,
        management_revision: approval.revision, entitlement_revision: approval.entitlementRevision,
        old_time_epoch: '1', new_time_epoch: '2', old_watermark_digest: approval.oldWatermarkDigest,
        operation_id: approval.resetOperationId, intent_digest: approval.intentDigest,
        request_nonce: first.attempt.serverNonce, client_nonce: first.attempt.clientNonce,
        request_digest: sha256(JSON.stringify(first.attempt.body)), admin_approval_id: approval.approvalId,
        admin_operation_id: approval.adminOperationId, admin_approval_digest: approval.requestDigest,
      },
    })).rejects.toThrow();

    const secondApproval = await approveReset(active);
    expect(secondApproval.expectedTimeEpoch).toBe('1');
    const secondAnchor = await requestAnchor(server.port, runtime);
    const secondReset = await sendApprovedReset(secondApproval, 1, { created: anchorCreatedAt(secondAnchor) });
    expect(secondReset.response.status).toBe(200);
    const secondReceipt = secondReset.response.json['time_reset_receipt'];
    const finalAnchor = await requestAnchor(server.port, runtime);
    const verifiedSecondReceipt = await verifyTimeResetReceipt(secondReceipt, {
      publicKey: runtime.config.signingPublicKey, issuer: runtime.config.issuer,
      keyId: runtime.config.signingKeyId, trustedServerTime: finalAnchor.serverTime,
      expected: {
        license_id: active.licenseId, database_id: active.databaseId, instance_id: active.instanceId,
        identity_jkt: active.identity.jkt, activation_generation: secondApproval.generation,
        management_revision: secondApproval.revision, entitlement_revision: secondApproval.entitlementRevision,
        old_time_epoch: '1', new_time_epoch: '2', old_watermark_digest: secondApproval.oldWatermarkDigest,
        operation_id: secondApproval.resetOperationId, intent_digest: secondApproval.intentDigest,
        request_nonce: secondReset.attempt.serverNonce, client_nonce: secondReset.attempt.clientNonce,
        request_digest: sha256(JSON.stringify(secondReset.attempt.body)), admin_approval_id: secondApproval.approvalId,
        admin_operation_id: secondApproval.adminOperationId, admin_approval_digest: secondApproval.requestDigest,
      },
    });
    expect(verifiedSecondReceipt.old_time_epoch).toBe('1');
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', active.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('2');
    const afterSecondReset = await db.selectFrom('licenses').selectAll().where('id', '=', active.licenseId).executeTakeFirstOrThrow();
    expect(afterSecondReset.revision).toBe(beforeLicense.revision);
    expect(afterSecondReset.entitlement_revision).toBe(beforeLicense.entitlement_revision);
    expect(afterSecondReset.confirmed_subscription_end).toEqual(beforeLicense.confirmed_subscription_end);
  });

  it('refuses revoked approvals and stale management revisions without consuming the challenge or changing epoch', async () => {
    const revokedApprovalActive = await activate();
    const revokedApproval = await approveReset(revokedApprovalActive);
    const revokeRequest = {
      operationId: randomUUID(), licenseId: revokedApprovalActive.licenseId,
      expectedRevision: revokedApproval.revision, approvalId: revokedApproval.approvalId,
      reason: '审批后发现核验材料变化，撤销时间恢复批准',
    };
    const revoked = await admin.revokeTimeResetApproval({
      ...revokeRequest,
      confirmedRequestDigest: revokeTimeResetApprovalRequestDigest(revokeRequest),
    });
    expect(revoked.state).toBe('succeeded');
    const revokedAttempt = await makeResetAttempt(revokedApproval, 1);
    const revokedResponse = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit',
      body: revokedAttempt.body, identity: revokedApprovalActive.identity, nonce: revokedAttempt.serverNonce,
    });
    expect(revokedResponse.status).toBe(403);
    expect(revokedResponse.json['error']).toEqual({ code: 'TIME_RESET_APPROVAL_REVOKED' });
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', revokedApprovalActive.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('0');
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', revokedApproval.resetOperationId).execute()).toHaveLength(0);
    const nonceRow = await db.selectFrom('request_nonces').selectAll().where('operation_id', '=', revokedApproval.resetOperationId).executeTakeFirstOrThrow();
    expect(nonceRow.consumed_at).toBeNull();

    const staleActive = await activate();
    const staleApproval = await approveReset(staleActive);
    const statusChange = {
      operationId: randomUUID(), licenseId: staleActive.licenseId,
      expectedRevision: staleApproval.revision, reason: '人工撤销后使原校时审批revision失效',
    };
    const licenseRevoked = await admin.revokeLicense({
      ...statusChange,
      confirmedRequestDigest: changeLicenseStatusRequestDigest(statusChange, 'license_revoke'),
    });
    expect(licenseRevoked.state).toBe('succeeded');
    const staleAttempt = await makeResetAttempt(staleApproval, 1);
    const staleResponse = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit',
      body: staleAttempt.body, identity: staleActive.identity, nonce: staleAttempt.serverNonce,
    });
    expect(staleResponse.status).toBe(409);
    expect(staleResponse.json['error']).toEqual({ code: 'TIME_RESET_WATERMARK_CONFLICT' });
    const after = await db.selectFrom('licenses').selectAll().where('id', '=', staleActive.licenseId).executeTakeFirstOrThrow();
    expect(after.status).toBe('revoked');
    expect(after.current_generation).toBe('1');
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', staleActive.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('0');
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', staleApproval.resetOperationId).execute()).toHaveLength(0);
  });

  it('allows an approved reset for an expired or revoked license without restoring any business right', async () => {
    const revokedActive = await activate();
    const original = await db.selectFrom('licenses').selectAll().where('id', '=', revokedActive.licenseId).executeTakeFirstOrThrow();
    const revoke = { operationId: randomUUID(), licenseId: revokedActive.licenseId, expectedRevision: original.revision.toString(), reason: '测试已撤销许可仍可单独恢复时钟水位' };
    await admin.revokeLicense({ ...revoke, confirmedRequestDigest: changeLicenseStatusRequestDigest(revoke, 'license_revoke') });
    const revokedApproval = await approveReset(revokedActive);
    const revokedReset = await sendApprovedReset(revokedApproval, 1);
    expect(revokedReset.response.status).toBe(200);
    const revokedLicense = await db.selectFrom('licenses').selectAll().where('id', '=', revokedActive.licenseId).executeTakeFirstOrThrow();
    expect(revokedLicense.status).toBe('revoked');
    expect(revokedLicense.confirmed_subscription_end).toEqual(original.confirmed_subscription_end);
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', revokedActive.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('1');

    const expiredActive = await activate();
    const expiredAt = new Date(Date.now() - 60_000);
    await db.updateTable('licenses').set({ confirmed_subscription_end: expiredAt }).where('id', '=', expiredActive.licenseId).execute();
    const expiredApproval = await approveReset(expiredActive);
    const expiredReset = await sendApprovedReset(expiredApproval, 1);
    expect(expiredReset.response.status).toBe(200);
    const expiredLicense = await db.selectFrom('licenses').selectAll().where('id', '=', expiredActive.licenseId).executeTakeFirstOrThrow();
    expect(expiredLicense.status).toBe('active');
    expect(expiredLicense.confirmed_subscription_end).toEqual(expiredAt);
    expect(expiredLicense.confirmed_subscription_end.getTime()).toBeLessThan(Date.now());
    for (const token of [revokedReset.response.json['time_reset_receipt'], expiredReset.response.json['time_reset_receipt']]) {
      expect(typeof token).toBe('string');
      expect(decodeJwt(token as string)).not.toHaveProperty('grants');
      expect(decodeJwt(token as string)).not.toHaveProperty('new_lease');
      expect(decodeJwt(token as string)).not.toHaveProperty('subscription_end');
    }
  });

  it('serializes concurrent same-operation retries to one epoch and one immutable result', async () => {
    const active = await activate();
    const approval = await approveReset(active);
    const [one, two] = await Promise.all([
      makeResetAttempt(approval, 1),
      makeResetAttempt(approval, 2),
    ]);
    const [first, second] = await Promise.all([
      signPost({ port: server.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit', body: one.body, identity: active.identity, nonce: one.serverNonce }),
      signPost({ port: server.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit', body: two.body, identity: active.identity, nonce: two.serverNonce }),
    ]);
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(first.json['time_reset_receipt']).toBe(second.json['time_reset_receipt']);
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', active.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('1');
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', approval.resetOperationId).execute()).toHaveLength(1);
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', approval.resetOperationId).execute()).toHaveLength(2);
  });

  it('lets only one of two different reset operations advance the same expected epoch', async () => {
    const active = await activate();
    const firstApproval = await approveReset(active);
    const secondApproval = await approveReset(active);
    const first = await makeResetAttempt(firstApproval, 1);
    const second = await makeResetAttempt(secondApproval, 1);
    const [left, right] = await Promise.all([
      signPost({ port: server.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit', body: first.body, identity: active.identity, nonce: first.serverNonce }),
      signPost({ port: server.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit', body: second.body, identity: active.identity, nonce: second.serverNonce }),
    ]);
    expect([left.status, right.status].sort()).toEqual([200, 409]);
    const loser = left.status === 409 ? left : right;
    expect(loser.json['error']).toEqual({ code: 'TIME_RESET_WATERMARK_CONFLICT' });
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', active.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('1');
    expect(await db.selectFrom('license_operations').selectAll().where('kind', '=', 'time_reset').where('license_id', '=', active.licenseId).execute()).toHaveLength(1);
  });

  it('replays the original reset receipt when the HTTPS response is lost', async () => {
    const active = await activate();
    const approval = await approveReset(active);
    const attempt = await makeResetAttempt(approval, 1);
    const proxy = new HttpResponseDropProxy();
    await proxy.start(server.port, runtime.config.tlsPrivateKey, runtime.config.tlsCertificate);
    try {
      const dropped = proxy.armNextResponseDrop();
      await expect(signPost({
        port: proxy.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit',
        body: attempt.body, identity: active.identity, nonce: attempt.serverNonce,
      })).rejects.toThrow();
      await dropped;
    } finally {
      await proxy.stop();
    }
    const committed = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', approval.resetOperationId).executeTakeFirstOrThrow();
    expect(committed.state).toBe('committed');
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', active.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('1');
    const retry = await sendApprovedReset(approval, 2);
    expect(retry.response.status).toBe(200);
    expect(retry.response.json['time_reset_receipt']).toBe(committed.response_jws);
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', active.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('1');
  });

  it('recovers an unknown PostgreSQL COMMIT acknowledgement by querying and replaying the operation', async () => {
    const active = await activate();
    const approval = await approveReset(active);
    const proxy = new CommitAckDropProxy();
    await proxy.start('127.0.0.1', Number(new URL(runtime.config.databaseUrl).port));
    const proxiedUrl = new URL(runtime.config.databaseUrl);
    proxiedUrl.port = String(proxy.port);
    const proxiedDb = createDatabase(proxiedUrl.toString(), 4);
    const proxiedServer = await startAppServer(createApp({ config: runtime.config, db: proxiedDb }));
    try {
      const attempt = await makeResetAttempt(approval, 1, { port: proxiedServer.port });
      const dropped = proxy.armNextCommitAckDrop();
      let response: HttpResponse | undefined;
      let requestError: unknown;
      try {
        response = await signPost({
          port: proxiedServer.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit',
          body: attempt.body, identity: active.identity, nonce: attempt.serverNonce,
        });
      } catch (error) {
        requestError = error;
      }
      await dropped;
      expect(requestError !== undefined || (response?.status ?? 0) >= 500).toBe(true);
      const committed = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', approval.resetOperationId).executeTakeFirstOrThrow();
      expect(committed.state).toBe('committed');
      expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', active.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('1');
    } finally {
      await proxiedServer.stop();
      await proxiedDb.destroy();
      await proxy.stop();
    }
    const replay = await sendApprovedReset(approval, 2);
    expect(replay.response.status).toBe(200);
    const committed = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', approval.resetOperationId).executeTakeFirstOrThrow();
    expect(replay.response.json['time_reset_receipt']).toBe(committed.response_jws);
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', active.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('1');
  });

  it('rolls back nonce consumption, epoch, operation, and audit together on a real PostgreSQL failure', async () => {
    const active = await activate();
    const approval = await approveReset(active);
    const attempt = await makeResetAttempt(approval, 1);
    await sql`
      CREATE OR REPLACE FUNCTION fail_time_reset_commit_fixture() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF NEW.kind = 'committed' THEN RAISE EXCEPTION 'injected time-reset rollback'; END IF;
        RETURN NEW;
      END;
      $$;
      CREATE TRIGGER fail_time_reset_commit_fixture BEFORE INSERT ON license_time_reset_events
        FOR EACH ROW EXECUTE FUNCTION fail_time_reset_commit_fixture();
    `.execute(db);
    try {
      const response = await signPost({
        port: server.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit',
        body: attempt.body, identity: active.identity, nonce: attempt.serverNonce,
      });
      expect(response.status).toBe(500);
    } finally {
      await sql`DROP TRIGGER IF EXISTS fail_time_reset_commit_fixture ON license_time_reset_events; DROP FUNCTION IF EXISTS fail_time_reset_commit_fixture()`.execute(db);
    }
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', active.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('0');
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', approval.resetOperationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', approval.resetOperationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', approval.resetOperationId).execute()).toHaveLength(0);
    const nonce = await db.selectFrom('request_nonces').selectAll().where('operation_id', '=', approval.resetOperationId).executeTakeFirstOrThrow();
    expect(nonce.consumed_at).toBeNull();
    const retry = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit',
      body: attempt.body, identity: active.identity, nonce: attempt.serverNonce,
    });
    expect(retry.status).toBe(200);
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', active.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('1');
  });

  it('leaves no partial reset after SIGKILL during its PostgreSQL transaction and accepts the same operation on retry', async () => {
    const active = await activate();
    const approval = await approveReset(active);
    const keyFile = join(scratchDirectory, `test-signing-${randomUUID()}.pem`);
    await writeFile(keyFile, runtime.privatePem, { mode: 0o600 });
    await chmod(keyFile, 0o600);
    const child = await startChildLicenseServer({
      databaseUrl: runtime.config.databaseUrl,
      issuer: runtime.config.issuer,
      publicOrigin: runtime.config.publicOrigin,
      keyFile,
      tlsKeyFile: runtime.config.tlsKeyFile,
      tlsCertFile: runtime.config.tlsCertFile,
    });
    let releaseLock!: () => void;
    let acquiredLock!: () => void;
    const acquired = new Promise<void>((resolve) => { acquiredLock = resolve; });
    const released = new Promise<void>((resolve) => { releaseLock = resolve; });
    const lockTransaction = db.transaction().execute(async (trx) => {
      await sql`SELECT pg_advisory_xact_lock(hashtextextended(${approval.resetOperationId}, 0))`.execute(trx);
      acquiredLock();
      await released;
    });
    await acquired;
    try {
      const attempt = await makeResetAttempt(approval, 1, { port: child.port });
      const pending = signPost({
        port: child.port, origin: runtime.config.publicOrigin, path: '/v1/time-resets/commit',
        body: attempt.body, identity: active.identity, nonce: attempt.serverNonce,
      }).then((response) => ({ response }), (error: unknown) => ({ error }));
      const [waiterPid] = await waitForAdvisoryLockWaiterPids(db, 1);
      if (waiterPid === undefined) throw new Error('Expected one PostgreSQL advisory-lock waiter');
      await child.stop('SIGKILL');
      await terminatePostgresBackend(db, waiterPid);
      const interrupted = await pending;
      expect('error' in interrupted || interrupted.response.status >= 500).toBe(true);
      await waitForNoLockWaiters(db);
    } finally {
      releaseLock();
      await lockTransaction;
      await child.stop('SIGKILL');
    }
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', active.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('0');
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', approval.resetOperationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', approval.resetOperationId).execute()).toHaveLength(0);
    const retry = await sendApprovedReset(approval, 1);
    expect(retry.response.status).toBe(200);
    expect((await db.selectFrom('license_activations').select('time_epoch').where('id', '=', active.activationId).executeTakeFirstOrThrow()).time_epoch).toBe('1');
  });
});
