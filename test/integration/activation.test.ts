import { createHash, randomUUID } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { sql, type Kysely } from 'kysely';
import { decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { createDatabase, migrateToLatest } from '../../src/db/database.js';
import type { Database } from '../../src/db/types.js';
import { activationIntentDigest, renewalIntentDigest } from '../../src/intent.js';
import { applyConfirmedRenewal } from '../../src/services/entitlements.js';
import { createActivationCode, createExpiredActivationFixture, createLicense, getDbNow } from '../fixtures.js';
import { loadTrustedSigningContext } from '../../src/crypto/signing-authority.js';
import { verifyTypedJwt } from '../../src/crypto/jwt.js';
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
  buildChallengeBoundBody,
  requestChallenge,
  signPost,
  startAppServer,
  type HttpResponse,
  type RunningTestServer,
} from '../support/http.js';
import { createIdentity, createTestSigningRuntime, type TestIdentity, type TestSigningRuntime } from '../support/runtime.js';

interface PreparedActivation {
  licenseId: string;
  code: string;
  tokenHash: string;
  identity: TestIdentity;
  instanceId: string;
  databaseId: string;
  operationId: string;
  origin: string;
  intentDigest: string;
}

interface PreparedAttempt {
  body: Record<string, unknown>;
  challengeToken: string;
  serverNonce: string;
}

function nonceFromChallenge(token: string): string {
  const value = decodeJwt(token)['server_nonce'];
  if (typeof value !== 'string') throw new Error('Server challenge nonce missing');
  return value;
}

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

async function holdLicenseRow(db: Kysely<Database>, licenseId: string) {
  const acquired = deferred<void>();
  const release = deferred<void>();
  const transaction = db.transaction().execute(async (trx) => {
    await trx.selectFrom('licenses').select('id').where('id', '=', licenseId).forUpdate().executeTakeFirstOrThrow();
    acquired.resolve();
    await release.promise;
  });
  await acquired.promise;
  return { release: () => release.resolve(), done: transaction };
}

async function holdOperationLock(db: Kysely<Database>, operationId: string) {
  const acquired = deferred<void>();
  const release = deferred<void>();
  const transaction = db.transaction().execute(async (trx) => {
    await sql`SELECT pg_advisory_xact_lock(hashtextextended(${operationId}, 0))`.execute(trx);
    acquired.resolve();
    await release.promise;
  });
  await acquired.promise;
  return { release: () => release.resolve(), done: transaction };
}

async function verifyCenterJwt(token: string, runtime: TestSigningRuntime, now?: Date) {
  return jwtVerify(token, runtime.config.signingPublicKey, {
    algorithms: ['Ed25519'],
    issuer: runtime.config.issuer,
    audience: 'aikayun-commerce',
    ...(now ? { currentDate: now } : {}),
  });
}

describe('real PostgreSQL HTTP activation and recovery', () => {
  let db: Kysely<Database>;
  let server: RunningTestServer;
  let runtime: TestSigningRuntime;

  async function prepareActivation(): Promise<PreparedActivation> {
    const license = await createLicense(db);
    const code = await createActivationCode(db, license.id);
    const identity = await createIdentity();
    const instanceId = randomUUID();
    const databaseId = randomUUID();
    const operationId = randomUUID();
    const origin = 'https://shop.example.test';
    const intentDigest = activationIntentDigest({
      licenseId: license.id, activationCode: code.code, instanceId, databaseId,
      identityJkt: identity.jkt, origin,
    });
    return { licenseId: license.id, code: code.code, tokenHash: code.tokenHash, identity, instanceId, databaseId, operationId, origin, intentDigest };
  }

  async function activationAttempt(
    prepared: PreparedActivation,
    attemptNo: number,
    operation: 'activation' | 'continue' = 'activation',
    onServer = server,
  ): Promise<PreparedAttempt> {
    const challenge = await requestChallenge({
      port: onServer.port, config: runtime.config, identity: prepared.identity, operation,
      operationId: prepared.operationId, intentDigest: prepared.intentDigest, instanceId: prepared.instanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId: prepared.operationId, intentDigest: prepared.intentDigest,
        attemptNo, instanceId: prepared.instanceId, identity: prepared.identity,
        licenseId: prepared.licenseId, databaseId: prepared.databaseId,
      }),
      activation_code: prepared.code,
      origin: prepared.origin,
      ...(operation === 'continue' ? { kind: 'activation' } : {}),
    };
    return { body, challengeToken: challenge.token, serverNonce: nonceFromChallenge(challenge.token) };
  }

  async function sendActivation(prepared: PreparedActivation, attempt: PreparedAttempt, options: {
    signPath?: string;
    sendPath?: string;
    rawBodyOverride?: Buffer;
  } = {}): Promise<HttpResponse> {
    return signPost({
      port: server.port,
      origin: runtime.config.publicOrigin,
      path: '/v1/activations',
      body: attempt.body,
      identity: prepared.identity,
      nonce: attempt.serverNonce,
      ...(options.signPath ? { signPath: options.signPath } : {}),
      ...(options.sendPath ? { sendPath: options.sendPath } : {}),
      ...(options.rawBodyOverride ? { rawBodyOverride: options.rawBodyOverride } : {}),
    });
  }

  async function sendContinue(prepared: PreparedActivation, attemptNo: number, onServer = server): Promise<HttpResponse> {
    const attempt = await activationAttempt(prepared, attemptNo, 'continue', onServer);
    return signPost({
      port: onServer.port,
      origin: runtime.config.publicOrigin,
      path: '/v1/operations/continue',
      body: attempt.body,
      identity: prepared.identity,
      nonce: attempt.serverNonce,
    });
  }

  async function sendRenewal(input: {
    licenseId: string;
    databaseId: string;
    instanceId: string;
    identity: TestIdentity;
    operationId: string;
    sourceOperationId: string;
    expectedGeneration: string;
    knownRevision: string;
    attemptNo: number;
  }): Promise<HttpResponse> {
    const intentDigest = renewalIntentDigest({
      kind: 'recovery', licenseId: input.licenseId, databaseId: input.databaseId,
      instanceId: input.instanceId, identityJkt: input.identity.jkt,
      expectedGeneration: input.expectedGeneration, knownRevision: input.knownRevision,
      recoveryOfOperationId: input.sourceOperationId,
    });
    const challenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: input.identity, operation: 'recovery',
      operationId: input.operationId, intentDigest, instanceId: input.instanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId: input.operationId, intentDigest,
        attemptNo: input.attemptNo, instanceId: input.instanceId, identity: input.identity,
        licenseId: input.licenseId, databaseId: input.databaseId,
      }),
      expected_generation: input.expectedGeneration,
      known_revision: input.knownRevision,
      recovery_of_operation_id: input.sourceOperationId,
    };
    return signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/leases/renew', body,
      identity: input.identity, nonce: nonceFromChallenge(challenge.token),
    });
  }

  async function sendQuery(input: {
    port?: number;
    operationId: string;
    intentDigest: string;
    licenseId: string;
    databaseId: string;
    instanceId: string;
    identity: TestIdentity;
    attemptNo: number;
  }) {
    const requestServer = input.port ? { port: input.port } : server;
    const challenge = await requestChallenge({
      port: requestServer.port, config: runtime.config, identity: input.identity, operation: 'query',
      operationId: input.operationId, intentDigest: input.intentDigest, instanceId: input.instanceId,
    });
    const body = buildChallengeBoundBody({
      challenge: challenge.token, operationId: input.operationId, intentDigest: input.intentDigest,
      attemptNo: input.attemptNo, instanceId: input.instanceId, identity: input.identity,
      licenseId: input.licenseId, databaseId: input.databaseId,
    });
    return signPost({
      port: requestServer.port, origin: runtime.config.publicOrigin, path: '/v1/operations/query', body,
      identity: input.identity, nonce: nonceFromChallenge(challenge.token),
    });
  }

  beforeAll(async () => {
    runtime = await createTestSigningRuntime();
    db = createDatabase(runtime.config.databaseUrl, 24);
    await migrateToLatest(db);
    await runtime.initializeAuthority(db);
    server = await startAppServer(createApp({ config: runtime.config, db }), runtime.config);
  });

  afterAll(async () => {
    await server?.stop();
    await db?.destroy();
    await runtime?.cleanup();
  });

  it('issues a signed challenge and atomically commits a first activation', async () => {
    const prepared = await prepareActivation();
    const attempt = await activationAttempt(prepared, 1);
    const response = await sendActivation(prepared, attempt);
    expect(response.status).toBe(200);
    const token = response.json['license'] as string;
    expect(typeof token).toBe('string');
    const verified = await verifyCenterJwt(token, runtime);
    expect(verified.protectedHeader['typ']).toBe('aikayun-license+jwt');
    expect(Object.keys(verified.protectedHeader).sort()).toEqual(['alg', 'kid', 'typ']);
    expect(Object.keys(verified.payload).sort()).toEqual([
      'activation_generation', 'aud', 'database_id', 'entitlement_revision', 'exp', 'grants', 'iat', 'identity_jkt',
      'instance_id', 'iss', 'jti', 'nbf', 'plan', 'renew_after', 'request_digest', 'request_nonce', 'sub', 'subscription_end', 'v',
    ].sort());
    expect(verified.payload['activation_generation']).toBe('1');
    expect(verified.payload['entitlement_revision']).toBe('1');
    expect(verified.payload['instance_id']).toBe(prepared.instanceId);
    expect(verified.payload['database_id']).toBe(prepared.databaseId);
    expect(verified.payload['identity_jkt']).toBe(prepared.identity.jkt);
    expect(verified.payload['request_digest']).toBe(createHash('sha256').update(JSON.stringify(attempt.body)).digest('base64url'));
    expect(verified.payload['exp']).toBeLessThanOrEqual(verified.payload['subscription_end'] as number);
    expect((verified.payload['exp'] as number) - (verified.payload['iat'] as number)).toBeLessThanOrEqual(7 * 24 * 60 * 60);
    expect(verified.payload['renew_after']).toBeLessThanOrEqual(verified.payload['exp'] as number);
    expect(verified.payload['grants']).toEqual(['create_order', 'create_top_up']);

    const [license, activations, code, operation, attempts, nonceRow] = await Promise.all([
      db.selectFrom('licenses').selectAll().where('id', '=', prepared.licenseId).executeTakeFirstOrThrow(),
      db.selectFrom('license_activations').selectAll().where('license_id', '=', prepared.licenseId).execute(),
      db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow(),
      db.selectFrom('license_operations').selectAll().where('operation_id', '=', prepared.operationId).executeTakeFirstOrThrow(),
      db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).execute(),
      db.selectFrom('request_nonces').selectAll().where('nonce_hash', '=', createHash('sha256').update(attempt.serverNonce).digest('base64url')).executeTakeFirstOrThrow(),
    ]);
    expect(license.current_generation).toBe('1');
    expect(activations).toHaveLength(1);
    expect(activations[0]!.state).toBe('active');
    expect(code.consumed_at).toBeInstanceOf(Date);
    expect(operation.state).toBe('committed');
    expect(operation.response_jws).toBe(token);
    expect(attempts).toHaveLength(1);
    expect(attempts[0]!.outcome).toBe('accepted');
    expect(attempts[0]!.body_digest).toBe(verified.payload['request_digest']);
    expect(nonceRow.consumed_at).toBeInstanceOf(Date);
  });

  it('replays the same committed operation once without consuming the activation code again', async () => {
    const prepared = await prepareActivation();
    const first = await sendActivation(prepared, await activationAttempt(prepared, 1));
    const second = await sendActivation(prepared, await activationAttempt(prepared, 2));
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(second.json['license']).toBe(first.json['license']);
    const attempts = await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).orderBy('attempt_no').execute();
    expect(attempts.map((row) => row.outcome)).toEqual(['accepted', 'committed_replay']);
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', prepared.licenseId).executeTakeFirstOrThrow();
    const code = await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow();
    expect(license.current_generation).toBe('1');
    expect(code.consumed_at).toBeInstanceOf(Date);

    const changedOrigin = 'https://changed.example.test';
    const changedIntent = activationIntentDigest({
      licenseId: prepared.licenseId, activationCode: prepared.code, instanceId: prepared.instanceId,
      databaseId: prepared.databaseId, identityJkt: prepared.identity.jkt, origin: changedOrigin,
    });
    const conflictChallenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: prepared.identity, operation: 'activation',
      operationId: prepared.operationId, intentDigest: changedIntent, instanceId: prepared.instanceId,
    });
    const conflictBody = {
      ...buildChallengeBoundBody({
        challenge: conflictChallenge.token, operationId: prepared.operationId, intentDigest: changedIntent,
        attemptNo: 3, instanceId: prepared.instanceId, identity: prepared.identity,
        licenseId: prepared.licenseId, databaseId: prepared.databaseId,
      }),
      activation_code: prepared.code,
      origin: changedOrigin,
    };
    const changed = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/activations', body: conflictBody,
      identity: prepared.identity, nonce: nonceFromChallenge(conflictChallenge.token),
    });
    expect(changed.status).toBe(409);
    expect((await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).execute())).toHaveLength(2);
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', prepared.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');
  });

  it('rejects signed-body and signed-target changes before changing an existing operation', async () => {
    const prepared = await prepareActivation();
    const original = await sendActivation(prepared, await activationAttempt(prepared, 1));
    expect(original.status).toBe(200);
    const attempt = await activationAttempt(prepared, 2);
    const alteredBody = Buffer.from(JSON.stringify({ ...attempt.body, activation_code: createHash('sha256').update('different').digest('base64url').slice(0, 43) }));
    const bodyTamper = await sendActivation(prepared, attempt, { rawBodyOverride: alteredBody });
    expect(bodyTamper.status).toBe(401);
    const targetTamper = await sendActivation(prepared, attempt, { signPath: '/v1/leases/renew' });
    expect(targetTamper.status).toBe(401);
    const operation = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', prepared.operationId).executeTakeFirstOrThrow();
    expect(operation.state).toBe('committed');
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).execute()).toHaveLength(1);
    const nonceRow = await db.selectFrom('request_nonces').selectAll()
      .where('nonce_hash', '=', createHash('sha256').update(attempt.serverNonce).digest('base64url')).executeTakeFirstOrThrow();
    expect(nonceRow.consumed_at).toBeNull();
  });

  it('replays a committed activation after the HTTP response is lost', async () => {
    const prepared = await prepareActivation();
    const attempt = await activationAttempt(prepared, 1);
    const proxy = new HttpResponseDropProxy();
    await proxy.start(server.port, runtime.config.tlsPrivateKey, runtime.config.tlsCertificate);
    const responseDropped = proxy.armNextResponseDrop();
    let lostResponse: unknown;
    try {
      lostResponse = await signPost({
        port: proxy.port, origin: runtime.config.publicOrigin, path: '/v1/activations', body: attempt.body,
        identity: prepared.identity, nonce: attempt.serverNonce,
      }).catch((error: unknown) => error);
      await responseDropped;
    } finally {
      await proxy.stop();
    }
    expect(lostResponse).toBeInstanceOf(Error);
    const committed = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', prepared.operationId).executeTakeFirstOrThrow();
    expect(committed.state).toBe('committed');
    expect(committed.response_type).toBe('license');
    const code = await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow();
    expect(code.consumed_at).toBeInstanceOf(Date);

    const continued = await sendContinue(prepared, 2);
    expect(continued.status).toBe(200);
    const receipt = await verifyCenterJwt(continued.json['operation_receipt'] as string, runtime);
    expect(receipt.payload['state']).toBe('committed');
    expect(receipt.payload['operation_id']).toBe(prepared.operationId);
    const lease = await verifyCenterJwt(receipt.payload['result_jws'] as string, runtime);
    expect(lease.payload['activation_generation']).toBe('1');
    expect((await db.selectFrom('license_activations').selectAll().where('license_id', '=', prepared.licenseId).where('state', '=', 'active').execute())).toHaveLength(1);
    expect((await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).orderBy('attempt_no').execute()).map((row) => row.outcome))
      .toEqual(['accepted', 'committed_replay']);
  });

  it('does not reveal another identity’s operation result or write business history', async () => {
    const prepared = await prepareActivation();
    const activated = await sendActivation(prepared, await activationAttempt(prepared, 1));
    expect(activated.status).toBe(200);
    const before = await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).execute();
    const rogue = await createIdentity();
    const rejected = await sendQuery({
      operationId: prepared.operationId, intentDigest: prepared.intentDigest,
      licenseId: prepared.licenseId, databaseId: prepared.databaseId,
      instanceId: prepared.instanceId, identity: rogue, attemptNo: 2,
    });
    expect(rejected.status).toBe(200);
    const receipt = await verifyCenterJwt(rejected.json['operation_receipt'] as string, runtime);
    expect(receipt.payload['state']).toBe('not_found');
    expect(receipt.payload['result_jws']).toBeNull();
    const after = await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).execute();
    expect(after).toEqual(before);
    const operation = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', prepared.operationId).executeTakeFirstOrThrow();
    expect(operation.state).toBe('committed');
    expect(operation.actor_jkt).toBe(prepared.identity.jkt);
  });

  it('serializes two instances attempting the same license using PostgreSQL row locks', async () => {
    const license = await createLicense(db);
    const code = await createActivationCode(db, license.id);
    const firstIdentity = await createIdentity();
    const secondIdentity = await createIdentity();
    const first = await prepareActivationWithExisting(license.id, code.code, code.tokenHash, firstIdentity);
    const second = await prepareActivationWithExisting(license.id, code.code, code.tokenHash, secondIdentity);
    const firstAttempt = await activationAttempt(first, 1);
    const secondAttempt = await activationAttempt(second, 1);
    const blocker = await holdLicenseRow(db, license.id);
    try {
      const results = [
        sendActivation(first, firstAttempt),
        sendActivation(second, secondAttempt),
      ];
      await waitForLicenseRowWaiters(db, 2);
      blocker.release();
      const responses = await Promise.all(results);
      expect(responses.map((response) => response.status).sort()).toEqual([200, 409]);
    } finally {
      blocker.release();
      await blocker.done;
    }
    const active = await db.selectFrom('license_activations').selectAll().where('license_id', '=', license.id).where('state', '=', 'active').execute();
    const licenseRow = await db.selectFrom('licenses').selectAll().where('id', '=', license.id).executeTakeFirstOrThrow();
    const codeRow = await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', code.tokenHash).executeTakeFirstOrThrow();
    expect(active).toHaveLength(1);
    expect(licenseRow.current_generation).toBe('1');
    expect(codeRow.consumed_at).toBeInstanceOf(Date);
    const operations = await db.selectFrom('license_operations').selectAll()
      .where('operation_id', 'in', [first.operationId, second.operationId]).execute();
    expect(operations).toHaveLength(1);
    expect(operations[0]!.state).toBe('committed');
    const loserOperationId = operations[0]!.operation_id === first.operationId ? second.operationId : first.operationId;
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', loserOperationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', loserOperationId).execute()).toHaveLength(0);
  });

  it('serializes different licenses competing for one active instance', async () => {
    const licenseA = await createLicense(db);
    const licenseB = await createLicense(db);
    const codeA = await createActivationCode(db, licenseA.id);
    const codeB = await createActivationCode(db, licenseB.id);
    const identityA = await createIdentity();
    const identityB = await createIdentity();
    const sharedInstanceId = randomUUID();
    const first = await prepareActivationWithExisting(licenseA.id, codeA.code, codeA.tokenHash, identityA, sharedInstanceId);
    const second = await prepareActivationWithExisting(licenseB.id, codeB.code, codeB.tokenHash, identityB, sharedInstanceId);
    const firstAttempt = await activationAttempt(first, 1);
    const secondAttempt = await activationAttempt(second, 1);
    let acquired!: () => void;
    let release!: () => void;
    const acquiredPromise = new Promise<void>((resolve) => { acquired = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    const blocker = db.transaction().execute(async (trx) => {
      await sql`SELECT pg_advisory_xact_lock(hashtextextended(${'activation-instance:' + sharedInstanceId}, 0))`.execute(trx);
      acquired();
      await releasePromise;
    });
    await acquiredPromise;
    try {
      const firstRequest = sendActivation(first, firstAttempt);
      await waitForAdvisoryLockWaiters(db, 1);
      const secondRequest = sendActivation(second, secondAttempt);
      await waitForAdvisoryLockWaiters(db, 2);
      release();
      const [firstResponse, secondResponse] = await Promise.all([firstRequest, secondRequest]);
      expect(firstResponse.status).toBe(200);
      expect(secondResponse.status).toBe(409);
      expect((await verifyCenterJwt(secondResponse.json['operation_receipt'] as string, runtime)).payload['outcome_code'])
        .toBe('ACTIVATION_INSTANCE_ALREADY_ACTIVE');
    } finally {
      release();
      await blocker;
    }

    const activeRows = await db.selectFrom('license_activations').selectAll()
      .where('instance_id', '=', sharedInstanceId).where('state', '=', 'active').execute();
    expect(activeRows).toHaveLength(1);
    expect(activeRows[0]!.license_id).toBe(licenseA.id);
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', licenseA.id).executeTakeFirstOrThrow()).current_generation).toBe('1');
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', licenseB.id).executeTakeFirstOrThrow()).current_generation).toBe('0');
    expect((await db.selectFrom('license_operations').selectAll().where('operation_id', '=', first.operationId).executeTakeFirstOrThrow()).state)
      .toBe('committed');
    expect((await db.selectFrom('license_operations').selectAll().where('operation_id', '=', second.operationId).executeTakeFirstOrThrow()).state)
      .toBe('rejected');
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', second.operationId).execute()).toHaveLength(1);
  });

  it('serializes concurrent retries of one operation and produces exactly one business result', async () => {
    const prepared = await prepareActivation();
    const first = await activationAttempt(prepared, 1);
    const second = await activationAttempt(prepared, 2);
    const blocker = await holdOperationLock(db, prepared.operationId);
    try {
      const requests = [sendActivation(prepared, first), sendActivation(prepared, second)];
      await waitForAdvisoryLockWaiters(db, 2);
      blocker.release();
      const responses = await Promise.all(requests);
      expect(responses.map((response) => response.status)).toEqual([200, 200]);
      expect(responses[0]!.json['license']).toBe(responses[1]!.json['license']);
    } finally {
      blocker.release();
      await blocker.done;
    }
    const attempts = await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).execute();
    const license = await db.selectFrom('licenses').selectAll().where('id', '=', prepared.licenseId).executeTakeFirstOrThrow();
    expect(attempts.map((row) => row.outcome).sort()).toEqual(['accepted', 'committed_replay']);
    expect(license.current_generation).toBe('1');
  });

  it('keeps query not-found non-fencing and continues the same intent into one activation', async () => {
    const prepared = await prepareActivation();
    const query = await sendQuery({
      operationId: prepared.operationId, intentDigest: prepared.intentDigest, licenseId: prepared.licenseId,
      databaseId: prepared.databaseId, instanceId: prepared.instanceId, identity: prepared.identity, attemptNo: 1,
    });
    expect(query.status).toBe(200);
    const queryReceipt = await verifyCenterJwt(query.json['operation_receipt'] as string, runtime);
    expect(queryReceipt.protectedHeader['typ']).toBe('aikayun-license-operation+jwt');
    expect(queryReceipt.payload['state']).toBe('not_found');
    expect(queryReceipt.payload['outcome_code']).toBe('OPERATION_NOT_FOUND');
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', prepared.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', prepared.operationId).execute()).toHaveLength(0);

    const continued = await sendContinue(prepared, 2);
    expect(continued.status).toBe(200);
    const receipt = await verifyCenterJwt(continued.json['operation_receipt'] as string, runtime);
    expect(receipt.payload['state']).toBe('committed');
    expect(receipt.payload['operation_id']).toBe(prepared.operationId);
    expect(receipt.payload['intent_digest']).toBe(prepared.intentDigest);
    expect(receipt.payload['committed_attempt_no']).toBe(2);
    const originalLease = await verifyCenterJwt(receipt.payload['result_jws'] as string, runtime);
    expect(originalLease.protectedHeader['typ']).toBe('aikayun-license+jwt');
    expect(originalLease.payload['activation_generation']).toBe('1');
    const attempts = await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).orderBy('attempt_no').execute();
    expect(attempts.map((row) => row.outcome)).toEqual(['accepted']);
  });

  it('does not let an unrecognized activation code create a victim operation or audit event', async () => {
    const victim = await prepareActivation();
    const attacker = await createIdentity();
    const activationCode = createHash('sha256').update(randomUUID()).digest('base64url');
    const instanceId = randomUUID();
    const databaseId = randomUUID();
    const operationId = randomUUID();
    const origin = 'https://shop.example.test';
    const intentDigest = activationIntentDigest({
      licenseId: victim.licenseId, activationCode, instanceId, databaseId,
      identityJkt: attacker.jkt, origin,
    });
    const challenge = await requestChallenge({
      port: server.port, config: runtime.config, identity: attacker, operation: 'activation',
      operationId, intentDigest, instanceId,
    });
    const body = {
      ...buildChallengeBoundBody({
        challenge: challenge.token, operationId, intentDigest, attemptNo: 1, instanceId,
        identity: attacker, licenseId: victim.licenseId, databaseId,
      }),
      activation_code: activationCode,
      origin,
    };
    const response = await signPost({
      port: server.port, origin: runtime.config.publicOrigin, path: '/v1/activations', body,
      identity: attacker, nonce: nonceFromChallenge(challenge.token),
    });
    expect(response.status).toBe(409);
    expect((await verifyCenterJwt(response.json['operation_receipt'] as string, runtime)).payload).toMatchObject({ state: 'rejected', outcome_code: 'ACTIVATION_AUTHORIZATION_INVALID' });
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', operationId).execute()).toHaveLength(0);
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', victim.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('0');
  });

  it.each(['missing', 'expired', 'revoked', 'consumed', 'other-license'])('signs an isolated %s code rejection and recovers via continue', async (variant) => {
    const prepared = await prepareActivation();
    if (variant === 'missing' || variant === 'other-license') {
      const foreign = variant === 'other-license' ? await prepareActivation() : undefined;
      prepared.code = foreign?.code ?? createHash('sha256').update(randomUUID()).digest('base64url');
      prepared.intentDigest = activationIntentDigest({ licenseId: prepared.licenseId, activationCode: prepared.code,
        instanceId: prepared.instanceId, databaseId: prepared.databaseId, identityJkt: prepared.identity.jkt, origin: prepared.origin });
    } else if (variant === 'expired') {
      const old = createHash('sha256').update(randomUUID()).digest('base64url');
      prepared.code = old;
      prepared.tokenHash = createHash('sha256').update(old).digest('base64url');
      const now = await getDbNow(db);
      // An expired historical code can coexist with the current live code only after retirement.
      await db.updateTable('activation_codes').set({ revoked_at: now }).where('license_id', '=', prepared.licenseId).execute();
      await db.insertInto('activation_codes').values({ id: randomUUID(), license_id: prepared.licenseId, token_hash: prepared.tokenHash,
        created_at: new Date(now.getTime() - 120000), expires_at: new Date(now.getTime() - 60000), consumed_at: null, revoked_at: null }).execute();
      prepared.intentDigest = activationIntentDigest({ licenseId: prepared.licenseId, activationCode: old,
        instanceId: prepared.instanceId, databaseId: prepared.databaseId, identityJkt: prepared.identity.jkt, origin: prepared.origin });
    } else {
      const now = await getDbNow(db);
      await db.updateTable('activation_codes').set(variant === 'revoked' ? { revoked_at: now } : { consumed_at: now })
        .where('token_hash', '=', prepared.tokenHash).execute();
    }
    const late = await activationAttempt(prepared, 1);
    const results = await Promise.all([sendActivation(prepared, late), sendContinue(prepared, 2)]);
    expect(results.map(r => r.status).sort()).toEqual([200, 409]);
    for (const response of results) {
      const receipt = await verifyCenterJwt(response.json['operation_receipt'] as string, runtime);
      expect(receipt.payload).toMatchObject({ state: 'rejected', outcome_code: 'ACTIVATION_AUTHORIZATION_INVALID',
        actor_jkt: prepared.identity.jkt, operation_id: prepared.operationId, intent_digest: prepared.intentDigest });
    }
    const direct = results.find(r => r.status === 409)!;
    const directClaims = (await verifyCenterJwt(direct.json['operation_receipt'] as string, runtime)).payload;
    expect(directClaims['attempt_no']).toBe(1);
    expect(directClaims['request_nonce_hash']).toBe(createHash('sha256').update(late.serverNonce).digest('base64url'));
    expect(directClaims['request_digest']).toBe(createHash('sha256').update(JSON.stringify(late.body)).digest('base64url'));
    expect((await sendContinue(prepared, 3)).status).toBe(200);
    expect((await sendActivation(prepared, late)).json['error']).toEqual({ code: 'CHALLENGE_EXPIRED_OR_REPLAYED' });
    expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', prepared.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).execute()).toHaveLength(0);
    expect(await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', prepared.operationId).execute()).toHaveLength(0);
    if (variant === 'expired') expect((await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow()).revoked_at).toBeInstanceOf(Date);
  });

  it('lets the original inactive actor query a persisted rejection without exposing it to another actor', async () => {
    const prepared = await prepareActivation();
    const now = await getDbNow(db);
    await db.updateTable('licenses').set({ status: 'revoked', updated_at: now }).where('id', '=', prepared.licenseId).execute();
    const rejected = await sendActivation(prepared, await activationAttempt(prepared, 1));
    expect(rejected.status).toBe(409);
    const original = rejected.json['operation_receipt'];
    const query = await sendQuery({ ...prepared, attemptNo: 2 });
    expect((await verifyCenterJwt(query.json['operation_receipt'] as string, runtime)).payload)
      .toMatchObject({ state: 'rejected', result_jws: original, outcome_code: 'LICENSE_REVOKED' });
    const rogue = await createIdentity();
    const hidden = await sendQuery({ ...prepared, identity: rogue, attemptNo: 3 });
    expect((await verifyCenterJwt(hidden.json['operation_receipt'] as string, runtime)).payload)
      .toMatchObject({ state: 'not_found', result_jws: null });
    expect(await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).execute()).toHaveLength(2);
  });

  it('keeps an expired code revoked when database time rolls back before a late original request', async () => {
    const prepared = await prepareActivation();
    const now = await getDbNow(db);
    await db.updateTable('activation_codes').set({ revoked_at: now }).where('token_hash', '=', prepared.tokenHash).execute();
    prepared.code = createHash('sha256').update(randomUUID()).digest('base64url');
    prepared.tokenHash = createHash('sha256').update(prepared.code).digest('base64url');
    await db.insertInto('activation_codes').values({ id: randomUUID(), license_id: prepared.licenseId, token_hash: prepared.tokenHash,
      created_at: now, expires_at: new Date(now.getTime() + 10000), consumed_at: null, revoked_at: null }).execute();
    prepared.intentDigest = activationIntentDigest({ licenseId: prepared.licenseId, activationCode: prepared.code,
      instanceId: prepared.instanceId, databaseId: prepared.databaseId, identityJkt: prepared.identity.jkt, origin: prepared.origin });
    await sql`CREATE TABLE public.test_clock_offset (seconds integer NOT NULL); INSERT INTO public.test_clock_offset VALUES (0);
      CREATE FUNCTION public.clock_timestamp() RETURNS timestamptz LANGUAGE sql VOLATILE AS
      'SELECT pg_catalog.clock_timestamp() + (seconds * interval ''1 second'') FROM public.test_clock_offset'`.execute(db);
    const url = new URL(runtime.config.databaseUrl);
    url.searchParams.set('options', '-csearch_path=public,pg_catalog');
    const clockDb = createDatabase(url.toString(), 4);
    const clockServer = await startAppServer(createApp({ config: runtime.config, db: clockDb }), runtime.config);
    try {
      const original = await activationAttempt(prepared, 1, 'activation', clockServer);
      await sql`UPDATE public.test_clock_offset SET seconds = 20`.execute(db);
      expect((await getDbNow(clockDb)).getTime() - (await getDbNow(db)).getTime()).toBeGreaterThan(19000);
      const rejected = await sendContinue(prepared, 2, clockServer);
      expect(rejected.status).toBe(200);
      expect((await verifyCenterJwt(rejected.json['operation_receipt'] as string, runtime, new Date(Date.now() + 20000))).payload['state']).toBe('rejected');
      await sql`UPDATE public.test_clock_offset SET seconds = 0`.execute(db);
      const late = await signPost({ port: clockServer.port, origin: runtime.config.publicOrigin, path: '/v1/activations',
        body: original.body, identity: prepared.identity, nonce: original.serverNonce });
      expect(late.status).toBe(409);
      expect((await verifyCenterJwt(late.json['operation_receipt'] as string, runtime)).payload['state']).toBe('rejected');
      const code = await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow();
      expect(code.revoked_at).toBeInstanceOf(Date);
      expect(code.consumed_at).toBeNull();
      expect((await db.selectFrom('licenses').select('current_generation').where('id', '=', prepared.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('0');
    } finally {
      await clockServer.stop();
      await clockDb.destroy();
      await sql`DROP FUNCTION public.clock_timestamp(); DROP TABLE public.test_clock_offset`.execute(db);
    }
  });

  it('does not consume a nonce or retire an expired code when signing authority is unavailable', async () => {
    const prepared = await prepareActivation();
    const now = await getDbNow(db);
    await db.updateTable('activation_codes').set({ revoked_at: now }).where('token_hash', '=', prepared.tokenHash).execute();
    prepared.code = createHash('sha256').update(randomUUID()).digest('base64url');
    prepared.tokenHash = createHash('sha256').update(prepared.code).digest('base64url');
    await db.insertInto('activation_codes').values({ id: randomUUID(), license_id: prepared.licenseId, token_hash: prepared.tokenHash,
      created_at: new Date(now.getTime() - 120000), expires_at: new Date(now.getTime() - 60000), consumed_at: null, revoked_at: null }).execute();
    prepared.intentDigest = activationIntentDigest({ licenseId: prepared.licenseId, activationCode: prepared.code,
      instanceId: prepared.instanceId, databaseId: prepared.databaseId, identityJkt: prepared.identity.jkt, origin: prepared.origin });
    const attempt = await activationAttempt(prepared, 1);
    const badServer = await startAppServer(createApp({ config: { ...runtime.config, signingKeyring: new Map() }, db }), runtime.config);
    try {
      const failed = await signPost({ port: badServer.port, origin: runtime.config.publicOrigin, path: '/v1/activations',
        body: attempt.body, identity: prepared.identity, nonce: attempt.serverNonce });
      expect(failed.status).toBe(503);
      expect(failed.json['operation_receipt']).toBeUndefined();
      expect((await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow()).revoked_at).toBeNull();
      const recovered = await sendActivation(prepared, attempt);
      expect(recovered.status).toBe(409);
      expect((await verifyCenterJwt(recovered.json['operation_receipt'] as string, runtime)).payload['state']).toBe('rejected');
    } finally { await badServer.stop(); }
  });

  it('rolls back expired-code retirement and nonce consumption on a database error', async () => {
    const prepared = await prepareActivation();
    const now = await getDbNow(db);
    await db.updateTable('activation_codes').set({ revoked_at: now }).where('token_hash', '=', prepared.tokenHash).execute();
    prepared.code = createHash('sha256').update(randomUUID()).digest('base64url');
    prepared.tokenHash = createHash('sha256').update(prepared.code).digest('base64url');
    await db.insertInto('activation_codes').values({ id: randomUUID(), license_id: prepared.licenseId, token_hash: prepared.tokenHash,
      created_at: new Date(now.getTime() - 120000), expires_at: new Date(now.getTime() - 60000), consumed_at: null, revoked_at: null }).execute();
    prepared.intentDigest = activationIntentDigest({ licenseId: prepared.licenseId, activationCode: prepared.code,
      instanceId: prepared.instanceId, databaseId: prepared.databaseId, identityJkt: prepared.identity.jkt, origin: prepared.origin });
    const attempt = await activationAttempt(prepared, 1);
    await sql`CREATE FUNCTION public.test_fail_code_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected failure'; END $$;
      CREATE TRIGGER test_fail_code_update AFTER UPDATE ON activation_codes FOR EACH ROW EXECUTE FUNCTION public.test_fail_code_update()`.execute(db);
    try {
      const failed = await sendActivation(prepared, attempt);
      expect(failed.status).toBe(500);
      expect(failed.json['operation_receipt']).toBeUndefined();
      expect((await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow()).revoked_at).toBeNull();
    } finally {
      await sql`DROP TRIGGER test_fail_code_update ON activation_codes; DROP FUNCTION public.test_fail_code_update()`.execute(db);
    }
    const recovered = await sendActivation(prepared, attempt);
    expect(recovered.status).toBe(409);
    expect((await verifyCenterJwt(recovered.json['operation_receipt'] as string, runtime)).payload['state']).toBe('rejected');
  });

  it('rejects an expired nonce that arrives after continuation already committed', async () => {
    const prepared = await prepareActivation();
    const oldIssuer = startAppServer(createApp({
      config: runtime.config,
      db,
      challengeNow: async () => new Date(Date.now() - 10 * 60 * 1000),
    }), runtime.config);
    const oldServer = await oldIssuer;
    const staleAttempt = await activationAttempt(prepared, 1, 'activation', oldServer);
    const continued = await sendContinue(prepared, 2);
    expect(continued.status).toBe(200);

    const late = await sendActivation(prepared, staleAttempt);
    expect(late.status, JSON.stringify(late.json)).toBe(409);
    expect(late.json['error']).toEqual({ code: 'CHALLENGE_EXPIRED_OR_REPLAYED' });
    await oldServer.stop();
    const attempts = await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).orderBy('attempt_no').execute();
    expect(attempts.map(({ attempt_no, outcome }) => [attempt_no, outcome])).toEqual([
      [1, 'retryable_reject'], [2, 'accepted'],
    ]);
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', prepared.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');
    expect((await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow()).consumed_at).toBeInstanceOf(Date);
  });

  it('does not restore authority to an old signed challenge after nonce cleanup', async () => {
    const prepared = await prepareActivation();
    const oldIssuer = startAppServer(createApp({
      config: runtime.config,
      db,
      challengeNow: async () => new Date(Date.now() - 26 * 60 * 60 * 1000),
    }), runtime.config);
    const oldServer = await oldIssuer;
    try {
      const staleAttempt = await activationAttempt(prepared, 1, 'activation', oldServer);
      const nonceHash = createHash('sha256').update(staleAttempt.serverNonce).digest('base64url');
      expect(await db.selectFrom('request_nonces').selectAll().where('nonce_hash', '=', nonceHash).executeTakeFirst()).toBeDefined();
      const cleanup = await sql<{ count: number }>`SELECT cleanup_expired_request_nonces(10) AS count`.execute(db);
      expect(Number(cleanup.rows[0]!.count)).toBeGreaterThanOrEqual(1);
      expect(await db.selectFrom('request_nonces').selectAll().where('nonce_hash', '=', nonceHash).executeTakeFirst()).toBeUndefined();

      const late = await sendActivation(prepared, staleAttempt);
      expect(late.status, JSON.stringify(late.json)).toBe(409);
      expect(late.json['error']).toEqual({ code: 'CHALLENGE_EXPIRED_OR_REPLAYED' });
      expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', prepared.operationId).executeTakeFirst()).toBeUndefined();
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', prepared.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('0');
      expect((await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow()).consumed_at).toBeNull();
    } finally {
      await oldServer.stop();
    }
  });

  it('recovers an expired historical lease at the current revision without incrementing generation', async () => {
    const identity = await createIdentity();
    const fixture = await createExpiredActivationFixture(db, runtime.config, identity);
    const original = await jwtVerify(fixture.token, runtime.config.signingPublicKey, {
      algorithms: ['Ed25519'], issuer: runtime.config.issuer, audience: 'aikayun-commerce',
      currentDate: new Date((fixture.iat + 1) * 1000),
    });
    expect(original.payload['exp']).toBeLessThan(Math.floor(Date.now() / 1000));

    const event = await applyConfirmedRenewal(db, {
      licenseId: fixture.id, externalEventId: `event-${randomUUID()}`, actor: 'isolated-test-fixture',
    });
    const replayedEvent = await applyConfirmedRenewal(db, {
      licenseId: fixture.id, externalEventId: (await db.selectFrom('entitlement_events').select('external_event_id').where('id', '=', event.eventId).executeTakeFirstOrThrow()).external_event_id,
      actor: 'isolated-test-fixture',
    });
    expect(event.replayed).toBe(false);
    expect(replayedEvent.replayed).toBe(true);
    expect(replayedEvent.newEnd).toEqual(event.newEnd);
    expect(replayedEvent.revision).toBe('2');

    const recoveryOperationId = randomUUID();
    const response = await sendRenewal({
      licenseId: fixture.id, databaseId: fixture.databaseId, instanceId: fixture.instanceId,
      identity, operationId: recoveryOperationId, sourceOperationId: fixture.operationId,
      expectedGeneration: '1', knownRevision: '1', attemptNo: 1,
    });
    expect(response.status).toBe(200);
    const renewed = await verifyCenterJwt(response.json['license'] as string, runtime);
    expect(renewed.protectedHeader['typ']).toBe('aikayun-license+jwt');
    expect(renewed.payload['activation_generation']).toBe('1');
    expect(renewed.payload['entitlement_revision']).toBe('2');
    expect(renewed.payload['request_nonce']).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const recoveryAttempt = await db.selectFrom('license_operation_attempts').selectAll()
      .where('operation_id', '=', recoveryOperationId).where('outcome', '=', 'accepted').executeTakeFirstOrThrow();
    expect(renewed.payload['request_digest']).toBe(recoveryAttempt.body_digest);
    expect(createHash('sha256').update(renewed.payload['request_nonce'] as string).digest('base64url'))
      .toBe(recoveryAttempt.server_nonce_hash);
    expect(renewed.payload['exp']).toBeGreaterThan(Math.floor(Date.now() / 1000));
    const current = await db.selectFrom('licenses').selectAll().where('id', '=', fixture.id).executeTakeFirstOrThrow();
    const activations = await db.selectFrom('license_activations').selectAll().where('license_id', '=', fixture.id).where('state', '=', 'active').execute();
    expect(current.current_generation).toBe('1');
    expect(current.entitlement_revision).toBe('2');
    expect(activations).toHaveLength(1);
  });

  it('replays a prior renewal with its original revision after a later renewal', async () => {
    const license = await createLicense(db);
    const firstId = `event-first-${randomUUID()}`;
    const secondId = `event-second-${randomUUID()}`;
    const first = await applyConfirmedRenewal(db, { licenseId: license.id, externalEventId: firstId, actor: 'isolated-test-fixture' });
    const second = await applyConfirmedRenewal(db, { licenseId: license.id, externalEventId: secondId, actor: 'isolated-test-fixture' });
    const beforeReplay = await db.selectFrom('licenses').selectAll().where('id', '=', license.id).executeTakeFirstOrThrow();
    const replay = await applyConfirmedRenewal(db, { licenseId: license.id, externalEventId: firstId, actor: 'isolated-test-fixture' });
    const afterReplay = await db.selectFrom('licenses').selectAll().where('id', '=', license.id).executeTakeFirstOrThrow();
    const events = await db.selectFrom('entitlement_events').selectAll().where('license_id', '=', license.id).execute();

    expect(first.revision).toBe('2');
    expect(second.revision).toBe('3');
    expect(replay).toMatchObject({
      eventId: first.eventId, licenseId: license.id, previousEnd: first.previousEnd,
      newEnd: first.newEnd, revision: '2', replayed: true,
    });
    expect(afterReplay.confirmed_subscription_end).toEqual(beforeReplay.confirmed_subscription_end);
    expect(afterReplay.entitlement_revision).toBe('3');
    expect(events).toHaveLength(2);
  });

  it('returns signed revoked and superseded statuses without issuing recovery leases', async () => {
    const revokedIdentity = await createIdentity();
    const revoked = await createExpiredActivationFixture(db, runtime.config, revokedIdentity);
    const revokedNow = await getDbNow(db);
    await db.updateTable('licenses').set({ status: 'revoked', entitlement_revision: '2', revision: '3', updated_at: revokedNow })
      .where('id', '=', revoked.id).execute();
    const revokedResponse = await sendRenewal({
      licenseId: revoked.id, databaseId: revoked.databaseId, instanceId: revoked.instanceId,
      identity: revokedIdentity, operationId: randomUUID(), sourceOperationId: revoked.operationId,
      expectedGeneration: '1', knownRevision: '1', attemptNo: 1,
    });
    expect(revokedResponse.status).toBe(409);
    const revokedReceipt = await verifyCenterJwt(revokedResponse.json['status_receipt'] as string, runtime);
    expect(revokedReceipt.protectedHeader['typ']).toBe('aikayun-license-status+jwt');
    expect(revokedReceipt.payload['status']).toBe('revoked');
    expect(revokedReceipt.payload['entitlement_revision']).toBe('2');
    expect(revokedResponse.json['license']).toBeUndefined();

    const oldIdentity = await createIdentity();
    const superseded = await createExpiredActivationFixture(db, runtime.config, oldIdentity);
    const newIdentity = await createIdentity();
    const supersededNow = await getDbNow(db);
    const oldActivation = await db.selectFrom('license_activations').selectAll()
      .where('license_id', '=', superseded.id).where('identity_jkt', '=', oldIdentity.jkt).executeTakeFirstOrThrow();
    await db.updateTable('license_activations').set({ state: 'retired', retired_at: supersededNow }).where('id', '=', oldActivation.id).execute();
    await db.updateTable('licenses').set({ current_generation: '2', revision: '3', updated_at: supersededNow })
      .where('id', '=', superseded.id).execute();
    await db.insertInto('license_activations').values({
      id: randomUUID(), license_id: superseded.id, generation: '2', instance_id: randomUUID(), database_id: randomUUID(),
      identity_jwk_public: newIdentity.publicJwk, identity_jkt: newIdentity.jkt, state: 'active', activated_at: supersededNow,
      retired_at: null, last_seen_at: supersededNow, origin_display: 'https://new-shop.example.test',
    }).execute();
    const supersededResponse = await sendRenewal({
      licenseId: superseded.id, databaseId: superseded.databaseId, instanceId: superseded.instanceId,
      identity: oldIdentity, operationId: randomUUID(), sourceOperationId: superseded.operationId,
      expectedGeneration: '1', knownRevision: '1', attemptNo: 1,
    });
    expect(supersededResponse.status).toBe(409);
    const supersededReceipt = await verifyCenterJwt(supersededResponse.json['status_receipt'] as string, runtime);
    expect(supersededReceipt.payload['status']).toBe('superseded');
    expect(supersededReceipt.payload['current_generation']).toBe('2');
    expect(supersededResponse.json['license']).toBeUndefined();
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', superseded.id).executeTakeFirstOrThrow()).current_generation).toBe('2');
  });

  it('enforces immutable terminal operations, append-only attempts/audit, and one-way nonce/code consumption', async () => {
    const prepared = await prepareActivation();
    const attempt = await activationAttempt(prepared, 1);
    expect((await sendActivation(prepared, attempt)).status).toBe(200);
    const operation = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', prepared.operationId).executeTakeFirstOrThrow();
    const savedAttempt = await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).executeTakeFirstOrThrow();
    const audit = await db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', prepared.operationId).executeTakeFirstOrThrow();
    const nonceHash = createHash('sha256').update(attempt.serverNonce).digest('base64url');
    await expect(db.updateTable('license_operations').set({ outcome_code: 'CHANGED' }).where('operation_id', '=', operation.operation_id).execute())
      .rejects.toMatchObject({ code: '55000' });
    await expect(db.updateTable('license_operation_attempts').set({ outcome: 'retryable_reject' }).where('attempt_id', '=', savedAttempt.attempt_id).execute())
      .rejects.toMatchObject({ code: '55000' });
    await expect(db.deleteFrom('license_audit_events').where('id', '=', audit.id).execute()).rejects.toMatchObject({ code: '55000' });
    await expect(db.updateTable('activation_codes').set({ consumed_at: null }).where('token_hash', '=', prepared.tokenHash).execute())
      .rejects.toMatchObject({ code: '55000' });
    await expect(db.updateTable('request_nonces').set({ consumed_at: null }).where('nonce_hash', '=', nonceHash).execute())
      .rejects.toMatchObject({ code: '55000' });
    expect((await db.selectFrom('license_operations').selectAll().where('operation_id', '=', operation.operation_id).executeTakeFirstOrThrow()).outcome_code)
      .toBe('ACTIVATED');
  });

  it('allows only bounded cleanup of sufficiently old nonces and never changes attempt evidence', async () => {
    const oldHash = `old-${randomUUID()}`;
    const recentHash = `recent-${randomUUID()}`;
    const liveHash = `live-${randomUUID()}`;
    const now = await getDbNow(db);
    const old = new Date(now.getTime() - 26 * 60 * 60 * 1000);
    const recent = new Date(now.getTime() - 23 * 60 * 60 * 1000);
    const operationId = randomUUID();
    for (const [hash, createdAt, expiresAt] of [
      [oldHash, old, new Date(old.getTime() + 5 * 60 * 1000)],
      [recentHash, recent, new Date(recent.getTime() + 5 * 60 * 1000)],
      [liveHash, now, new Date(now.getTime() + 5 * 60 * 1000)],
    ] as const) {
      await db.insertInto('request_nonces').values({
        nonce_hash: hash, operation: 'activation', operation_id: operationId, intent_digest: 'test',
        instance_id: randomUUID(), identity_jkt: 'test', client_nonce_hash: `client-${hash}`,
        challenge_jws_digest: `challenge-${hash}`, created_at: createdAt, expires_at: expiresAt, consumed_at: null,
      }).execute();
    }
    const beforeAttempts = await db.selectFrom('license_operation_attempts').selectAll().execute();
    await expect(sql`SELECT cleanup_expired_request_nonces(501)`.execute(db)).rejects.toMatchObject({ code: '22023' });
    const cleaned = await sql<{ count: number }>`SELECT cleanup_expired_request_nonces(1) AS count`.execute(db);
    expect(Number(cleaned.rows[0]!.count)).toBe(1);
    expect(await db.selectFrom('request_nonces').selectAll().where('nonce_hash', '=', oldHash).executeTakeFirst()).toBeUndefined();
    expect(await db.selectFrom('request_nonces').selectAll().where('nonce_hash', '=', recentHash).executeTakeFirst()).toBeDefined();
    expect(await db.selectFrom('request_nonces').selectAll().where('nonce_hash', '=', liveHash).executeTakeFirst()).toBeDefined();
    expect(await db.selectFrom('license_operation_attempts').selectAll().execute()).toEqual(beforeAttempts);
    await expect(db.deleteFrom('request_nonces').where('nonce_hash', '=', recentHash).execute()).rejects.toMatchObject({ code: '55000' });
    await expect(db.deleteFrom('request_nonces').where('nonce_hash', '=', liveHash).execute()).rejects.toMatchObject({ code: '55000' });
  });

  it('rejects direct and CASCADE TRUNCATE across every core authorization table', async () => {
    const protectedTables = [
      'licenses', 'license_activations', 'activation_codes', 'request_nonces',
      'license_operations', 'license_operation_attempts', 'entitlement_events', 'license_audit_events',
      'license_admin_operations', 'license_admin_audit_events',
    ];
    for (const table of protectedTables) {
      await expect(sql`TRUNCATE TABLE ${sql.table(table)} CASCADE`.execute(db)).rejects.toMatchObject({ code: '55000' });
    }
    await expect(sql`TRUNCATE TABLE request_nonces`.execute(db)).rejects.toMatchObject({ code: '55000' });
    await expect(sql`TRUNCATE TABLE licenses CASCADE`.execute(db)).rejects.toMatchObject({ code: '55000' });
  });

  it('drops the PostgreSQL COMMIT acknowledgement and recovers the durable result by the same operation', async () => {
    const previous = { db, server, runtime };
    const isolatedRuntime = await createTestSigningRuntime();
    const isolatedDb = createDatabase(isolatedRuntime.config.databaseUrl, 24);
    await migrateToLatest(isolatedDb);
    await isolatedRuntime.initializeAuthority(isolatedDb);
    const isolatedServer = await startAppServer(createApp({ config: isolatedRuntime.config, db: isolatedDb }), isolatedRuntime.config);
    db = isolatedDb;
    server = isolatedServer;
    runtime = isolatedRuntime;
    try {
    const prepared = await prepareActivation();
    const proxy = new CommitAckDropProxy();
    const database = new URL(runtime.config.databaseUrl);
    await proxy.start(database.hostname, Number(database.port || '5432'));
    const proxyUrl = new URL(runtime.config.databaseUrl);
    proxyUrl.port = String(proxy.port);
    proxyUrl.searchParams.set('sslmode', 'disable');
    const proxyDb = createDatabase(proxyUrl.toString(), 4);
    const proxyServer = await startAppServer(createApp({ config: runtime.config, db: proxyDb }), runtime.config);
    try {
      const attempt = await activationAttempt(prepared, 1, 'activation', proxyServer);
      const commitDropped = proxy.armNextCommitAckDrop(1);
      const responsePromise = signPost({
        port: proxyServer.port, origin: runtime.config.publicOrigin, path: '/v1/activations', body: attempt.body,
        identity: prepared.identity, nonce: attempt.serverNonce,
      });
      await commitDropped;
      const lostResponse = await responsePromise;
      expect(lostResponse.status, JSON.stringify(lostResponse.json)).toBe(500);
      const durable = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', prepared.operationId).executeTakeFirstOrThrow();
      expect(durable.state).toBe('committed');
      expect(durable.response_type).toBe('license');
      expect(decodeProtectedHeader(durable.response_jws!)['kid']).toBe(runtime.onlineKey.kid);
      await proxyServer.stop();
      await proxyDb.destroy();

      const b = await runtime.createOnlineKey();
      await publishAndRotateTo(db, runtime, b, '2');
      const continued = await sendContinue(prepared, 2);
      expect(continued.status).toBe(200);
      const trusted = (await loadTrustedSigningContext(db, runtime.config)).context;
      const operationReceiptToken = continued.json['operation_receipt'] as string;
      const operationReceipt = await verifyTypedJwt(operationReceiptToken, {
        ...trusted, typ: 'aikayun-license-operation+jwt', audience: 'aikayun-commerce',
        now: new Date(trusted.trustedTime * 1000), requiredClaims: Object.keys(decodeJwt(operationReceiptToken)),
      });
      expect(decodeProtectedHeader(operationReceiptToken)['kid']).toBe(b.kid);
      expect(operationReceipt.claims['state']).toBe('committed');
      expect(operationReceipt.claims['result_jws']).toBe(durable.response_jws);
      const originalLease = await verifyTypedJwt(durable.response_jws!, {
        ...trusted, typ: 'aikayun-license+jwt', audience: 'aikayun-commerce',
        now: new Date(trusted.trustedTime * 1000), requiredClaims: Object.keys(decodeJwt(durable.response_jws!)),
      });
      expect(decodeProtectedHeader(durable.response_jws!)['kid']).toBe(runtime.onlineKey.kid);
      expect(originalLease.claims['activation_generation']).toBe('1');
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', prepared.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');
      expect((await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow()).consumed_at).toBeInstanceOf(Date);
    } finally {
      await proxyServer.stop().catch(() => undefined);
      await proxyDb.destroy().catch(() => undefined);
      await proxy.stop();
    }
    } finally {
      await isolatedServer.stop();
      await isolatedDb.destroy();
      await isolatedRuntime.cleanup();
      db = previous.db;
      server = previous.server;
      runtime = previous.runtime;
    }
  });

  it('rolls back a blocked activation when the process is killed and resumes after restart', async () => {
    const prepared = await prepareActivation();
    let child: Awaited<ReturnType<typeof startChildLicenseServer>> | undefined;
    let restarted: Awaited<ReturnType<typeof startChildLicenseServer>> | undefined;
    const blocker = await holdLicenseRow(db, prepared.licenseId);
    try {
      child = await startChildLicenseServer({
        databaseUrl: runtime.config.databaseUrl, issuer: runtime.config.issuer,
        publicOrigin: runtime.config.publicOrigin,
        keyringFile: runtime.keyringFile,
        offlineRootJwkFile: runtime.offlineRootJwkFile,
        minimumTrustBundleVersion: runtime.config.minimumTrustBundleVersion,
        tlsKeyFile: runtime.config.tlsKeyFile, tlsCertFile: runtime.config.tlsCertFile,
      });
      const attempt = await activationAttempt(prepared, 1, 'activation', child);
      const responsePromise = signPost({
        port: child.port, origin: runtime.config.publicOrigin, path: '/v1/activations', body: attempt.body,
        identity: prepared.identity, nonce: attempt.serverNonce,
      }).catch((error: unknown) => error);
      const [waiterPid] = await waitForLicenseRowWaiterPids(db, 1);
      if (waiterPid === undefined) throw new Error('Expected one PostgreSQL row-lock waiter');
      await child.stop('SIGKILL');
      // Docker Desktop's host port forwarder can keep the TCP half-open briefly
      // after SIGKILL; terminate this observed backend to synchronize rollback.
      await terminatePostgresBackend(db, waiterPid);
      await waitForNoLockWaiters(db);
      const lost = await responsePromise;
      expect(lost instanceof Error || (lost as HttpResponse).status >= 500).toBe(true);
      const beforeRelease = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', prepared.operationId).execute();
      expect(beforeRelease).toHaveLength(0);
      const codeBeforeRelease = await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow();
      expect(codeBeforeRelease.consumed_at).toBeNull();
      const attemptsBeforeRelease = await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).execute();
      expect(attemptsBeforeRelease).toHaveLength(0);
      blocker.release();
      await blocker.done;

      restarted = await startChildLicenseServer({
        databaseUrl: runtime.config.databaseUrl, issuer: runtime.config.issuer,
        publicOrigin: runtime.config.publicOrigin,
        keyringFile: runtime.keyringFile,
        offlineRootJwkFile: runtime.offlineRootJwkFile,
        minimumTrustBundleVersion: runtime.config.minimumTrustBundleVersion,
        tlsKeyFile: runtime.config.tlsKeyFile, tlsCertFile: runtime.config.tlsCertFile,
      });
      const continued = await sendContinue(prepared, 2, restarted);
      expect(continued.status).toBe(200);
      const receipt = await verifyCenterJwt(continued.json['operation_receipt'] as string, runtime);
      expect(receipt.payload['state']).toBe('committed');
      const current = await db.selectFrom('licenses').selectAll().where('id', '=', prepared.licenseId).executeTakeFirstOrThrow();
      expect(current.current_generation).toBe('1');
      expect(await db.selectFrom('license_operations').selectAll().where('operation_id', '=', prepared.operationId).execute()).toHaveLength(1);
    } finally {
      blocker.release();
      await blocker.done.catch(() => undefined);
      await child?.stop('SIGKILL').catch(() => undefined);
      await restarted?.stop().catch(() => undefined);
    }
  });
});

async function prepareActivationWithExisting(
  licenseId: string,
  code: string,
  tokenHash: string,
  identity: TestIdentity,
  instanceId = randomUUID(),
): Promise<PreparedActivation> {
  const databaseId = randomUUID();
  const operationId = randomUUID();
  const origin = 'https://shop.example.test';
  const intentDigest = activationIntentDigest({
    licenseId, activationCode: code, instanceId, databaseId, identityJkt: identity.jkt, origin,
  });
  return { licenseId, code, tokenHash, identity, instanceId, databaseId, operationId, origin, intentDigest };
}
