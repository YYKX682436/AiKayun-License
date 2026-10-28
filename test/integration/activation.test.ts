import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as httpRequest } from 'node:http';
import { sql, type Kysely } from 'kysely';
import { decodeJwt, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { createDatabase, migrateToLatest } from '../../src/db/database.js';
import type { Database } from '../../src/db/types.js';
import { activationIntentDigest, renewalIntentDigest } from '../../src/intent.js';
import { applyConfirmedRenewal } from '../../src/services/entitlements.js';
import { createActivationCode, createExpiredActivationFixture, createLicense, getDbNow } from '../fixtures.js';
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
    server = await startAppServer(createApp({ config: runtime.config, db }));
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

  it('rejects a different actor querying a known operation without changing its attempts', async () => {
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
    expect(rejected.status).toBe(403);
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
    expect(operations.map((row) => row.state).sort()).toEqual(['committed', 'rejected']);
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
    expect(attempts.map((row) => row.outcome)).toEqual(['retryable_reject', 'accepted']);
  });

  it('rejects an expired nonce that arrives after continuation already committed', async () => {
    const prepared = await prepareActivation();
    const oldIssuer = startAppServer(createApp({
      config: runtime.config,
      db,
      challengeNow: async () => new Date(Date.now() - 10 * 60 * 1000),
    }));
    const oldServer = await oldIssuer;
    const staleAttempt = await activationAttempt(prepared, 1, 'activation', oldServer);
    const continued = await sendContinue(prepared, 2);
    expect(continued.status).toBe(200);

    const late = await sendActivation(prepared, staleAttempt);
    expect(late.status).toBe(409);
    expect(late.json['error']).toEqual({ code: 'CHALLENGE_EXPIRED_OR_REPLAYED' });
    await oldServer.stop();
    const attempts = await db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', prepared.operationId).orderBy('attempt_no').execute();
    expect(attempts.map(({ attempt_no, outcome }) => [attempt_no, outcome])).toEqual([
      [1, 'retryable_reject'], [2, 'accepted'],
    ]);
    expect((await db.selectFrom('licenses').selectAll().where('id', '=', prepared.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');
    expect((await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow()).consumed_at).toBeInstanceOf(Date);
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

  it('drops the PostgreSQL COMMIT acknowledgement and recovers the durable result by the same operation', async () => {
    const prepared = await prepareActivation();
    const proxy = new CommitAckDropProxy();
    const database = new URL(runtime.config.databaseUrl);
    await proxy.start(database.hostname, Number(database.port || '5432'));
    const proxyUrl = new URL(runtime.config.databaseUrl);
    proxyUrl.port = String(proxy.port);
    proxyUrl.searchParams.set('sslmode', 'disable');
    const proxyDb = createDatabase(proxyUrl.toString(), 4);
    const proxyServer = await startAppServer(createApp({ config: runtime.config, db: proxyDb }));
    try {
      const attempt = await activationAttempt(prepared, 1, 'activation', proxyServer);
      const commitDropped = proxy.armNextCommitAckDrop();
      const responsePromise = signPost({
        port: proxyServer.port, origin: runtime.config.publicOrigin, path: '/v1/activations', body: attempt.body,
        identity: prepared.identity, nonce: attempt.serverNonce,
      });
      await commitDropped;
      const lostResponse = await responsePromise;
      expect(lostResponse.status).toBe(500);
      const durable = await db.selectFrom('license_operations').selectAll().where('operation_id', '=', prepared.operationId).executeTakeFirstOrThrow();
      expect(durable.state).toBe('committed');
      expect(durable.response_type).toBe('license');
      await proxyServer.stop();
      await proxyDb.destroy();

      const continued = await sendContinue(prepared, 2);
      expect(continued.status).toBe(200);
      const receipt = await verifyCenterJwt(continued.json['operation_receipt'] as string, runtime);
      expect(receipt.payload['state']).toBe('committed');
      expect(receipt.payload['result_jws']).toBe(durable.response_jws);
      expect((await db.selectFrom('licenses').selectAll().where('id', '=', prepared.licenseId).executeTakeFirstOrThrow()).current_generation).toBe('1');
      expect((await db.selectFrom('activation_codes').selectAll().where('token_hash', '=', prepared.tokenHash).executeTakeFirstOrThrow()).consumed_at).toBeInstanceOf(Date);
    } finally {
      await proxyServer.stop().catch(() => undefined);
      await proxyDb.destroy().catch(() => undefined);
      await proxy.stop();
    }
  });

  it('rolls back a blocked activation when the process is killed and resumes after restart', async () => {
    const prepared = await prepareActivation();
    const secretDir = await mkdtemp(join(tmpdir(), 'aikayun-license-process-'));
    const keyFile = join(secretDir, 'license-signing-key.pem');
    await writeFile(keyFile, runtime.privatePem, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    let child: Awaited<ReturnType<typeof startChildLicenseServer>> | undefined;
    let restarted: Awaited<ReturnType<typeof startChildLicenseServer>> | undefined;
    const blocker = await holdLicenseRow(db, prepared.licenseId);
    try {
      child = await startChildLicenseServer({
        databaseUrl: runtime.config.databaseUrl, issuer: runtime.config.issuer,
        publicOrigin: runtime.config.publicOrigin, keyFile,
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
        publicOrigin: runtime.config.publicOrigin, keyFile,
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
      await rm(secretDir, { recursive: true, force: true });
    }
  });
});

async function prepareActivationWithExisting(
  licenseId: string,
  code: string,
  tokenHash: string,
  identity: TestIdentity,
): Promise<PreparedActivation> {
  const instanceId = randomUUID();
  const databaseId = randomUUID();
  const operationId = randomUUID();
  const origin = 'https://shop.example.test';
  const intentDigest = activationIntentDigest({
    licenseId, activationCode: code, instanceId, databaseId, identityJkt: identity.jkt, origin,
  });
  return { licenseId, code, tokenHash, identity, instanceId, databaseId, operationId, origin, intentDigest };
}
