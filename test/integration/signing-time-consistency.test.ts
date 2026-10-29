import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { sql, type Kysely } from 'kysely';
import { describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import {
  acceptSignerTrustBundleRequestDigest, initializeSignerRequestDigest, rotateSignerRequestDigest,
} from '../../src/admin/signing-service.js';
import { lockSigningAuthorityForSigning, lockSigningAuthorityForUpdate, loadTrustedSigningContext } from '../../src/crypto/signing-authority.js';
import { verifyTypedJwt } from '../../src/crypto/jwt.js';
import { activationIntentDigest } from '../../src/intent.js';
import { verifyLicenseLease } from '../../src/receipts.js';
import { createDatabase, migrateToLatest } from '../../src/db/database.js';
import type { Database } from '../../src/db/types.js';
import { createActivationCode, createLicense } from '../fixtures.js';
import { buildChallengeBoundBody, signPost, startAppServer, type HttpResponse, type RunningTestServer } from '../support/http.js';
import { createIdentity, createTestSigningRuntime, type TestIdentity, type TestSigningRuntime } from '../support/runtime.js';
import { waitForAdvisoryLockWaiterPids, waitForLicenseRowWaiterPids } from '../support/pg-waits.js';

type TestSystem = { runtime: TestSigningRuntime; db: Kysely<Database>; server: RunningTestServer };

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

async function waitForDbSecond(db: Kysely<Database>, predicate: (seconds: number) => boolean): Promise<number> {
  const deadline = Date.now() + 35_000;
  while (Date.now() < deadline) {
    const result = await sql<{ seconds: string }>`SELECT floor(extract(epoch from clock_timestamp()))::bigint::text AS seconds`.execute(db);
    const seconds = Number(result.rows[0]!.seconds);
    if (predicate(seconds)) return seconds;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for PostgreSQL trusted time boundary');
}

async function boot(retireAfter?: number): Promise<TestSystem & { record: TestSigningRuntime['onlineKey']['record'] }> {
  const runtime = await createTestSigningRuntime();
  const db = createDatabase(runtime.config.databaseUrl, 16);
  await migrateToLatest(db);
  const record = retireAfter === undefined ? runtime.onlineKey.record : {
    ...runtime.onlineKey.record,
    retire_after: retireAfter,
    verify_until: retireAfter + 7 * 24 * 60 * 60 + 60,
  };
  const bundleJws = await runtime.createBundle('1', [record]);
  const service = runtime.createAdminService(db);
  const initial = {
    operationId: randomUUID(), expectedSignerRevision: '0', activeKid: runtime.onlineKey.kid,
    bundleJws, reason: 'initialize isolated R1 signing-time test',
  };
  await service.initialize({
    ...initial,
    rolloutGate: 'isolated-development-confirmed',
    confirmedRequestDigest: initializeSignerRequestDigest(initial),
  });
  const server = await startAppServer(createApp({ config: runtime.config, db }));
  return { runtime, db, server, record };
}

async function dispose(system: TestSystem): Promise<void> {
  await system.server.stop();
  await system.db.destroy();
  await system.runtime.cleanup();
}

async function createChallenge(system: TestSystem, input: {
  identity: TestIdentity; operation: 'activation' | 'query'; operationId: string; intentDigest: string; instanceId: string;
}): Promise<string> {
  const clientNonce = randomBytes(32).toString('base64url');
  const response = await signPost({
    port: system.server.port, origin: system.runtime.config.publicOrigin, path: '/v1/challenges',
    body: {
      operation: input.operation, operation_id: input.operationId, intent_digest: input.intentDigest,
      instance_id: input.instanceId, public_jwk: input.identity.publicJwk, client_nonce: clientNonce,
    },
    identity: input.identity, nonce: clientNonce,
  });
  expect(response.status, JSON.stringify(response.json)).toBe(201);
  return response.json['challenge'] as string;
}

async function sendActivation(system: TestSystem, input: {
  identity: TestIdentity; licenseId: string; activationCode: string; databaseId: string; instanceId: string;
  operationId: string; intentDigest: string; origin: string; challenge: string;
}): Promise<HttpResponse> {
  const serverNonce = decodeJwt(input.challenge)['server_nonce'] as string;
  const body = {
    ...buildChallengeBoundBody({
      challenge: input.challenge, operationId: input.operationId, intentDigest: input.intentDigest,
      attemptNo: 1, instanceId: input.instanceId, identity: input.identity,
      licenseId: input.licenseId, databaseId: input.databaseId,
    }),
    activation_code: input.activationCode,
    origin: input.origin,
  };
  return signPost({
    port: system.server.port, origin: system.runtime.config.publicOrigin, path: '/v1/activations',
    body, identity: input.identity, nonce: serverNonce,
  });
}

async function prepareActivation(system: TestSystem) {
  const license = await createLicense(system.db);
  const code = await createActivationCode(system.db, license.id);
  const identity = await createIdentity();
  const instanceId = randomUUID();
  const databaseId = randomUUID();
  const operationId = randomUUID();
  const origin = 'https://shop.example.test';
  const intentDigest = activationIntentDigest({
    licenseId: license.id, activationCode: code.code, instanceId, databaseId,
    identityJkt: identity.jkt, origin,
  });
  const challenge = await createChallenge(system, { identity, operation: 'activation', operationId, intentDigest, instanceId });
  return { license, code, identity, instanceId, databaseId, operationId, origin, intentDigest, challenge };
}

async function dbSecond(db: Kysely<Database>): Promise<number> {
  const result = await sql<{ seconds: string }>`SELECT floor(extract(epoch from clock_timestamp()))::bigint::text AS seconds`.execute(db);
  return Number(result.rows[0]!.seconds);
}

describe('signing time and key-lifecycle consistency', () => {
  it('blocks A signing after a license-row wait crosses retire_after, then allows B and preserves A history', async () => {
    const retirement = Math.floor(Date.now() / 1000) + 25;
    const system = await boot(retirement);
    const { runtime, db } = system;
    try {
      const keyB = await runtime.createOnlineKey();
      const bundle2 = await runtime.createBundle('2', [system.record, keyB.record]);
      const accept = { operationId: randomUUID(), expectedSignerRevision: '1', bundleJws: bundle2, reason: 'prepublish isolated B key' };
      const accepted = await runtime.createAdminService(db).acceptTrustBundle({
        ...accept, rolloutGate: 'isolated-development-confirmed',
        confirmedRequestDigest: acceptSignerTrustBundleRequestDigest(accept),
      });
      (runtime.config.signingKeyring as Map<string, typeof keyB>).set(keyB.kid, keyB);

      const validA = await prepareActivation(system);
      const validAResponse = await sendActivation(system, {
        identity: validA.identity, licenseId: validA.license.id, activationCode: validA.code.code,
        databaseId: validA.databaseId, instanceId: validA.instanceId, operationId: validA.operationId,
        intentDigest: validA.intentDigest, origin: validA.origin, challenge: validA.challenge,
      });
      expect(validAResponse.status, JSON.stringify(validAResponse.json)).toBe(200);
      const validALease = validAResponse.json['license'] as string;
      expect(decodeProtectedHeader(validALease)['kid']).toBe(runtime.onlineKey.kid);

      await expect(db.transaction().execute((trx) => lockSigningAuthorityForSigning(
        trx, runtime.config, new Date(retirement * 1000),
      ))).rejects.toMatchObject({ code: 'ACTIVE_SIGNING_KEY_OUTSIDE_LIFECYCLE' });

      const blocked = await prepareActivation(system);
      const lockAcquired = deferred<void>();
      const release = deferred<void>();
      const heldLicense = db.transaction().execute(async (trx) => {
        await trx.selectFrom('licenses').select('id').where('id', '=', blocked.license.id)
          .forUpdate().executeTakeFirstOrThrow();
        lockAcquired.resolve();
        await release.promise;
      });
      await lockAcquired.promise;
      const operationResponse = sendActivation(system, {
        identity: blocked.identity, licenseId: blocked.license.id, activationCode: blocked.code.code,
        databaseId: blocked.databaseId, instanceId: blocked.instanceId, operationId: blocked.operationId,
        intentDigest: blocked.intentDigest, origin: blocked.origin, challenge: blocked.challenge,
      });
      const [waiterPid] = await waitForLicenseRowWaiterPids(db, 1);
      const sharedLock = await sql<{ mode: string }>`
        SELECT mode FROM pg_locks WHERE pid = ${waiterPid} AND locktype = 'advisory'
          AND mode = 'ShareLock' AND granted
      `.execute(db);
      expect(sharedLock.rows.length).toBeGreaterThan(0);
      expect(await dbSecond(db)).toBeLessThan(retirement);
      const actualTime = await waitForDbSecond(db, (seconds) => seconds > retirement);
      release.resolve();
      await heldLicense;
      const response = await operationResponse;
      expect(response.status, JSON.stringify(response.json)).toBe(503);
      expect(response.json['error']).toEqual({ code: 'ACTIVE_SIGNING_KEY_OUTSIDE_LIFECYCLE' });

      const [operation, code, license, activationRows, attempts, auditEvents, nonceRow] = await Promise.all([
        db.selectFrom('license_operations').selectAll().where('operation_id', '=', blocked.operationId).executeTakeFirst(),
        db.selectFrom('activation_codes').selectAll().where('token_hash', '=', blocked.code.tokenHash).executeTakeFirstOrThrow(),
        db.selectFrom('licenses').selectAll().where('id', '=', blocked.license.id).executeTakeFirstOrThrow(),
        db.selectFrom('license_activations').selectAll().where('license_id', '=', blocked.license.id).execute(),
        db.selectFrom('license_operation_attempts').selectAll().where('operation_id', '=', blocked.operationId).execute(),
        db.selectFrom('license_audit_events').selectAll().where('operation_id', '=', blocked.operationId).execute(),
        db.selectFrom('request_nonces').selectAll().where('nonce_hash', '=', createHash('sha256')
          .update(String(decodeJwt(blocked.challenge)['server_nonce'])).digest('base64url')).executeTakeFirstOrThrow(),
      ]);
      expect(operation).toBeUndefined();
      expect(code.consumed_at).toBeNull();
      expect(license.current_generation).toBe('0');
      expect(activationRows).toHaveLength(0);
      expect(attempts).toHaveLength(0);
      expect(auditEvents).toHaveLength(0);
      expect(nonceRow.consumed_at).toBeNull();
      const afterA = await loadTrustedSigningContext(db, runtime.config);
      await expect(verifyLicenseLease(validALease, afterA.context, new Date(actualTime * 1000))).resolves.toMatchObject({
        sub: validA.license.id,
        activation_generation: '1',
      });

      const state = await runtime.createAdminService(db).getState();
      const rotate = {
        operationId: randomUUID(), expectedSignerRevision: state.signerRevision, targetKid: keyB.kid,
        bundleVersion: accepted.bundleVersion!, artifactSha256: accepted.artifactSha256!,
        reason: 'activate isolated B after A retirement boundary',
      };
      const rotated = await runtime.createAdminService(db).rotate({
        ...rotate, rolloutGate: 'isolated-development-confirmed',
        confirmedRequestDigest: rotateSignerRequestDigest(rotate),
      });
      expect(rotated).toMatchObject({ state: 'succeeded', activeSigningKid: keyB.kid, signerRevision: '2' });

      const validB = await prepareActivation(system);
      const validBResponse = await sendActivation(system, {
        identity: validB.identity, licenseId: validB.license.id, activationCode: validB.code.code,
        databaseId: validB.databaseId, instanceId: validB.instanceId, operationId: validB.operationId,
        intentDigest: validB.intentDigest, origin: validB.origin, challenge: validB.challenge,
      });
      expect(validBResponse.status, JSON.stringify(validBResponse.json)).toBe(200);
      const validBLease = validBResponse.json['license'] as string;
      expect(decodeProtectedHeader(validBLease)['kid']).toBe(keyB.kid);
      const afterB = await loadTrustedSigningContext(db, runtime.config);
      await expect(verifyLicenseLease(validBLease, afterB.context, new Date(afterB.context.trustedTime * 1000)))
        .resolves.toMatchObject({ sub: validB.license.id, activation_generation: '1' });
    } finally {
      await dispose(system);
    }
  }, 90_000);

  it('rejects a challenge when its signed HTTP request expires while queued on the signer lock', async () => {
    const system = await boot();
    const staleChallengeClock = async () => new Date(Date.now() - 10 * 60 * 1000);
    const server = await startAppServer(createApp({ config: system.runtime.config, db: system.db, challengeNow: staleChallengeClock }));
    try {
      const identity = await createIdentity();
      const operationId = randomUUID();
      const intentDigest = randomBytes(32).toString('base64url');
      const instanceId = randomUUID();
      const clientNonce = randomBytes(32).toString('base64url');
      const signedAt = await dbSecond(system.db) - 30;
      const release = deferred<void>();
      const lockAcquired = deferred<void>();
      const heldSigner = system.db.transaction().execute(async (trx) => {
        await lockSigningAuthorityForUpdate(trx);
        lockAcquired.resolve();
        await release.promise;
      });
      await lockAcquired.promise;
      const responsePromise = signPost({
        port: server.port, origin: system.runtime.config.publicOrigin, path: '/v1/challenges',
        body: {
          operation: 'query', operation_id: operationId, intent_digest: intentDigest,
          instance_id: instanceId, public_jwk: identity.publicJwk, client_nonce: clientNonce,
        },
        identity, nonce: clientNonce, created: signedAt,
      });
      const [waiterPid] = await waitForAdvisoryLockWaiterPids(system.db, 1);
      const queuedSharedLock = await sql<{ granted: boolean }>`
        SELECT granted FROM pg_locks WHERE pid = ${waiterPid} AND locktype = 'advisory' AND mode = 'ShareLock'
      `.execute(system.db);
      expect(queuedSharedLock.rows).toEqual([{ granted: false }]);
      const actualTime = await waitForDbSecond(system.db, (seconds) => seconds > signedAt + 60);
      release.resolve();
      await heldSigner;
      const response = await responsePromise;
      expect(response.status, JSON.stringify(response.json)).toBe(401);
      expect(response.json['error']).toEqual({ code: 'HTTP_SIGNATURE_INVALID' });
      expect(await system.db.selectFrom('request_nonces').selectAll()
        .where('operation_id', '=', operationId).execute()).toHaveLength(0);
      expect(await system.db.selectFrom('license_operations').selectAll()
        .where('operation_id', '=', operationId).execute()).toHaveLength(0);
      expect(actualTime).toBeGreaterThan(signedAt + 60);
    } finally {
      await server.stop();
      await dispose(system);
    }
  }, 90_000);

  it('issues a challenge from PostgreSQL time after a short signer-lock wait', async () => {
    const system = await boot();
    try {
      expect(() => createApp({
        config: { ...system.runtime.config, nodeEnv: 'production' }, db: system.db,
        challengeNow: async () => new Date(0),
      })).toThrow('Injected time sources are disabled in production');
      const identity = await createIdentity();
      const operationId = randomUUID();
      const intentDigest = randomBytes(32).toString('base64url');
      const instanceId = randomUUID();
      const clientNonce = randomBytes(32).toString('base64url');
      const release = deferred<void>();
      const lockAcquired = deferred<void>();
      const heldSigner = system.db.transaction().execute(async (trx) => {
        await lockSigningAuthorityForUpdate(trx);
        lockAcquired.resolve();
        await release.promise;
      });
      await lockAcquired.promise;
      const responsePromise = signPost({
        port: system.server.port, origin: system.runtime.config.publicOrigin, path: '/v1/challenges',
        body: {
          operation: 'query', operation_id: operationId, intent_digest: intentDigest,
          instance_id: instanceId, public_jwk: identity.publicJwk, client_nonce: clientNonce,
        },
        identity, nonce: clientNonce,
      });
      const [waiterPid] = await waitForAdvisoryLockWaiterPids(system.db, 1);
      const queuedSharedLock = await sql<{ granted: boolean }>`
        SELECT granted FROM pg_locks WHERE pid = ${waiterPid} AND locktype = 'advisory' AND mode = 'ShareLock'
      `.execute(system.db);
      expect(queuedSharedLock.rows).toEqual([{ granted: false }]);
      const beforeRelease = await dbSecond(system.db);
      await waitForDbSecond(system.db, (seconds) => seconds >= beforeRelease + 2);
      const releaseTime = await dbSecond(system.db);
      release.resolve();
      await heldSigner;
      const response = await responsePromise;
      expect(response.status, JSON.stringify(response.json)).toBe(201);
      const token = response.json['challenge'] as string;
      const claims = decodeJwt(token);
      expect(Number(claims['iat'])).toBeGreaterThanOrEqual(releaseTime);
      const serverNonce = String(claims['server_nonce']);
      const nonceRow = await system.db.selectFrom('request_nonces').selectAll()
        .where('nonce_hash', '=', createHash('sha256').update(serverNonce).digest('base64url'))
        .executeTakeFirstOrThrow();
      expect(Math.floor(nonceRow.created_at.getTime() / 1000)).toBe(claims['iat']);
      expect(Math.floor(nonceRow.expires_at.getTime() / 1000)).toBe(claims['exp']);
      const current = await loadTrustedSigningContext(system.db, system.runtime.config);
      await expect(verifyTypedJwt(token, {
        ...current.context, typ: 'aikayun-license-challenge+jwt', audience: 'aikayun-commerce',
        now: new Date(current.context.trustedTime * 1000), requiredClaims: Object.keys(claims),
      })).resolves.toMatchObject({ header: { kid: system.runtime.onlineKey.kid } });
    } finally {
      await dispose(system);
    }
  }, 90_000);
});
