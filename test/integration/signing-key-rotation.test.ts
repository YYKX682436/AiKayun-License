import { randomBytes, randomUUID } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { exportJWK, generateKeyPair } from 'jose';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import type { Kysely } from 'kysely';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import {
  acceptSignerTrustBundleRequestDigest,
  rotateSignerRequestDigest,
} from '../../src/admin/signing-service.js';
import { loadTrustedSigningContext } from '../../src/crypto/signing-authority.js';
import { lockSigningAuthorityForSigning } from '../../src/crypto/signing-authority.js';
import { verifyTypedJwt } from '../../src/crypto/jwt.js';
import { signTimeAnchor, verifyTimeAnchorWithTrustBundleCandidate } from '../../src/crypto/time-reset.js';
import { activationIntentDigest } from '../../src/intent.js';
import {
  signDisasterTransferResult,
  signLicenseLease,
  signTransferReceipt,
  verifyDisasterTransferReceipt,
  verifyLicenseLease,
  verifyTransferReceipt,
} from '../../src/receipts.js';
import { createDatabase, migrateToLatest } from '../../src/db/database.js';
import type { Database } from '../../src/db/types.js';
import { createActivationCode, createLicense } from '../fixtures.js';
import { buildTrustBundleClaims, signTrustBundle } from '../../tools/offline-trust/trust-bundle-signing.js';
import {
  buildChallengeBoundBody, requestChallenge, signPost, startAppServer, type RunningTestServer,
} from '../support/http.js';
import { createIdentity, createTestSigningRuntime, type TestSigningRuntime } from '../support/runtime.js';
import { waitForAdvisoryLockWaiters } from '../support/pg-waits.js';
import { startChildLicenseServer } from '../support/child-server.js';

const digest = () => randomBytes(32).toString('base64url');

async function postJson(port: number, path: string, value: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
  const body = Buffer.from(JSON.stringify(value));
  return new Promise((resolve, reject) => {
    const request = httpsRequest({
      host: '127.0.0.1', port, path, method: 'POST', rejectUnauthorized: false,
      headers: { host: 'license.example.test', 'content-type': 'application/json', 'content-length': String(body.byteLength), connection: 'close' },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      response.on('end', () => {
        let json: Record<string, unknown> = {};
        try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>; } catch { /* response details are asserted by callers */ }
        resolve({ status: response.statusCode ?? 0, json });
      });
    });
    request.on('error', reject);
    request.end(body);
  });
}

function serverNonce(token: string): string {
  const value = decodeJwt(token)['server_nonce'];
  if (typeof value !== 'string') throw new Error('Challenge server nonce missing');
  return value;
}

describe('database-authoritative Ed25519 signing rotation', () => {
  let db: Kysely<Database>;
  let runtimeA: TestSigningRuntime;
  let runtimeB: TestSigningRuntime;
  let serverA: RunningTestServer;
  let serverB: RunningTestServer;

  beforeAll(async () => {
    runtimeA = await createTestSigningRuntime();
    runtimeB = await createTestSigningRuntime({ databaseUrl: runtimeA.config.databaseUrl, trustFrom: runtimeA });
    db = createDatabase(runtimeA.config.databaseUrl, 16);
    await migrateToLatest(db);
    await runtimeA.initializeAuthority(db);
    serverA = await startAppServer(createApp({ config: runtimeA.config, db }));
    serverB = await startAppServer(createApp({ config: runtimeB.config, db }));
  });

  afterAll(async () => {
    await serverA?.stop();
    await serverB?.stop();
    await db?.destroy();
    await runtimeB?.cleanup();
    await runtimeA?.cleanup();
  });

  it('keeps one active identity across two processes and accepts an A challenge after B takes over', async () => {
    const identity = await createIdentity();
    const license = await createLicense(db);
    const code = await createActivationCode(db, license.id);
    const instanceId = randomUUID();
    const databaseId = randomUUID();
    const activationOperationId = randomUUID();
    const origin = 'https://shop.example.test';
    const activationDigest = activationIntentDigest({
      licenseId: license.id, activationCode: code.code, instanceId, databaseId,
      identityJkt: identity.jkt, origin,
    });
    const activationChallenge = await requestChallenge({
      port: serverA.port, config: runtimeA.config, identity, operation: 'activation',
      operationId: activationOperationId, intentDigest: activationDigest, instanceId,
    });
    const activationBody = {
      ...buildChallengeBoundBody({
        challenge: activationChallenge.token, operationId: activationOperationId, intentDigest: activationDigest,
        attemptNo: 1, instanceId, identity, licenseId: license.id, databaseId,
      }),
      activation_code: code.code,
      origin,
    };
    const activationResponse = await signPost({
      port: serverA.port, origin: runtimeA.config.publicOrigin, path: '/v1/activations',
      body: activationBody, identity, nonce: serverNonce(activationChallenge.token),
    });
    expect(activationResponse.status).toBe(200);
    const originalLease = activationResponse.json['license'] as string;
    const originalOperation = await db.selectFrom('license_operations').selectAll()
      .where('operation_id', '=', activationOperationId).executeTakeFirstOrThrow();
    expect(originalOperation.response_jws).toBe(originalLease);
    expect(decodeProtectedHeader(originalLease)['kid']).toBe(runtimeA.onlineKey.kid);

    const beforeRotationTrust = await loadTrustedSigningContext(db, runtimeA.config);
    const beforeRotationContext = beforeRotationTrust.context;
    const beforeRotationNow = new Date(beforeRotationContext.trustedTime * 1000);
    const historicalAnchorNonce = digest();
    const historicalTimeAnchorA = await signTimeAnchor(runtimeA.signer, historicalAnchorNonce, beforeRotationNow);
    const historyLicense = await db.selectFrom('licenses').selectAll().where('id', '=', license.id).executeTakeFirstOrThrow();
    const historyTarget = await createIdentity();
    const historyTargetInstanceId = randomUUID();
    const historySubscriptionEnd = new Date(beforeRotationNow.getTime() + 60 * 24 * 60 * 60 * 1000);
    const historyNonce = digest();
    const historyRequestDigest = digest();
    const historicalLeaseA = await signLicenseLease(runtimeA.signer, {
      licenseId: license.id, instanceId: historyTargetInstanceId, databaseId, identityJkt: historyTarget.jkt,
      generation: '2', entitlementRevision: historyLicense.entitlement_revision, plan: 'monthly',
      subscriptionEnd: historySubscriptionEnd, requestNonce: historyNonce, requestDigest: historyRequestDigest,
      now: beforeRotationNow,
    });
    const historicalTransferReceiptA = await signTransferReceipt(runtimeA.signer, {
      licenseId: license.id, databaseId, sourceInstanceId: instanceId, sourceIdentityJkt: identity.jkt,
      sourceGeneration: '1', targetInstanceId: historyTargetInstanceId, targetIdentityJkt: historyTarget.jkt,
      targetGeneration: '2', expectedBindingRevision: '0', expectedRevision: '1', resultRevision: '2',
      entitlementRevision: historyLicense.entitlement_revision, operationId: randomUUID(), intentDigest: digest(),
      requestNonce: historyNonce, requestDigest: historyRequestDigest, newLease: historicalLeaseA.token,
      subscriptionEnd: historySubscriptionEnd, now: beforeRotationNow,
    });
    const historicalDisasterReceiptA = await signDisasterTransferResult(runtimeA.signer, {
      mode: 'active_lease', licenseId: license.id, databaseId, accountReference: historyLicense.account_id,
      sourceActivationId: randomUUID(), sourceInstanceId: instanceId, sourceIdentityJkt: identity.jkt,
      sourceGeneration: '1', targetInstanceId: historyTargetInstanceId, targetIdentityJkt: historyTarget.jkt,
      targetGeneration: '2', expectedBindingRevision: '0', expectedRevision: '1', resultRevision: '2',
      entitlementRevision: historyLicense.entitlement_revision, operationId: randomUUID(), intentDigest: digest(),
      requestNonce: historyNonce, requestDigest: historyRequestDigest, subscriptionEnd: historySubscriptionEnd,
      licenseStatus: 'active', lease: historicalLeaseA.token, now: beforeRotationNow,
    });

    const queryOperationId = activationOperationId;
    const queryIntentDigest = activationDigest;
    const challengeA = await requestChallenge({
      port: serverA.port, config: runtimeA.config, identity, operation: 'query',
      operationId: queryOperationId, intentDigest: queryIntentDigest, instanceId,
    });
    const unreadyClientNonce = digest();
    const unreadyB = await signPost({
      port: serverB.port, origin: runtimeB.config.publicOrigin, path: '/v1/challenges',
      body: {
        operation: 'query', operation_id: randomUUID(), intent_digest: digest(), instance_id: instanceId,
        public_jwk: identity.publicJwk, client_nonce: unreadyClientNonce,
      },
      identity, nonce: unreadyClientNonce,
    });
    expect(unreadyB.status).toBe(503);

    const authorityService = runtimeA.createAdminService(db);
    const targetB = runtimeB.onlineKey;
    const afterARetirement = new Date((runtimeA.onlineKey.record.retire_after! + 1) * 1000);
    await expect(db.transaction().execute((trx) => lockSigningAuthorityForSigning(trx, runtimeA.config, afterARetirement)))
      .rejects.toMatchObject({ code: 'ACTIVE_SIGNING_KEY_OUTSIDE_LIFECYCLE' });
    const unpublishedRotate = {
      operationId: randomUUID(), expectedSignerRevision: '1', targetKid: targetB.kid,
      bundleVersion: '1', artifactSha256: (await authorityService.getState()).artifactSha256!,
      reason: 'attempt untrusted target activation',
    };
    let rejectedRotationError: unknown;
    try {
      await authorityService.rotate({
      ...unpublishedRotate,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: rotateSignerRequestDigest(unpublishedRotate),
      });
    } catch (error) {
      rejectedRotationError = error;
    }
    expect(rejectedRotationError).toMatchObject({ code: 'SIGNER_TARGET_KEY_NOT_TRUSTED' });
    const rejectedRotation = await db.selectFrom('license_signer_operations').selectAll()
      .where('operation_id', '=', unpublishedRotate.operationId).executeTakeFirstOrThrow();
    expect(rejectedRotation).toMatchObject({
      state: 'rejected', action: 'key_rotate', expected_signer_revision: '1',
      target_signing_kid: targetB.kid,
    });
    const rejectedAudit = await db.selectFrom('license_signer_audit_events').selectAll()
      .where('operation_id', '=', unpublishedRotate.operationId).executeTakeFirstOrThrow();
    expect(rejectedAudit).toMatchObject({ state: 'rejected', reason: unpublishedRotate.reason });
    expect(await authorityService.rotate({
      ...unpublishedRotate,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: rotateSignerRequestDigest(unpublishedRotate),
    })).toMatchObject({ replayed: true, state: 'rejected', signerRevision: '1' });
    expect((await authorityService.getState()).signerRevision).toBe('1');

    const stagedTargetB = {
      ...targetB,
      record: { ...targetB.record, not_before: Math.floor(Date.now() / 1000) + 3 },
    };
    const otherRoot = await generateKeyPair('Ed25519', { extractable: true });
    const otherRootExport = await exportJWK(otherRoot.publicKey);
    const otherRootJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: otherRootExport.x! };
    const wrongRootNow = Math.floor(Date.now() / 1000) - 20;
    const wrongRootClaims = await buildTrustBundleClaims(runtimeA.config.issuer, {
      bundle_version: '2', iat: wrongRootNow, nbf: wrongRootNow + 10, exp: wrongRootNow + 60 * 24 * 60 * 60,
      propagation_budget_seconds: 60, keys: [runtimeA.onlineKey.record, stagedTargetB.record],
    }, otherRootJwk);
    const wrongRootBundle = await signTrustBundle(wrongRootClaims, otherRoot.privateKey, otherRootJwk);
    const wrongRootRequest = {
      operationId: randomUUID(), expectedSignerRevision: '1', bundleJws: wrongRootBundle.token,
      reason: 'reject bundle signed by an untrusted offline root',
    };
    await expect(authorityService.acceptTrustBundle({
      ...wrongRootRequest,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: acceptSignerTrustBundleRequestDigest(wrongRootRequest),
    })).rejects.toMatchObject({ code: 'SIGNER_BUNDLE_SIGNATURE_INVALID' });
    expect(await db.selectFrom('license_signer_authority').selectAll()
      .where('singleton', '=', true).executeTakeFirstOrThrow()).toMatchObject({ signer_revision: '1', bundle_version: '1' });
    const bundleJws = await runtimeA.createBundle('2', [runtimeA.onlineKey.record, stagedTargetB.record]);
    const accept = {
      operationId: randomUUID(), expectedSignerRevision: '1', bundleJws,
      reason: 'prepublish B in an isolated trust bundle',
    };
    const accepted = await authorityService.acceptTrustBundle({
      ...accept,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: acceptSignerTrustBundleRequestDigest(accept),
    });
    expect(accepted.signerRevision).toBe('1');
    (runtimeA.config.signingKeyring as Map<string, typeof targetB>).set(stagedTargetB.kid, stagedTargetB);
    const notYetValid = {
      operationId: randomUUID(), expectedSignerRevision: '1', targetKid: targetB.kid,
      bundleVersion: '2', artifactSha256: accepted.artifactSha256!, reason: 'reject B before its scheduled activation time',
    };
    await expect(authorityService.rotate({
      ...notYetValid,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: rotateSignerRequestDigest(notYetValid),
    })).rejects.toMatchObject({ code: 'SIGNER_TARGET_KEY_OUTSIDE_LIFECYCLE' });
    const wrongDigest = {
      operationId: randomUUID(), expectedSignerRevision: '1', targetKid: targetB.kid,
      bundleVersion: '2', artifactSha256: 'A'.repeat(43), reason: 'reject a mismatched bundle artifact digest',
    };
    await expect(authorityService.rotate({
      ...wrongDigest,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: rotateSignerRequestDigest(wrongDigest),
    })).rejects.toMatchObject({ code: 'SIGNER_BUNDLE_REFERENCE_MISMATCH' });
    const wrongDigestAudit = await db.selectFrom('license_signer_operations').selectAll()
      .where('operation_id', '=', wrongDigest.operationId).executeTakeFirstOrThrow();
    expect(wrongDigestAudit).toMatchObject({ state: 'rejected', artifact_sha256: 'A'.repeat(43) });

    const notBeforeDelay = stagedTargetB.record.not_before * 1000 - Date.now() + 100;
    if (notBeforeDelay > 0) await new Promise((resolve) => setTimeout(resolve, notBeforeDelay));
    const wrongMaterial = { ...runtimeA.onlineKey, kid: targetB.kid };
    (runtimeA.config.signingKeyring as Map<string, typeof targetB>).set(targetB.kid, wrongMaterial);
    const wrongPrivateKey = {
      operationId: randomUUID(), expectedSignerRevision: '1', targetKid: targetB.kid,
      bundleVersion: '2', artifactSha256: accepted.artifactSha256!, reason: 'reject a mismatched B private key',
    };
    await expect(authorityService.rotate({
      ...wrongPrivateKey,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: rotateSignerRequestDigest(wrongPrivateKey),
    })).rejects.toMatchObject({ code: 'SIGNER_TARGET_PRIVATE_KEY_MISMATCH' });
    (runtimeA.config.signingKeyring as Map<string, typeof targetB>).set(targetB.kid, stagedTargetB);
    const state = await authorityService.getState();
    const rotate = {
      operationId: randomUUID(), expectedSignerRevision: state.signerRevision, targetKid: targetB.kid,
      bundleVersion: state.bundleVersion!, artifactSha256: state.artifactSha256!,
      reason: 'controlled A to B signer rotation',
    };
    const rotateRequest = {
      ...rotate,
      rolloutGate: 'isolated-development-confirmed' as const,
      confirmedRequestDigest: rotateSignerRequestDigest(rotate),
    };
    let releaseSharedLock!: () => void;
    let sharedLockAcquired!: () => void;
    const releaseGate = new Promise<void>((resolve) => { releaseSharedLock = resolve; });
    const acquiredGate = new Promise<void>((resolve) => { sharedLockAcquired = resolve; });
    const earlierSigningTransaction = db.transaction().execute(async (trx) => {
      await lockSigningAuthorityForSigning(trx, runtimeA.config);
      sharedLockAcquired();
      await releaseGate;
    });
    await acquiredGate;

    const rotationInQueue = authorityService.rotate(rotateRequest);
    await waitForAdvisoryLockWaiters(db, 1);
    const challengeIssuedBySecondProcess = requestChallenge({
      port: serverB.port, config: runtimeB.config, identity, operation: 'query',
      operationId: randomUUID(), intentDigest: digest(), instanceId,
    });
    await waitForAdvisoryLockWaiters(db, 2);
    expect((await authorityService.getState()).activeKid).toBe(runtimeA.onlineKey.kid);
    releaseSharedLock();
    await earlierSigningTransaction;
    const rotated = await rotationInQueue;
    const queuedChallenge = await challengeIssuedBySecondProcess;
    expect(decodeProtectedHeader(queuedChallenge.token)['kid']).toBe(targetB.kid);
    expect(rotated).toMatchObject({ activeSigningKid: targetB.kid, signerRevision: '2', state: 'succeeded' });
    const replay = await authorityService.rotate(rotateRequest);
    expect(replay).toMatchObject({ replayed: true, activeSigningKid: targetB.kid, signerRevision: '2' });
    expect((await authorityService.getState()).signerRevision).toBe('2');

    const authority = await db.selectFrom('license_signer_authority').selectAll().where('singleton', '=', true).executeTakeFirstOrThrow();
    expect(authority.active_signing_kid).toBe(targetB.kid);
    expect(authority.previous_signing_kid).toBe(runtimeA.onlineKey.kid);
    await expect(db.updateTable('license_signer_authority').set({
      active_signing_kid: runtimeA.onlineKey.kid,
      signer_revision: '3',
      previous_signing_kid: targetB.kid,
    }).where('singleton', '=', true).execute()).rejects.toThrow('active signer changes require a matching successful signer operation');
    expect((await authorityService.getState()).activeKid).toBe(targetB.kid);
    const { context } = await loadTrustedSigningContext(db, runtimeA.config);
    const verificationNow = new Date(context.trustedTime * 1000);
    await expect(verifyLicenseLease(originalLease, context, verificationNow)).resolves.toMatchObject({
      sub: license.id,
      activation_generation: '1',
    });

    const queryBody = buildChallengeBoundBody({
      challenge: challengeA.token, operationId: queryOperationId, intentDigest: queryIntentDigest,
      attemptNo: 2, instanceId, identity, licenseId: license.id, databaseId,
    });
    const queryResponse = await signPost({
      port: serverB.port, origin: runtimeB.config.publicOrigin, path: '/v1/operations/query',
      body: queryBody, identity, nonce: serverNonce(challengeA.token),
    });
    expect(queryResponse.status, JSON.stringify(queryResponse.json)).toBe(200);
    const receiptToken = queryResponse.json['operation_receipt'] as string;
    const queryAuthority = await loadTrustedSigningContext(db, runtimeA.config);
    const queryContext = queryAuthority.context;
    const queryVerificationNow = new Date(queryContext.trustedTime * 1000);
    await verifyTimeAnchorWithTrustBundleCandidate(historicalTimeAnchorA, {
      // Verify an anchor against the root-signed bundle that was current when
      // it was issued; a later bundle may have an iat after this historical time.
      candidate: beforeRotationTrust.candidate,
      clientNonce: historicalAnchorNonce,
      roundTripMs: 10,
    });
    expect(decodeProtectedHeader(historicalTransferReceiptA)['kid']).toBe(runtimeA.onlineKey.kid);
    expect(decodeProtectedHeader(historicalLeaseA.token)['kid']).toBe(runtimeA.onlineKey.kid);
    expect((await verifyTransferReceipt(historicalTransferReceiptA, queryContext, queryVerificationNow))['new_lease'])
      .toBe(historicalLeaseA.token);
    expect((await verifyDisasterTransferReceipt(historicalDisasterReceiptA, queryContext, queryVerificationNow))['new_lease'])
      .toBe(historicalLeaseA.token);
    expect(decodeProtectedHeader(challengeA.token)['kid']).toBe(runtimeA.onlineKey.kid);
    expect(decodeProtectedHeader(receiptToken)['kid']).toBe(targetB.kid);
    const receipt = await verifyTypedJwt(receiptToken, {
      ...queryContext,
      typ: 'aikayun-license-operation+jwt',
      audience: 'aikayun-commerce',
      now: queryVerificationNow,
      requiredClaims: [
        'v', 'iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'actor_jkt', 'operation_id', 'intent_digest',
        'state', 'outcome_code', 'attempt_no', 'request_nonce_hash', 'request_digest', 'committed_attempt_no',
        'committed_request_nonce_hash', 'committed_request_digest', 'result_jws',
      ],
    });
    expect(receipt.claims['result_jws']).toBe(originalOperation.response_jws);
    expect(originalOperation.response_jws).toBe(originalLease);

    const challengeFromAProcess = await requestChallenge({
      port: serverA.port, config: runtimeA.config, identity, operation: 'query',
      operationId: randomUUID(), intentDigest: digest(), instanceId,
    });
    const challengeFromBProcess = await requestChallenge({
      port: serverB.port, config: runtimeB.config, identity, operation: 'query',
      operationId: randomUUID(), intentDigest: digest(), instanceId,
    });
    expect(decodeProtectedHeader(challengeFromAProcess.token)['kid']).toBe(targetB.kid);
    expect(decodeProtectedHeader(challengeFromBProcess.token)['kid']).toBe(targetB.kid);

    const timeAnchorResponse = await postJson(serverA.port, '/v1/time-anchor', { client_nonce: digest() });
    expect(timeAnchorResponse.status).toBe(200);
    const timeAnchorToken = timeAnchorResponse.json['time_anchor'] as string;
    expect(decodeProtectedHeader(timeAnchorToken)['kid']).toBe(targetB.kid);
    const anchorContext = (await loadTrustedSigningContext(db, runtimeA.config)).context;
    const verifiedAnchor = await verifyTypedJwt(timeAnchorToken, {
      ...anchorContext,
      typ: 'aikayun-time-anchor+jwt',
      audience: 'aikayun-time-bootstrap',
      now: new Date(anchorContext.trustedTime * 1000),
      requiredClaims: Object.keys(decodeJwt(timeAnchorToken)),
    });
    expect(verifiedAnchor.claims['client_nonce']).toBe(decodeJwt(timeAnchorToken)['client_nonce']);

    const keyC = await runtimeA.createOnlineKey();
    const bundle3 = await runtimeA.createBundle('3', [runtimeA.onlineKey.record, stagedTargetB.record, keyC.record]);
    const accept3 = {
      operationId: randomUUID(), expectedSignerRevision: '2', bundleJws: bundle3,
      reason: 'prepublish C for the next isolated signer epoch',
    };
    const accepted3 = await authorityService.acceptTrustBundle({
      ...accept3,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: acceptSignerTrustBundleRequestDigest(accept3),
    });
    (runtimeA.config.signingKeyring as Map<string, typeof keyC>).set(keyC.kid, keyC);
    (runtimeB.config.signingKeyring as Map<string, typeof keyC>).set(keyC.kid, keyC);
    const rotateC = {
      operationId: randomUUID(), expectedSignerRevision: '2', targetKid: keyC.kid,
      bundleVersion: '3', artifactSha256: accepted3.artifactSha256!, reason: 'controlled B to C signer rotation',
    };
    const rotatedC = await authorityService.rotate({
      ...rotateC,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: rotateSignerRequestDigest(rotateC),
    });
    expect(rotatedC).toMatchObject({ activeSigningKid: keyC.kid, signerRevision: '3', state: 'succeeded' });
    const restartedWithOnlyB = await startChildLicenseServer({
      databaseUrl: runtimeB.config.databaseUrl,
      issuer: runtimeB.config.issuer,
      publicOrigin: runtimeB.config.publicOrigin,
      keyringFile: runtimeB.keyringFile,
      offlineRootJwkFile: runtimeB.offlineRootJwkFile,
      minimumTrustBundleVersion: runtimeB.config.minimumTrustBundleVersion,
      tlsKeyFile: runtimeB.config.tlsKeyFile,
      tlsCertFile: runtimeB.config.tlsCertFile,
    });
    try {
      const missingCNonce = digest();
      const missingC = await signPost({
        port: restartedWithOnlyB.port, origin: runtimeB.config.publicOrigin, path: '/v1/challenges',
        body: {
          operation: 'query', operation_id: randomUUID(), intent_digest: digest(), instance_id: instanceId,
          public_jwk: identity.publicJwk, client_nonce: missingCNonce,
        },
        identity, nonce: missingCNonce,
      });
      expect(missingC.status).toBe(503);
      expect(missingC.json['error']).toEqual({ code: 'ACTIVE_SIGNING_KEY_MATERIAL_UNAVAILABLE' });
    } finally {
      await restartedWithOnlyB.stop();
    }
    const rollbackToA = {
      operationId: randomUUID(), expectedSignerRevision: '3', targetKid: runtimeA.onlineKey.kid,
      bundleVersion: '3', artifactSha256: accepted3.artifactSha256!, reason: 'reject signer identity rollback to A',
    };
    await expect(authorityService.rotate({
      ...rollbackToA,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: rotateSignerRequestDigest(rollbackToA),
    })).rejects.toMatchObject({ code: 'SIGNER_KEY_IDENTITY_CANNOT_BE_REUSED' });

    const revokeAAt = Math.floor(Date.now() / 1000);
    const bundle4 = await runtimeA.createBundle('4', [
      { ...runtimeA.onlineKey.record, revoked_at: revokeAAt }, stagedTargetB.record, keyC.record,
    ]);
    const accept4 = {
      operationId: randomUUID(), expectedSignerRevision: '3', bundleJws: bundle4,
      reason: 'emergency revoke leaked historical A signer',
    };
    const accepted4 = await authorityService.acceptTrustBundle({
      ...accept4,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: acceptSignerTrustBundleRequestDigest(accept4),
    });
    expect(accepted4.signerRevision).toBe('3');
    const currentContext = (await loadTrustedSigningContext(db, runtimeA.config)).context;
    const currentVerificationNow = new Date(currentContext.trustedTime * 1000);
    await expect(verifyLicenseLease(originalLease, currentContext, currentVerificationNow)).rejects.toThrow();
    await expect(verifyTypedJwt(challengeA.token, {
      ...currentContext,
      typ: 'aikayun-license-challenge+jwt',
      audience: 'aikayun-commerce',
      now: currentVerificationNow,
      requiredClaims: Object.keys(decodeJwt(challengeA.token)),
    })).rejects.toThrow();
    await expect(verifyTypedJwt(challengeFromBProcess.token, {
      ...currentContext,
      typ: 'aikayun-license-challenge+jwt',
      audience: 'aikayun-commerce',
      now: currentVerificationNow,
      requiredClaims: Object.keys(decodeJwt(challengeFromBProcess.token)),
    })).resolves.toMatchObject({ header: { kid: targetB.kid } });

    const historyChallenge = await requestChallenge({
      port: serverB.port, config: runtimeB.config, identity, operation: 'query',
      operationId: queryOperationId, intentDigest: queryIntentDigest, instanceId,
    });
    expect(decodeProtectedHeader(historyChallenge.token)['kid']).toBe(keyC.kid);
    const historyBody = buildChallengeBoundBody({
      challenge: historyChallenge.token, operationId: queryOperationId, intentDigest: queryIntentDigest,
      attemptNo: 3, instanceId, identity, licenseId: license.id, databaseId,
    });
    const historyResponse = await signPost({
      port: serverB.port, origin: runtimeB.config.publicOrigin, path: '/v1/operations/query',
      body: historyBody, identity, nonce: serverNonce(historyChallenge.token),
    });
    expect(historyResponse.status).toBe(200);
    expect(decodeProtectedHeader(historyResponse.json['operation_receipt'] as string)['kid']).toBe(keyC.kid);
    const historyReceipt = await verifyTypedJwt(historyResponse.json['operation_receipt'], {
      ...currentContext,
      typ: 'aikayun-license-operation+jwt',
      audience: 'aikayun-commerce',
      now: currentVerificationNow,
      requiredClaims: Object.keys(decodeJwt(historyResponse.json['operation_receipt'] as string)),
    });
    expect(historyReceipt.claims['result_jws']).toBe(originalLease);
    expect((await db.selectFrom('license_operations').selectAll()
      .where('operation_id', '=', activationOperationId).executeTakeFirstOrThrow()).response_jws).toBe(originalLease);

    const revokeCAt = Math.floor(Date.now() / 1000);
    const bundle5 = await runtimeA.createBundle('5', [
      { ...runtimeA.onlineKey.record, revoked_at: revokeAAt }, stagedTargetB.record,
      { ...keyC.record, revoked_at: revokeCAt },
    ]);
    const accept5 = {
      operationId: randomUUID(), expectedSignerRevision: '3', bundleJws: bundle5,
      reason: 'emergency revoke active C and stop new center signing',
    };
    await authorityService.acceptTrustBundle({
      ...accept5,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: acceptSignerTrustBundleRequestDigest(accept5),
    });
    const rejectedChallengeNonce = digest();
    const rejectedChallenge = await signPost({
      port: serverA.port, origin: runtimeA.config.publicOrigin, path: '/v1/challenges',
      body: {
        operation: 'query', operation_id: randomUUID(), intent_digest: digest(), instance_id: instanceId,
        public_jwk: identity.publicJwk, client_nonce: rejectedChallengeNonce,
      },
      identity, nonce: rejectedChallengeNonce,
    });
    expect(rejectedChallenge.status).toBe(503);
    expect(rejectedChallenge.json['error']).toEqual({ code: 'ACTIVE_SIGNING_KEY_REVOKED_OR_RETIRED' });
  });
});
