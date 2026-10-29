import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CompactSign, calculateJwkThumbprint, exportJWK, generateKeyPair,
} from 'jose';
import type { CryptoKey, JWK } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { RuntimeConfig } from '../../src/config.js';
import { parseStrictJsonSegment } from '../../src/strict-json.js';
import { verifyLicenseLeaseWithTrustedKeys, signLicenseLease } from '../../src/receipts.js';
import { signTimeAnchor, verifyTimeAnchorWithTrustBundleCandidate } from '../../src/crypto/time-reset.js';
import {
  buildTrustBundleClaims,
  compareBundleVersions,
  signTrustBundle,
  verifyTrustBundleSignature,
} from '../../src/trust/trust-bundle.js';
import type {
  Ed25519PublicJwk,
  RootAuthenticatedTrustBundleCandidate,
  TrustBundleKeyRecord,
  TrustBundleSigningInput,
  TrustedOfflineRootPin,
} from '../../src/trust/trust-bundle.js';
import { TrustBundleStore, type TrustStoreWriteStage } from '../../src/trust/trust-bundle-store.js';

const CENTER_ISSUER = 'https://license.example.test';
const BASE = 2_000_000_000;
const DAY = 24 * 60 * 60;
const temporaryDirectories: string[] = [];
let rootPrivateKey: CryptoKey;
let rootPublicJwk: Ed25519PublicJwk;
let trustedRoot: TrustedOfflineRootPin;
let centerKeyOne: CryptoKey;
let centerVerifyOne: CryptoKey;
let centerPublicOne: Ed25519PublicJwk;
let centerKidOne: string;
let centerKeyTwo: CryptoKey;
let centerVerifyTwo: CryptoKey;
let centerPublicTwo: Ed25519PublicJwk;
let centerKidTwo: string;

async function createEd25519Pair(): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey; publicJwk: Ed25519PublicJwk; kid: string }> {
  const pair = await generateKeyPair('Ed25519', { extractable: true });
  const exported = await exportJWK(pair.publicKey);
  const publicJwk: Ed25519PublicJwk = { kty: 'OKP', crv: 'Ed25519', x: exported.x! };
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk, kid: await calculateJwkThumbprint(publicJwk as JWK, 'sha256') };
}

async function initKeys(): Promise<void> {
  const root = await createEd25519Pair();
  rootPrivateKey = root.privateKey;
  rootPublicJwk = root.publicJwk;
  trustedRoot = { publicJwk: rootPublicJwk, kid: root.kid };
  const one = await createEd25519Pair();
  centerKeyOne = one.privateKey;
  centerVerifyOne = one.publicKey;
  centerPublicOne = one.publicJwk;
  centerKidOne = one.kid;
  const two = await createEd25519Pair();
  centerKeyTwo = two.privateKey;
  centerVerifyTwo = two.publicKey;
  centerPublicTwo = two.publicJwk;
  centerKidTwo = two.kid;
}

async function publicEntry(
  publicJwk: Ed25519PublicJwk,
  kid: string,
  input: Partial<Pick<TrustBundleKeyRecord, 'not_before' | 'retire_after' | 'verify_until' | 'revoked_at'>> = {},
): Promise<TrustBundleKeyRecord> {
  return {
    kid,
    alg: 'Ed25519',
    ...publicJwk,
    not_before: input.not_before ?? BASE - 1_000,
    retire_after: input.retire_after ?? null,
    verify_until: input.verify_until ?? null,
    revoked_at: input.revoked_at ?? null,
  };
}

async function signingClaims(input: {
  version: string;
  keys?: unknown[];
  time?: number;
  iat?: number;
  nbf?: number;
  exp?: number;
  propagationBudget?: number;
}): Promise<Awaited<ReturnType<typeof buildTrustBundleClaims>>> {
  const time = input.time ?? BASE;
  const keys = input.keys ?? [await publicEntry(centerPublicOne, centerKidOne)];
  const claimsInput: TrustBundleSigningInput = {
    bundle_version: input.version,
    iat: input.iat ?? time - 20,
    nbf: input.nbf ?? time - 10,
    exp: input.exp ?? time + 30 * DAY,
    propagation_budget_seconds: input.propagationBudget ?? DAY,
    keys,
  };
  return buildTrustBundleClaims(CENTER_ISSUER, claimsInput, rootPublicJwk);
}

async function bundle(input: Parameters<typeof signingClaims>[0]): Promise<string> {
  const claims = await signingClaims(input);
  return (await signTrustBundle(claims, rootPrivateKey, rootPublicJwk)).token;
}

async function rawRootSigned(payload: string | Record<string, unknown>, header: Record<string, unknown> = {}): Promise<string> {
  const bytes = Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload), 'utf8');
  return new CompactSign(bytes).setProtectedHeader({
    alg: 'Ed25519', kid: trustedRoot.kid, typ: 'aikayun-license-trust-bundle+jwt', ...header,
  }).sign(rootPrivateKey);
}

function runtimeFor(input: { privateKey: CryptoKey; publicKey: CryptoKey; publicJwk: Ed25519PublicJwk; kid: string }): RuntimeConfig {
  return {
    nodeEnv: 'development', databaseUrl: 'postgres://unused', issuer: CENTER_ISSUER, publicOrigin: CENTER_ISSUER,
    tlsKeyFile: '', tlsCertFile: '', tlsPrivateKey: Buffer.alloc(0), tlsCertificate: Buffer.alloc(0),
    port: 1, listenHost: '127.0.0.1', signingPrivateKey: input.privateKey,
    signingPublicKey: input.publicKey, signingPublicJwk: input.publicJwk as JWK, signingKeyId: input.kid,
  };
}

async function lease(input: { privateKey: CryptoKey; publicKey: CryptoKey; publicJwk: Ed25519PublicJwk; kid: string }, issuedAt: number) {
  const config = runtimeFor(input);
  return signLicenseLease(config, {
    licenseId: randomUUID(), instanceId: randomUUID(), databaseId: randomUUID(),
    identityJkt: randomBytes(32).toString('base64url'), generation: '1', entitlementRevision: '1',
    plan: 'monthly', subscriptionEnd: new Date((issuedAt + 8 * DAY) * 1000),
    requestNonce: randomBytes(32).toString('base64url'), requestDigest: randomBytes(32).toString('base64url'),
    now: new Date(issuedAt * 1000),
  });
}

async function store(input: { directory?: string; minimum?: string; faultAt?: (stage: TrustStoreWriteStage) => void | Promise<void> } = {}) {
  const directory = input.directory ?? await mkdtemp(join(tmpdir(), 'aikayun-trust-store-'));
  if (!input.directory) temporaryDirectories.push(directory);
  return new TrustBundleStore({
    directory, trustedRoot, expectedCenterIssuer: CENTER_ISSUER,
    minimumBundleVersion: input.minimum ?? '1', ...(input.faultAt ? { faultAt: input.faultAt } : {}),
  });
}

afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('offline-root trust bundle and monotonic key selection', () => {
  it('accepts a root-signed bundle and verifies a real center lease JWS through its selected key', async () => {
    await initKeys();
    const token = await bundle({ version: '1' });
    const candidate = await verifyTrustBundleSignature(token, { trustedRoot, expectedCenterIssuer: CENTER_ISSUER });
    const accepted = await (await store()).accept(candidate.token, BASE);
    const signed = await lease({ privateKey: centerKeyOne, publicKey: centerVerifyOne, publicJwk: centerPublicOne, kid: centerKidOne }, BASE - 5);
    const verified = await verifyLicenseLeaseWithTrustedKeys(signed.token, {
      resolver: accepted.resolver, issuer: CENTER_ISSUER, now: new Date(BASE * 1000),
    });
    expect(verified['activation_generation']).toBe('1');
    expect(accepted.bundleVersion).toBe('1');
    const anchor = await signTimeAnchor(runtimeFor({
      privateKey: centerKeyOne, publicKey: centerVerifyOne, publicJwk: centerPublicOne, kid: centerKidOne,
    }), randomBytes(32).toString('base64url'), new Date(BASE * 1000));
    await expect(verifyLicenseLeaseWithTrustedKeys(anchor, {
      resolver: accepted.resolver, issuer: CENTER_ISSUER, now: new Date(BASE * 1000),
    })).rejects.toThrow(/header/i);
  });

  it('separates an offline root from online center keys and rejects an online key attempting root signing', async () => {
    await initKeys();
    const claims = await signingClaims({ version: '1' });
    await expect(signTrustBundle(claims, centerKeyOne, rootPublicJwk)).rejects.toThrow();
    const otherRoot = await createEd25519Pair();
    const wrongRootToken = await signTrustBundle(claims, otherRoot.privateKey, otherRoot.publicJwk);
    await expect(verifyTrustBundleSignature(wrongRootToken.token, { trustedRoot, expectedCenterIssuer: CENTER_ISSUER })).rejects.toThrow(/kid|signature/i);
  });

  it('rejects wrong fixed issuer, audience, type, root kid, duplicate fields, and critical headers', async () => {
    await initKeys();
    const valid = await signingClaims({ version: '1' });
    const wrongIssuer = await rawRootSigned({ ...valid, iss: 'https://attacker.example' });
    const wrongAudience = await rawRootSigned({ ...valid, aud: 'aikayun-commerce' });
    const wrongType = await rawRootSigned(valid as unknown as Record<string, unknown>, { typ: 'aikayun-license+jwt' });
    const wrongKid = await rawRootSigned(valid as unknown as Record<string, unknown>, { kid: centerKidOne });
    const duplicateClaim = await rawRootSigned('{"iss":"urn:aikayun:license:offline-release-root:v1","iss":"urn:aikayun:license:offline-release-root:v1"}');
    const criticalHeader = await rawRootSigned(valid as unknown as Record<string, unknown>, { crit: ['b64'], b64: true });
    const dynamicKeyHeader = await rawRootSigned(valid as unknown as Record<string, unknown>, { jku: 'https://attacker.example/keys' });
    for (const bad of [wrongIssuer, wrongAudience, wrongType, wrongKid, duplicateClaim, criticalHeader, dynamicKeyHeader]) {
      await expect(verifyTrustBundleSignature(bad, { trustedRoot, expectedCenterIssuer: CENTER_ISSUER })).rejects.toThrow();
    }
    await expect(verifyTrustBundleSignature(await bundle({ version: '1' }), {
      trustedRoot, expectedCenterIssuer: 'https://other-center.example',
    })).rejects.toThrow(/issuer|center/i);
  });

  it('rejects malformed and ambiguous public JWK records, numeric versions, and unknown schema fields', async () => {
    await initKeys();
    const validEntry = await publicEntry(centerPublicOne, centerKidOne);
    const badEntries = [
      { ...validEntry, kid: 'forged-kid' },
      { ...validEntry, alg: 'EdDSA' },
      { ...validEntry, d: 'private-material' },
      { ...validEntry, x: `${validEntry.x}=` },
      { ...validEntry, unknown: true },
      [validEntry, validEntry],
    ];
    for (const keys of badEntries) {
      await expect(signingClaims({ version: '1', keys: Array.isArray(keys) ? keys : [keys] })).rejects.toThrow();
    }
    await expect(signingClaims({ version: '1', keys: [await publicEntry(rootPublicJwk, trustedRoot.kid)] })).rejects.toThrow(/offline root/i);
    const valid = await signingClaims({ version: '1' });
    await expect(rawRootSigned({ ...valid, bundle_version: 1 })).resolves.toBeTruthy();
    await expect(verifyTrustBundleSignature(await rawRootSigned({ ...valid, bundle_version: 1 }), {
      trustedRoot, expectedCenterIssuer: CENTER_ISSUER,
    })).rejects.toThrow(/version/i);
    await expect(verifyTrustBundleSignature(await rawRootSigned({ ...valid, unexpected: true }), {
      trustedRoot, expectedCenterIssuer: CENTER_ISSUER,
    })).rejects.toThrow(/fields/i);
  });

  it('requires the trust bundle audience to stay distinct from lease and receipt audiences', async () => {
    await initKeys();
    const token = await bundle({ version: '1' });
    const header = parseStrictJsonSegment(token.split('.')[0]!);
    expect(header['typ']).toBe('aikayun-license-trust-bundle+jwt');
    const candidate = await verifyTrustBundleSignature(token, { trustedRoot, expectedCenterIssuer: CENTER_ISSUER });
    expect(candidate.claims.aud).toBe('aikayun-license-signing-keys');
    expect(candidate.claims.aud).not.toBe('aikayun-commerce');
  });

  it('accepts v1 to v2, replays the identical artifact, and rejects rollback or same-version replacement', async () => {
    await initKeys();
    const directory = await mkdtemp(join(tmpdir(), 'aikayun-trust-versions-'));
    temporaryDirectories.push(directory);
    const trust = await store({ directory });
    const v1 = await bundle({ version: '1' });
    const v2 = await bundle({ version: '2', keys: [await publicEntry(centerPublicOne, centerKidOne), await publicEntry(centerPublicTwo, centerKidTwo)] });
    const differentV2 = await bundle({ version: '2', keys: [await publicEntry(centerPublicTwo, centerKidTwo)] });
    expect((await trust.accept(v1, BASE)).bundleVersion).toBe('1');
    const oldResolver = (await trust.getAccepted(BASE)).resolver;
    expect((await trust.accept(v2, BASE)).bundleVersion).toBe('2');
    expect((await trust.accept(v2, BASE)).acceptedIdempotently).toBe(true);
    const signedByOldKey = await lease({ privateKey: centerKeyOne, publicKey: centerVerifyOne, publicJwk: centerPublicOne, kid: centerKidOne }, BASE - 5);
    await expect(verifyLicenseLeaseWithTrustedKeys(signedByOldKey.token, {
      resolver: oldResolver, issuer: CENTER_ISSUER, now: new Date(BASE * 1000),
    })).rejects.toThrow(/stale/i);
    await expect(trust.accept(v1, BASE)).rejects.toThrow(/rollback/i);
    await expect(trust.accept(differentV2, BASE)).rejects.toThrow(/same trust bundle version/i);
    expect((await trust.getAccepted(BASE)).bundleVersion).toBe('2');
  });

  it('R1 regression: rejects a newer bundle that silently drops an active key with a live lease', async () => {
    await initKeys();
    const trust = await store();
    const v1 = await bundle({ version: '1', keys: [await publicEntry(centerPublicOne, centerKidOne)] });
    await trust.accept(v1, BASE);
    const signedByA = await lease({
      privateKey: centerKeyOne, publicKey: centerVerifyOne, publicJwk: centerPublicOne, kid: centerKidOne,
    }, BASE - 5);
    const v2 = await bundle({ version: '2', keys: [await publicEntry(centerPublicTwo, centerKidTwo)] });
    await expect(trust.accept(v2, BASE)).rejects.toThrow(/lifecycle|retir|revok|remove/i);
    const accepted = await trust.getAccepted(BASE);
    await expect(verifyLicenseLeaseWithTrustedKeys(signedByA.token, {
      resolver: accepted.resolver, issuer: CENTER_ISSUER, now: new Date(BASE * 1000),
    })).resolves.toBeTruthy();
  });

  it('uses a release-pinned minimum version and does not trust the first older network package', async () => {
    await initKeys();
    const trust = await store({ minimum: '2' });
    const v1 = await bundle({ version: '1' });
    await expect(trust.accept(v1, BASE)).rejects.toThrow(/minimum version/i);
    await expect(trust.getAccepted(BASE)).rejects.toThrow(/No accepted/);
  });

  it('fails closed on storage corruption or deletion and preserves last-good bytes on invalid packages', async () => {
    await initKeys();
    const directory = await mkdtemp(join(tmpdir(), 'aikayun-trust-corrupt-'));
    temporaryDirectories.push(directory);
    const trust = await store({ directory });
    const v1 = await bundle({ version: '1' });
    const v2 = await bundle({ version: '2' });
    await trust.accept(v1, BASE);
    const statePath = join(directory, 'trust-bundle-state.json');
    const before = await readFile(statePath);
    await expect(trust.accept(`${v2}.tampered`, BASE)).rejects.toThrow();
    await expect(trust.accept(undefined, BASE)).rejects.toThrow();
    expect(await readFile(statePath)).toEqual(before);
    await writeFile(statePath, '{"broken":');
    await expect(trust.accept(v2, BASE)).rejects.toThrow();
    await expect(trust.getAccepted(BASE)).rejects.toThrow();

    const secondDirectory = await mkdtemp(join(tmpdir(), 'aikayun-trust-missing-'));
    temporaryDirectories.push(secondDirectory);
    const second = await store({ directory: secondDirectory });
    await second.accept(v1, BASE);
    await unlink(join(secondDirectory, 'trust-bundle-state.json'));
    await expect(second.accept(v1, BASE)).rejects.toThrow(/missing|checkpoint|mismatch/i);
  });

  it('R1 regression: rejects restoring a saved v1 state file while retaining the v2 checkpoint', async () => {
    await initKeys();
    const directory = await mkdtemp(join(tmpdir(), 'aikayun-trust-single-file-rollback-'));
    temporaryDirectories.push(directory);
    const trust = await store({ directory });
    const v1 = await bundle({ version: '1' });
    const acceptedV1 = await trust.accept(v1, BASE);
    const signedByA = await lease({
      privateKey: centerKeyOne, publicKey: centerVerifyOne, publicJwk: centerPublicOne, kid: centerKidOne,
    }, BASE - 5);
    const statePath = join(directory, 'trust-bundle-state.json');
    const savedV1State = await readFile(statePath);
    const revokedA = await publicEntry(centerPublicOne, centerKidOne, { revoked_at: BASE - 30 });
    const v2 = await bundle({ version: '2', keys: [revokedA] });
    await trust.accept(v2, BASE);
    await writeFile(statePath, savedV1State);

    const restarted = await store({ directory });
    await expect(restarted.getAccepted(BASE)).rejects.toThrow(/checkpoint|rollback|mismatch|watermark/i);
    await expect(verifyLicenseLeaseWithTrustedKeys(signedByA.token, {
      resolver: acceptedV1.resolver, issuer: CENTER_ISSUER, now: new Date(BASE * 1000),
    })).rejects.toThrow(/checkpoint|mismatch|stale/i);
  });

  it('preserves a key through normal retirement and permits removal only after verify_until', async () => {
    await initKeys();
    const trust = await store();
    const first = await bundle({ version: '1' });
    await trust.accept(first, BASE);
    const retireAt = BASE + 100;
    const verifyUntil = retireAt + 8 * DAY;
    const retiredA = await publicEntry(centerPublicOne, centerKidOne, {
      not_before: BASE - 1_000, retire_after: retireAt, verify_until: verifyUntil,
    });
    const second = await bundle({
      version: '2', time: retireAt, iat: retireAt - 20, nbf: retireAt - 10,
      exp: retireAt + 25 * DAY, keys: [retiredA, await publicEntry(centerPublicTwo, centerKidTwo)],
    });
    const secondAccepted = await trust.accept(second, retireAt);
    const preRetirementLease = await lease({
      privateKey: centerKeyOne, publicKey: centerVerifyOne, publicJwk: centerPublicOne, kid: centerKidOne,
    }, retireAt - 10);
    await expect(verifyLicenseLeaseWithTrustedKeys(preRetirementLease.token, {
      resolver: secondAccepted.resolver, issuer: CENTER_ISSUER, now: new Date(retireAt * 1000),
    })).resolves.toBeTruthy();

    const removedBeforeRetention = await bundle({
      version: '3', time: verifyUntil - 1, iat: verifyUntil - 21, nbf: verifyUntil - 11,
      exp: verifyUntil + 20 * DAY, keys: [await publicEntry(centerPublicTwo, centerKidTwo)],
    });
    await expect(trust.accept(removedBeforeRetention, verifyUntil - 1)).rejects.toThrow(/cannot be removed/i);
    const removedAfterRetention = await bundle({
      version: '3', time: verifyUntil, iat: verifyUntil - 20, nbf: verifyUntil - 10,
      exp: verifyUntil + 20 * DAY, keys: [await publicEntry(centerPublicTwo, centerKidTwo)],
    });
    expect((await trust.accept(removedAfterRetention, verifyUntil)).bundleVersion).toBe('3');
  });

  it('rejects lifecycle field rewrites and backdated retirement for the same kid', async () => {
    await initKeys();
    const trust = await store();
    await trust.accept(await bundle({ version: '1' }), BASE);
    const retireAt = BASE + 100;
    const verifyUntil = retireAt + 9 * DAY;
    const oldRecord = await publicEntry(centerPublicOne, centerKidOne, {
      not_before: BASE - 1_000, retire_after: retireAt, verify_until: verifyUntil,
    });
    const second = await bundle({
      version: '2', time: retireAt, iat: retireAt - 20, nbf: retireAt - 10,
      exp: retireAt + 25 * DAY, keys: [oldRecord, await publicEntry(centerPublicTwo, centerKidTwo)],
    });
    await trust.accept(second, retireAt);

    const changedRecords = [
      await publicEntry(centerPublicOne, centerKidOne, { ...oldRecord, not_before: oldRecord.not_before + 1 }),
      await publicEntry(centerPublicOne, centerKidOne, { ...oldRecord, retire_after: retireAt - 1 }),
      await publicEntry(centerPublicOne, centerKidOne, { ...oldRecord, verify_until: retireAt + 8 * DAY }),
    ];
    for (const [index, changed] of changedRecords.entries()) {
      const candidate = await bundle({
        version: '3', time: retireAt + 20 + index, iat: retireAt + index, nbf: retireAt + index + 1,
        exp: retireAt + 25 * DAY, keys: [changed, await publicEntry(centerPublicTwo, centerKidTwo)],
      });
      await expect(trust.accept(candidate, retireAt + 20 + index)).rejects.toThrow(/immutable|retirement|not_before/i);
    }

    const activeStore = await store();
    await activeStore.accept(await bundle({ version: '1' }), BASE);
    const backdated = await bundle({
      version: '2', time: BASE + 100, iat: BASE + 80, nbf: BASE + 90, exp: BASE + 20 * DAY,
      keys: [await publicEntry(centerPublicOne, centerKidOne, {
        not_before: BASE - 1_000, retire_after: BASE, verify_until: BASE + 8 * DAY,
      })],
    });
    await expect(activeStore.accept(backdated, BASE + 100)).rejects.toThrow(/backdated/i);
  });

  it('rejects expired bundles without replacing the accepted last-good version', async () => {
    await initKeys();
    const trust = await store();
    const v1 = await bundle({ version: '1' });
    await trust.accept(v1, BASE);
    const expiredV2 = await bundle({ version: '2', time: BASE - 100, exp: BASE - 1 });
    await expect(trust.accept(expiredV2, BASE)).rejects.toThrow(/valid|expired/i);
    expect((await trust.getAccepted(BASE)).bundleVersion).toBe('1');
  });

  it('uses root-authenticated candidate keys for time bootstrap with a five-year wall-clock error', async () => {
    await initKeys();
    const token = await bundle({ version: '1' });
    const candidate = await verifyTrustBundleSignature(token, { trustedRoot, expectedCenterIssuer: CENTER_ISSUER });
    const runtime = runtimeFor({ privateKey: centerKeyOne, publicKey: centerVerifyOne, publicJwk: centerPublicOne, kid: centerKidOne });
    const nonce = randomBytes(32).toString('base64url');
    const serverTime = BASE + 5;
    const anchor = await signTimeAnchor(runtime, nonce, new Date(serverTime * 1000));
    vi.useFakeTimers();
    vi.setSystemTime(new Date((serverTime + 5 * 365 * DAY) * 1000));
    const verified = await verifyTimeAnchorWithTrustBundleCandidate(anchor, {
      candidate, clientNonce: nonce, roundTripMs: 1_200,
    });
    expect(verified.serverTime).toBe(serverTime);
    expect(verified.clientNonce).toBe(nonce);
    await expect(verifyTimeAnchorWithTrustBundleCandidate(anchor, {
      candidate, clientNonce: randomBytes(32).toString('base64url'), roundTripMs: 1_200,
    })).rejects.toThrow();
    await expect(verifyTimeAnchorWithTrustBundleCandidate(anchor, {
      candidate, clientNonce: nonce, roundTripMs: 5_001,
    })).rejects.toThrow(/fresh/i);
  });

  it('selects two approved keys during overlap and preserves a pre-retirement lease until its verify window ends', async () => {
    await initKeys();
    const retiredAt = BASE;
    const verifyUntil = retiredAt + 7 * DAY + DAY;
    const oldEntry = await publicEntry(centerPublicOne, centerKidOne, {
      not_before: BASE - DAY,
      retire_after: retiredAt,
      verify_until: verifyUntil,
    });
    const newEntry = await publicEntry(centerPublicTwo, centerKidTwo, { not_before: BASE - 10 });
    const token = await bundle({ version: '2', time: BASE + 100, iat: BASE + 50, nbf: BASE + 50, exp: BASE + 25 * DAY, keys: [oldEntry, newEntry], propagationBudget: DAY });
    const accepted = await (await store()).accept(token, BASE + 100);
    const oldLease = await lease({ privateKey: centerKeyOne, publicKey: centerVerifyOne, publicJwk: centerPublicOne, kid: centerKidOne }, retiredAt - 10);
    const newLease = await lease({ privateKey: centerKeyTwo, publicKey: centerVerifyTwo, publicJwk: centerPublicTwo, kid: centerKidTwo }, BASE + 20);
    expect((await verifyLicenseLeaseWithTrustedKeys(oldLease.token, {
      resolver: accepted.resolver, issuer: CENTER_ISSUER, now: new Date((BASE + 100) * 1000),
    }))['sub']).toBeTruthy();
    expect((await verifyLicenseLeaseWithTrustedKeys(newLease.token, {
      resolver: accepted.resolver, issuer: CENTER_ISSUER, now: new Date((BASE + 100) * 1000),
    }))['sub']).toBeTruthy();

    const outsideWindow = await lease({ privateKey: centerKeyOne, publicKey: centerVerifyOne, publicJwk: centerPublicOne, kid: centerKidOne }, retiredAt + 1);
    await expect(verifyLicenseLeaseWithTrustedKeys(outsideWindow.token, {
      resolver: accepted.resolver, issuer: CENTER_ISSUER, now: new Date((BASE + 100) * 1000),
    })).rejects.toThrow(/issuance window/i);

    const laterTime = verifyUntil + 1;
    const laterBundle = await bundle({ version: '3', time: laterTime, iat: laterTime - 20, nbf: laterTime - 10, exp: laterTime + 10 * DAY, keys: [oldEntry, newEntry] });
    const laterDirectory = await mkdtemp(join(tmpdir(), 'aikayun-trust-verify-until-'));
    temporaryDirectories.push(laterDirectory);
    const later = await (await store({ directory: laterDirectory })).accept(laterBundle, laterTime);
    await expect(verifyLicenseLeaseWithTrustedKeys(oldLease.token, {
      resolver: later.resolver, issuer: CENTER_ISSUER, now: new Date(laterTime * 1000),
    })).rejects.toThrow(/verification-retention/i);
  });

  it('does not allow a prepublished key to sign before not_before', async () => {
    await initKeys();
    const futureKey = await publicEntry(centerPublicOne, centerKidOne, { not_before: BASE + 1 });
    const token = await bundle({ version: '1', time: BASE, keys: [futureKey] });
    const accepted = await (await store()).accept(token, BASE);
    const earlyLease = await lease({ privateKey: centerKeyOne, publicKey: centerVerifyOne, publicJwk: centerPublicOne, kid: centerKidOne }, BASE);
    await expect(verifyLicenseLeaseWithTrustedKeys(earlyLease.token, {
      resolver: accepted.resolver, issuer: CENTER_ISSUER, now: new Date(BASE * 1000),
    })).rejects.toThrow(/issuance window/i);
  });

  it('requires explicit retirement propagation budget and retains a monotonic revocation tombstone', async () => {
    await initKeys();
    const trust = await store();
    const first = await bundle({ version: '1' });
    await trust.accept(first, BASE);
    const oldLease = await lease({ privateKey: centerKeyOne, publicKey: centerVerifyOne, publicJwk: centerPublicOne, kid: centerKidOne }, BASE - 5);
    const revoked = await publicEntry(centerPublicOne, centerKidOne, { revoked_at: BASE - 30 });
    const second = await bundle({ version: '2', keys: [revoked] });
    const accepted = await trust.accept(second, BASE);
    await expect(verifyLicenseLeaseWithTrustedKeys(oldLease.token, {
      resolver: accepted.resolver, issuer: CENTER_ISSUER, now: new Date(BASE * 1000),
    })).rejects.toThrow(/revoked/i);

    const omitted = await bundle({ version: '3', keys: [await publicEntry(centerPublicTwo, centerKidTwo)] });
    const acceptedAfterOmission = await trust.accept(omitted, BASE);
    expect(acceptedAfterOmission.revokedKids).toContain(centerKidOne);
    await expect(verifyLicenseLeaseWithTrustedKeys(oldLease.token, {
      resolver: acceptedAfterOmission.resolver, issuer: CENTER_ISSUER, now: new Date(BASE * 1000),
    })).rejects.toThrow(/key|kid/i);
    const resurrected = await bundle({ version: '4', keys: [
      await publicEntry(centerPublicOne, centerKidOne), await publicEntry(centerPublicTwo, centerKidTwo),
    ] });
    await expect(trust.accept(resurrected, BASE)).rejects.toThrow(/cannot be reactivated/i);
    const restoredStore = await store({ directory: trust.directory });
    expect((await restoredStore.getAccepted(BASE)).revokedKids).toContain(centerKidOne);

    const badRetirement = await publicEntry(centerPublicTwo, centerKidTwo, {
      not_before: BASE - 1_000, retire_after: BASE, verify_until: BASE + 7 * DAY,
    });
    await expect(signingClaims({ version: '4', keys: [badRetirement], propagationBudget: 1 })).rejects.toThrow(/retirement/i);
  });

  it('recovers every atomic-write interruption without losing the committed high-water version', async () => {
    await initKeys();
    const stages: Array<{ stage: TrustStoreWriteStage; expected: '1' | '2' }> = [
      ...(['before_write', 'after_partial_write', 'after_write', 'after_file_fsync', 'after_rename', 'after_directory_fsync'] as const)
        .map((name) => ({ stage: `checkpoint_prepare_${name}` as TrustStoreWriteStage, expected: '1' as const })),
      ...(['before_write', 'after_partial_write', 'after_write', 'after_file_fsync'] as const)
        .map((name) => ({ stage: `state_${name}` as TrustStoreWriteStage, expected: '1' as const })),
      { stage: 'state_after_rename', expected: '2' },
      { stage: 'state_after_directory_fsync', expected: '2' },
      ...(['before_write', 'after_partial_write', 'after_write', 'after_file_fsync'] as const)
        .map((name) => ({ stage: `checkpoint_commit_${name}` as TrustStoreWriteStage, expected: '2' as const })),
      { stage: 'checkpoint_commit_after_rename', expected: '2' },
      { stage: 'checkpoint_commit_after_directory_fsync', expected: '2' },
    ];
    for (const { stage, expected } of stages) {
      const directory = await mkdtemp(join(tmpdir(), `aikayun-trust-${stage}-`));
      temporaryDirectories.push(directory);
      const stable = await store({ directory });
      const v1 = await bundle({ version: '1' });
      const v2 = await bundle({ version: '2' });
      await stable.accept(v1, BASE);
      const crashing = await store({ directory, faultAt: (observed) => {
        if (observed === stage) throw new Error(`simulated interruption at ${stage}`);
      } });
      await expect(crashing.accept(v2, BASE)).rejects.toThrow(/simulated interruption/i);
      const restarted = await store({ directory });
      const recovered = await restarted.getAccepted(BASE);
      expect(recovered.bundleVersion).toBe(expected);
      expect(compareBundleVersions(recovered.bundleVersion, '1')).toBeGreaterThanOrEqual(0);
    }
  });

  it('serializes concurrent writers and recovers a stale process lock without lowering the watermark', async () => {
    await initKeys();
    const directory = await mkdtemp(join(tmpdir(), 'aikayun-trust-concurrent-'));
    temporaryDirectories.push(directory);
    const firstStore = await store({ directory });
    await firstStore.accept(await bundle({ version: '1' }), BASE);
    const v2 = await bundle({ version: '2' });
    const v3 = await bundle({ version: '3' });
    const secondStore = await store({ directory });
    const outcomes = await Promise.allSettled([firstStore.accept(v2, BASE), secondStore.accept(v3, BASE)]);
    expect(outcomes.some((outcome) => outcome.status === 'fulfilled')).toBe(true);
    const concurrentHead = await firstStore.getAccepted(BASE);
    expect(['2', '3']).toContain(concurrentHead.bundleVersion);

    const lockPath = join(directory, '.trust-bundle-write.lock');
    await writeFile(lockPath, JSON.stringify({ pid: 2_147_483_647, host: hostname() }), { mode: 0o600 });
    const v4 = await bundle({ version: '4' });
    expect((await secondStore.accept(v4, BASE)).bundleVersion).toBe('4');
    await expect(readFile(lockPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('retries an interrupted checkpoint recovery without losing or lowering the committed version', async () => {
    await initKeys();
    const recoveryStages: TrustStoreWriteStage[] = [
      'checkpoint_recovery_before_write', 'checkpoint_recovery_after_partial_write',
      'checkpoint_recovery_after_write', 'checkpoint_recovery_after_file_fsync',
      'checkpoint_recovery_after_rename', 'checkpoint_recovery_after_directory_fsync',
    ];
    for (const stage of recoveryStages) {
      const directory = await mkdtemp(join(tmpdir(), `aikayun-trust-recovery-${stage}-`));
      temporaryDirectories.push(directory);
      const stable = await store({ directory });
      await stable.accept(await bundle({ version: '1' }), BASE);
      const v2 = await bundle({ version: '2' });
      const pendingStore = await store({ directory, faultAt: (observed) => {
        if (observed === 'checkpoint_commit_before_write') throw new Error('leave state-ahead pending');
      } });
      await expect(pendingStore.accept(v2, BASE)).rejects.toThrow(/leave state-ahead/i);
      const crashingRecovery = await store({ directory, faultAt: (observed) => {
        if (observed === stage) throw new Error(`simulated interruption at ${stage}`);
      } });
      await expect(crashingRecovery.getAccepted(BASE)).rejects.toThrow(/simulated interruption/i);
      const restarted = await store({ directory });
      expect((await restarted.getAccepted(BASE)).bundleVersion).toBe('2');
    }
  });
});
