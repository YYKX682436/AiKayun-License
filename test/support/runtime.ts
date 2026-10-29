import { randomBytes, randomUUID } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import {
  calculateJwkThumbprint, exportJWK, exportPKCS8, generateKeyPair,
  type CryptoKey, type JWK,
} from 'jose';
import type { RuntimeConfig } from '../../src/config.js';
import type { SigningContext, VerificationContext } from '../../src/crypto/signing-types.js';
import type { Database } from '../../src/db/types.js';
import type { Kysely } from 'kysely';
import { buildTrustBundleClaims, signTrustBundle } from '../../tools/offline-trust/trust-bundle-signing.js';
import { trustBundleArtifactDigest } from '../../src/trust/trust-bundle.js';
import type { Ed25519PublicJwk, TrustBundleKeyRecord, TrustedOfflineRootPin } from '../../src/trust/trust-bundle.js';
import { verifyTrustBundleSignature } from '../../src/trust/trust-bundle.js';
import { createTrustedSigningKeyResolver } from '../../src/trust/trust-bundle-store.js';
import { createSignerAdminService, initializeSignerRequestDigest } from '../../src/admin/signing-service.js';
import type { OnlineSigningKey } from '../../src/config.js';

const execFile = promisify(execFileCallback);

export interface TestIdentity {
  privateKey: CryptoKey;
  privateJwk: JWK;
  publicKey: CryptoKey;
  publicJwk: Ed25519PublicJwk & Record<string, unknown>;
  jkt: string;
}

export interface TestOnlineKey extends OnlineSigningKey {
  privatePem: string;
  record: TrustBundleKeyRecord;
}

export type TestRuntimeConfig = RuntimeConfig & SigningContext & VerificationContext & {
  signingKeyId: string;
  signingPublicKey: CryptoKey;
};

export interface TestSigningRuntime {
  config: TestRuntimeConfig;
  signer: SigningContext;
  verificationContext: VerificationContext;
  onlineKey: TestOnlineKey;
  offlineRootPrivateKey: CryptoKey;
  offlineRootPublicJwk: Ed25519PublicJwk;
  trustBundleJws: string;
  trustBundleVersion: string;
  keyringFile: string;
  onlinePrivateKeyFile: string;
  keyFiles: Map<string, string>;
  offlineRootJwkFile: string;
  privatePem: string;
  createOnlineKey(input?: Partial<Pick<TrustBundleKeyRecord, 'not_before' | 'retire_after' | 'verify_until' | 'revoked_at'>>): Promise<TestOnlineKey>;
  createBundle(version: string, keys: readonly TrustBundleKeyRecord[], input?: { iat?: number; nbf?: number; exp?: number; propagationBudgetSeconds?: number }): Promise<string>;
  initializeAuthority(db: Kysely<Database>): Promise<void>;
  createAdminService(db: Kysely<Database>): ReturnType<typeof createSignerAdminService>;
  cleanup(): Promise<void>;
}

export interface CreateTestRuntimeOptions {
  /** Share the disposable test database with another simulated service process. */
  databaseUrl?: string;
  /** Share only the isolated test offline root; a new online signer is still generated. */
  trustFrom?: TestSigningRuntime;
}

async function createTemporaryDatabase(baseConnectionString: string): Promise<{ url: string; drop(): Promise<void> }> {
  const databaseName = `license_test_${randomUUID().replaceAll('-', '')}`;
  const adminUrl = new URL(baseConnectionString);
  adminUrl.pathname = '/postgres';
  const adminPool = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  try {
    await adminPool.query(`CREATE DATABASE "${databaseName}"`);
  } finally {
    await adminPool.end();
  }
  const databaseUrl = new URL(baseConnectionString);
  databaseUrl.pathname = `/${databaseName}`;
  return {
    url: databaseUrl.toString(),
    async drop() {
      const dropPool = new Pool({ connectionString: adminUrl.toString(), max: 1 });
      try { await dropPool.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`); }
      finally { await dropPool.end(); }
    },
  };
}

export async function createTestSigningRuntime(options: CreateTestRuntimeOptions = {}): Promise<TestSigningRuntime> {
  const baseUrl = process.env['LICENSE_TEST_DATABASE_URL'] ?? 'postgres://license:license-test-only@127.0.0.1:55673/license_center_test';
  const ownedDatabase = options.databaseUrl ? null : await createTemporaryDatabase(baseUrl);
  const databaseUrl = options.databaseUrl ?? ownedDatabase!.url;
  const rootPair = options.trustFrom
    ? { privateKey: options.trustFrom.offlineRootPrivateKey, publicJwk: options.trustFrom.offlineRootPublicJwk }
    : await makePair();
  const onlineKey = await createTestOnlineKey();
  const rootPin: TrustedOfflineRootPin = {
    publicJwk: rootPair.publicJwk,
    kid: await calculateJwkThumbprint(rootPair.publicJwk as JWK, 'sha256'),
  };
  const issuer = 'https://license.example.test';
  const trustBundleVersion = '1';
  const trustBundleJws = await createTrustBundle(rootPair.privateKey, rootPair.publicJwk, issuer, trustBundleVersion, [onlineKey.record]);
  const candidate = await verifyTrustBundleSignature(trustBundleJws, { trustedRoot: rootPin, expectedCenterIssuer: issuer });
  const resolver = {
    async resolveKey(input: Parameters<ReturnType<typeof createTrustedSigningKeyResolver>['resolveKey']>[0]) {
      return createTrustedSigningKeyResolver(candidate, { revokedKids: [], trustedTime: input.trustedTime }).resolveKey(input);
    },
  };
  const verificationContext: VerificationContext = { issuer, resolver, trustedTime: Math.floor(Date.now() / 1000) };
  const signer: SigningContext = Object.freeze({
    issuer,
    kid: onlineKey.kid,
    privateKey: onlineKey.privateKey,
    publicKey: onlineKey.publicKey,
    publicJwk: onlineKey.publicJwk,
    signerRevision: '1',
    bundleVersion: trustBundleVersion,
    artifactSha256: trustBundleArtifactDigest(trustBundleJws),
    resolver,
  });
  const directory = await mkdtemp(join(tmpdir(), 'aikayun-license-tls-'));
  const tlsKeyFile = join(directory, 'tls-key.pem');
  const tlsCertFile = join(directory, 'tls-cert.pem');
  await execFile('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=license.example.test', '-addext', 'subjectAltName=DNS:license.example.test',
    '-keyout', tlsKeyFile, '-out', tlsCertFile,
  ]);
  await chmod(tlsKeyFile, 0o600);
  const onlinePrivateKeyFile = join(directory, `signing-${onlineKey.kid}.pem`);
  const offlineRootJwkFile = join(directory, 'offline-root-public.json');
  const keyringFile = join(directory, 'online-signing-keyring.json');
  await writeFile(onlinePrivateKeyFile, onlineKey.privatePem, { mode: 0o600 });
  await chmod(onlinePrivateKeyFile, 0o600);
  await writeFile(offlineRootJwkFile, JSON.stringify(rootPair.publicJwk), { mode: 0o600 });
  await chmod(offlineRootJwkFile, 0o600);
  await writeFile(keyringFile, JSON.stringify({ schema: 1, keys: [{ kid: onlineKey.kid, path: onlinePrivateKeyFile }] }), { mode: 0o600 });
  await chmod(keyringFile, 0o600);
  const config = Object.assign({
    nodeEnv: 'development' as const,
    databaseUrl,
    issuer,
    publicOrigin: issuer,
    tlsKeyFile,
    tlsCertFile,
    tlsPrivateKey: await readFile(tlsKeyFile),
    tlsCertificate: await readFile(tlsCertFile),
    port: 4318,
    listenHost: '127.0.0.1',
    signingKeyring: new Map([[onlineKey.kid, onlineKey]]),
    trustedOfflineRoot: rootPin,
    minimumTrustBundleVersion: '1',
  }, signer, verificationContext, {
    signingKeyId: onlineKey.kid,
    signingPublicKey: onlineKey.publicKey,
  }) as TestRuntimeConfig;

  async function createOnlineKey(input: Partial<Pick<TrustBundleKeyRecord, 'not_before' | 'retire_after' | 'verify_until' | 'revoked_at'>> = {}): Promise<TestOnlineKey> {
    return createTestOnlineKey(input);
  }

  async function createBundle(version: string, keys: readonly TrustBundleKeyRecord[], input: {
    iat?: number; nbf?: number; exp?: number; propagationBudgetSeconds?: number;
  } = {}): Promise<string> {
    return createTrustBundle(rootPair.privateKey, rootPair.publicJwk, issuer, version, keys, input);
  }

  async function initializeAuthority(db: Kysely<Database>): Promise<void> {
    const service = createAdminService(db);
    const request = {
      operationId: randomUUID(),
      expectedSignerRevision: '0',
      activeKid: onlineKey.kid,
      bundleJws: trustBundleJws,
      reason: 'initialize isolated integration signer',
    };
    await service.initialize({
      ...request,
      rolloutGate: 'isolated-development-confirmed',
      confirmedRequestDigest: initializeSignerRequestDigest(request),
    });
  }

  function createAdminService(db: Kysely<Database>) {
    const dbRole = decodeURIComponent(new URL(databaseUrl).username);
    const actor = {
      osUid: process.geteuid?.() ?? 0,
      osUsername: userInfo().username,
      databaseRole: dbRole,
    };
    return createSignerAdminService({ db, actor, close: async () => undefined }, config);
  }

  return {
    config, signer, verificationContext, onlineKey,
    offlineRootPrivateKey: rootPair.privateKey,
    offlineRootPublicJwk: rootPair.publicJwk,
    trustBundleJws,
    trustBundleVersion,
    keyringFile,
    keyFiles: new Map([[onlineKey.kid, onlinePrivateKeyFile]]),
    onlinePrivateKeyFile,
    offlineRootJwkFile,
    privatePem: onlineKey.privatePem,
    createOnlineKey,
    createBundle,
    initializeAuthority,
    createAdminService,
    async cleanup() {
      await rm(directory, { recursive: true, force: true });
      await ownedDatabase?.drop();
    },
  };
}

async function makePair(): Promise<{ privateKey: CryptoKey; publicJwk: Ed25519PublicJwk }> {
  const pair = await generateKeyPair('Ed25519', { extractable: true });
  const exported = await exportJWK(pair.publicKey);
  return { privateKey: pair.privateKey, publicJwk: { kty: 'OKP', crv: 'Ed25519', x: exported.x! } };
}

export async function createTestOnlineKey(input: Partial<Pick<TrustBundleKeyRecord, 'not_before' | 'retire_after' | 'verify_until' | 'revoked_at'>> = {}): Promise<TestOnlineKey> {
  const pair = await generateKeyPair('Ed25519', { extractable: true });
  const exported = await exportJWK(pair.publicKey);
  const publicJwk: Ed25519PublicJwk = { kty: 'OKP', crv: 'Ed25519', x: exported.x! };
  const kid = await calculateJwkThumbprint(publicJwk as JWK, 'sha256');
  const now = Math.floor(Date.now() / 1000);
  return {
    kid,
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    publicJwk,
    privatePem: await exportPKCS8(pair.privateKey),
    record: {
      kid, alg: 'Ed25519', ...publicJwk,
      not_before: input.not_before ?? now - 7 * 24 * 60 * 60,
      retire_after: input.retire_after ?? now + 30 * 24 * 60 * 60,
      verify_until: input.verify_until ?? now + 38 * 24 * 60 * 60,
      revoked_at: input.revoked_at ?? null,
    },
  };
}

async function createTrustBundle(
  rootPrivateKey: CryptoKey,
  rootPublicJwk: Ed25519PublicJwk,
  issuer: string,
  version: string,
  keys: readonly TrustBundleKeyRecord[],
  input: { iat?: number; nbf?: number; exp?: number; propagationBudgetSeconds?: number } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const claims = await buildTrustBundleClaims(issuer, {
    bundle_version: version,
    iat: input.iat ?? now,
    nbf: input.nbf ?? now,
    exp: input.exp ?? now + 60 * 24 * 60 * 60,
    propagation_budget_seconds: input.propagationBudgetSeconds ?? 60,
    keys: [...keys],
  }, rootPublicJwk);
  return (await signTrustBundle(claims, rootPrivateKey, rootPublicJwk)).token;
}

export async function createIdentity(): Promise<TestIdentity> {
  const pair = await generateKeyPair('Ed25519', { extractable: true });
  const privateJwk = await exportJWK(pair.privateKey);
  const publicJwkRaw = await exportJWK(pair.publicKey);
  const publicJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: publicJwkRaw.x! } as Ed25519PublicJwk & Record<string, unknown>;
  const jkt = await calculateJwkThumbprint(publicJwk, 'sha256');
  return { privateKey: pair.privateKey, privateJwk, publicKey: pair.publicKey, publicJwk, jkt };
}

export function newClientNonce(): string {
  return randomBytes(32).toString('base64url');
}
