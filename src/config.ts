import { createPrivateKey } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { open, readFile, stat } from 'node:fs/promises';
import { createSecureContext } from 'node:tls';
import { calculateJwkThumbprint, importJWK, importPKCS8 } from 'jose';
import type { CryptoKey, JWK } from 'jose';
import type { TrustedOfflineRootPin } from './trust/trust-bundle.js';

export interface OnlineSigningKey {
  readonly kid: string;
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
  readonly publicJwk: JWK;
}

export interface RuntimeConfig {
  nodeEnv: 'development' | 'production';
  databaseUrl: string;
  issuer: string;
  publicOrigin: string;
  tlsKeyFile: string;
  tlsCertFile: string;
  tlsPrivateKey: Buffer;
  tlsCertificate: Buffer;
  port: number;
  listenHost: string;
  signingKeyring: ReadonlyMap<string, OnlineSigningKey>;
  trustedOfflineRoot: TrustedOfflineRootPin;
  minimumTrustBundleVersion: string;
}

export type SignerRuntimeConfig = Pick<RuntimeConfig,
  'nodeEnv' | 'issuer' | 'signingKeyring' | 'trustedOfflineRoot' | 'minimumTrustBundleVersion'>;

function required(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key]?.trim();
  if (!value) throw new Error(`Missing required configuration: ${key}`);
  return value;
}

function validateOrigin(value: string, field: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error(`${field} must be an https origin without path, query, credentials, or fragment`);
  }
  return parsed.origin;
}

async function readConfigFile(path: string, maxBytes: number): Promise<Buffer> {
  let handle;
  try {
    const noFollow = process.platform === 'win32' ? 0 : fsConstants.O_NOFOLLOW;
    handle = await open(path, fsConstants.O_RDONLY | noFollow);
    const info = await handle.stat();
    if (!info.isFile() || info.size > maxBytes || (process.platform !== 'win32' && info.nlink !== 1)) {
      throw new Error('Configuration file must be a bounded, single-link regular file');
    }
    return await handle.readFile();
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function parseStrictJson(bytes: Buffer, label: string): Record<string, unknown> {
  let value: unknown;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { throw new Error(`${label} is invalid JSON`); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be a JSON object`);
  return value as Record<string, unknown>;
}

async function loadRootPin(path: string): Promise<TrustedOfflineRootPin> {
  const bytes = await readConfigFile(path, 4096);
  const input = parseStrictJson(bytes, 'Offline root public key file');
  if (Object.keys(input).sort().join(',') !== 'crv,kty,x' || input['kty'] !== 'OKP' || input['crv'] !== 'Ed25519' ||
    typeof input['x'] !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input['x']) ||
    Buffer.from(input['x'], 'base64url').byteLength !== 32 || Buffer.from(input['x'], 'base64url').toString('base64url') !== input['x']) {
    throw new Error('Offline root pin must be a public Ed25519 JWK');
  }
  const publicJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: input['x'] };
  const kid = await calculateJwkThumbprint(publicJwk, 'sha256');
  await importJWK(publicJwk, 'Ed25519');
  return Object.freeze({ kid, publicJwk: Object.freeze(publicJwk) });
}

function privateFileModeIsAllowed(mode: number): boolean {
  const permissions = mode & 0o777;
  return (permissions === 0o400 || permissions === 0o600) && (mode & 0o7000) === 0;
}

async function loadOnlineSigningKey(kid: string, path: string): Promise<OnlineSigningKey> {
  let handle;
  try {
    const noFollow = process.platform === 'win32' ? 0 : fsConstants.O_NOFOLLOW;
    handle = await open(path, fsConstants.O_RDONLY | noFollow);
  } catch {
    throw new Error(`Unable to open configured online signing key ${kid}`);
  }
  let privateBytes: Buffer | undefined;
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size < 1 || info.size > 8192 ||
      (process.platform !== 'win32' && (info.nlink !== 1 || !privateFileModeIsAllowed(info.mode)))) {
      throw new Error(`Online signing key ${kid} must be an ordinary single-link 0400 or 0600 file`);
    }
    privateBytes = await handle.readFile();
    const privatePem = privateBytes.toString('utf8');
    if (!/^-----BEGIN PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PRIVATE KEY-----\r?\n?$/.test(privatePem)) {
      throw new Error(`Online signing key ${kid} must use PKCS#8 PEM`);
    }
    const nodePrivateKey = createPrivateKey(privatePem);
    if (nodePrivateKey.asymmetricKeyType !== 'ed25519') throw new Error(`Online signing key ${kid} is not Ed25519`);
    const exported = nodePrivateKey.export({ format: 'jwk' });
    if (exported.kty !== 'OKP' || exported.crv !== 'Ed25519' || typeof exported.x !== 'string' || typeof exported.d !== 'string') {
      throw new Error(`Online signing key ${kid} does not contain Ed25519 PKCS#8 material`);
    }
    const publicJwk: JWK = { kty: 'OKP', crv: 'Ed25519', x: exported.x };
    const actualKid = await calculateJwkThumbprint(publicJwk, 'sha256');
    if (actualKid !== kid) throw new Error(`Online signing key ${kid} does not match its declared JKT`);
    const privateKey = await importPKCS8(privatePem, 'Ed25519');
    const publicKey = await importJWK(publicJwk, 'Ed25519') as CryptoKey;
    return Object.freeze({ kid, privateKey, publicKey, publicJwk: Object.freeze(publicJwk) });
  } finally {
    privateBytes?.fill(0);
    await handle.close().catch(() => undefined);
  }
}

async function loadSigningKeyring(path: string): Promise<ReadonlyMap<string, OnlineSigningKey>> {
  const bytes = await readConfigFile(path, 16 * 1024);
  const input = parseStrictJson(bytes, 'Online signing keyring manifest');
  if (Object.keys(input).sort().join(',') !== 'keys,schema' || input['schema'] !== 1 || !Array.isArray(input['keys']) ||
    input['keys'].length < 1 || input['keys'].length > 32) {
    throw new Error('Online signing keyring manifest schema is invalid');
  }
  const ring = new Map<string, OnlineSigningKey>();
  for (const entry of input['keys']) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error('Online signing keyring entry is invalid');
    const row = entry as Record<string, unknown>;
    if (Object.keys(row).sort().join(',') !== 'kid,path' || typeof row['kid'] !== 'string' ||
      !/^[A-Za-z0-9_-]{43}$/.test(row['kid']) || typeof row['path'] !== 'string' || !row['path'].startsWith('/')) {
      throw new Error('Online signing keyring entry must contain an absolute PKCS#8 secret path and JKT');
    }
    if (ring.has(row['kid'])) throw new Error('Online signing keyring contains a duplicate kid');
    ring.set(row['kid'], await loadOnlineSigningKey(row['kid'], row['path']));
  }
  return ring;
}

export async function loadSignerRuntimeConfig(env: NodeJS.ProcessEnv = process.env): Promise<SignerRuntimeConfig> {
  const nodeEnv = env['NODE_ENV'] ?? 'development';
  if (nodeEnv !== 'development' && nodeEnv !== 'production') throw new Error('NODE_ENV must be development or production');
  const issuer = validateOrigin(required(env, 'LICENSE_ISSUER'), 'LICENSE_ISSUER');
  const signingKeyring = await loadSigningKeyring(required(env, 'LICENSE_SIGNING_KEYRING_FILE'));
  const trustedOfflineRoot = await loadRootPin(required(env, 'LICENSE_OFFLINE_ROOT_JWK_FILE'));
  const minimumTrustBundleVersion = required(env, 'LICENSE_TRUST_BUNDLE_MIN_VERSION');
  if (!/^[1-9][0-9]{0,18}$/.test(minimumTrustBundleVersion)) {
    throw new Error('LICENSE_TRUST_BUNDLE_MIN_VERSION must be a positive canonical integer');
  }
  return { nodeEnv, issuer, signingKeyring, trustedOfflineRoot, minimumTrustBundleVersion };
}

export async function loadConfig(env: NodeJS.ProcessEnv = process.env): Promise<RuntimeConfig> {
  const signing = await loadSignerRuntimeConfig(env);
  const { nodeEnv, issuer, signingKeyring, trustedOfflineRoot, minimumTrustBundleVersion } = signing;
  const databaseUrl = required(env, 'LICENSE_DATABASE_URL');
  const database = new URL(databaseUrl);
  if (!['postgres:', 'postgresql:'].includes(database.protocol)) throw new Error('LICENSE_DATABASE_URL must use PostgreSQL');
  const publicOrigin = validateOrigin(required(env, 'LICENSE_PUBLIC_ORIGIN'), 'LICENSE_PUBLIC_ORIGIN');
  if (issuer !== publicOrigin) throw new Error('LICENSE_ISSUER and LICENSE_PUBLIC_ORIGIN must match');
  const tlsKeyFile = required(env, 'LICENSE_TLS_KEY_FILE');
  const tlsCertFile = required(env, 'LICENSE_TLS_CERT_FILE');
  const tlsKeyStat = await stat(tlsKeyFile);
  const tlsCertStat = await stat(tlsCertFile);
  if (!tlsKeyStat.isFile() || !tlsCertStat.isFile()) throw new Error('TLS certificate and key must be regular files');
  if (process.platform !== 'win32' && (tlsKeyStat.mode & 0o077) !== 0) {
    throw new Error('TLS private key file permissions must be 0600 or stricter');
  }
  const tlsPrivateKey = await readFile(tlsKeyFile);
  const tlsCertificate = await readFile(tlsCertFile);
  if (tlsPrivateKey.byteLength > 32 * 1024 || tlsCertificate.byteLength > 64 * 1024) throw new Error('TLS files exceed the configured size limit');
  createSecureContext({ key: tlsPrivateKey, cert: tlsCertificate });
  const portText = env['LICENSE_HTTP_PORT'] ?? '4318';
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('LICENSE_HTTP_PORT must be a TCP port');
  const listenHost = env['LICENSE_LISTEN_HOST'] ?? '127.0.0.1';
  const isolatedCompose = env['LICENSE_ISOLATED_CONTAINER'] === 'compose';
  if (!['127.0.0.1', '::1', '0.0.0.0'].includes(listenHost) ||
    (listenHost === '0.0.0.0' && (nodeEnv !== 'development' || !isolatedCompose))) {
    throw new Error('LICENSE_LISTEN_HOST must stay on loopback except inside isolated local Compose');
  }
  return {
    nodeEnv, databaseUrl, issuer, publicOrigin, tlsKeyFile, tlsCertFile, tlsPrivateKey, tlsCertificate,
    port, listenHost, signingKeyring, trustedOfflineRoot, minimumTrustBundleVersion,
  };
}
