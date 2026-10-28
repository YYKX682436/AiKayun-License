import { readFile, stat } from 'node:fs/promises';
import { createPublicKey } from 'node:crypto';
import { createSecureContext } from 'node:tls';
import { importJWK, importPKCS8, calculateJwkThumbprint } from 'jose';
import type { CryptoKey, JWK } from 'jose';

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
  signingPrivateKey: CryptoKey;
  signingPublicKey: CryptoKey;
  signingPublicJwk: JWK;
  signingKeyId: string;
}

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

export async function loadConfig(env: NodeJS.ProcessEnv = process.env): Promise<RuntimeConfig> {
  const nodeEnv = env['NODE_ENV'] ?? 'development';
  if (nodeEnv !== 'development' && nodeEnv !== 'production') throw new Error('NODE_ENV must be development or production');
  const databaseUrl = required(env, 'LICENSE_DATABASE_URL');
  const database = new URL(databaseUrl);
  if (!['postgres:', 'postgresql:'].includes(database.protocol)) throw new Error('LICENSE_DATABASE_URL must use PostgreSQL');
  const issuer = validateOrigin(required(env, 'LICENSE_ISSUER'), 'LICENSE_ISSUER');
  const publicOrigin = validateOrigin(required(env, 'LICENSE_PUBLIC_ORIGIN'), 'LICENSE_PUBLIC_ORIGIN');
  if (issuer !== publicOrigin) throw new Error('LICENSE_ISSUER and LICENSE_PUBLIC_ORIGIN must match');
  const keyPath = required(env, 'LICENSE_SIGNING_KEY_FILE');
  const keyStat = await stat(keyPath);
  if (!keyStat.isFile()) throw new Error('LICENSE_SIGNING_KEY_FILE must be a regular file');
  if (process.platform !== 'win32' && (keyStat.mode & 0o077) !== 0) {
    throw new Error('Signing private key file permissions must be 0600 or stricter');
  }
  const privatePem = await readFile(keyPath, 'utf8');
  if (Buffer.byteLength(privatePem, 'utf8') > 8192) throw new Error('Signing private key file is too large');
  const signingPrivateKey = await importPKCS8(privatePem, 'Ed25519');
  const exported = createPublicKey(privatePem).export({ format: 'jwk' });
  if (exported.kty !== 'OKP' || exported.crv !== 'Ed25519' || typeof exported.x !== 'string') {
    throw new Error('Configured signing key must be Ed25519');
  }
  const signingPublicJwk: JWK = { kty: 'OKP', crv: 'Ed25519', x: exported.x };
  const signingPublicKey = await importJWK(signingPublicJwk, 'Ed25519') as CryptoKey;
  const signingKeyId = await calculateJwkThumbprint(signingPublicJwk, 'sha256');
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
    port, listenHost, signingPrivateKey, signingPublicKey, signingPublicJwk, signingKeyId,
  };
}
