import { randomBytes } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import {
  calculateJwkThumbprint,
  exportJWK,
  exportPKCS8,
  generateKeyPair,
  importJWK,
  type CryptoKey,
  type JWK,
} from 'jose';
import type { RuntimeConfig } from '../../src/config.js';

const execFile = promisify(execFileCallback);

export interface TestIdentity {
  privateKey: CryptoKey;
  privateJwk: JWK;
  publicKey: CryptoKey;
  publicJwk: { kty: 'OKP'; crv: 'Ed25519'; x: string };
  jkt: string;
}

export interface TestSigningRuntime {
  config: RuntimeConfig;
  privatePem: string;
  cleanup(): Promise<void>;
}

export async function createTestSigningRuntime(): Promise<TestSigningRuntime> {
  const pair = await generateKeyPair('Ed25519', { extractable: true });
  const exportedPublic = await exportJWK(pair.publicKey);
  const publicJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: exportedPublic.x! };
  const signingKeyId = await calculateJwkThumbprint(publicJwk, 'sha256');
  const directory = await mkdtemp(join(tmpdir(), 'aikayun-license-tls-'));
  const tlsKeyFile = join(directory, 'tls-key.pem');
  const tlsCertFile = join(directory, 'tls-cert.pem');
  await execFile('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=license.example.test', '-addext', 'subjectAltName=DNS:license.example.test',
    '-keyout', tlsKeyFile, '-out', tlsCertFile,
  ]);
  await chmod(tlsKeyFile, 0o600);
  const config: RuntimeConfig = {
    nodeEnv: 'development',
    databaseUrl: process.env['LICENSE_TEST_DATABASE_URL'] ?? 'postgres://license:license-dev-only@127.0.0.1:55432/license_center_test',
    issuer: 'https://license.example.test',
    publicOrigin: 'https://license.example.test',
    tlsKeyFile,
    tlsCertFile,
    tlsPrivateKey: await readFile(tlsKeyFile),
    tlsCertificate: await readFile(tlsCertFile),
    port: 4318,
    listenHost: '127.0.0.1',
    signingPrivateKey: pair.privateKey,
    signingPublicKey: pair.publicKey,
    signingPublicJwk: publicJwk,
    signingKeyId,
  };
  return { config, privatePem: await exportPKCS8(pair.privateKey), cleanup: () => rm(directory, { recursive: true, force: true }) };
}

export async function createIdentity(): Promise<TestIdentity> {
  const pair = await generateKeyPair('Ed25519', { extractable: true });
  const privateJwk = await exportJWK(pair.privateKey);
  const publicJwkRaw = await exportJWK(pair.publicKey);
  const publicJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: publicJwkRaw.x! };
  const jkt = await calculateJwkThumbprint(publicJwk, 'sha256');
  return { privateKey: pair.privateKey, privateJwk, publicKey: pair.publicKey, publicJwk, jkt };
}

export function newClientNonce(): string {
  return randomBytes(32).toString('base64url');
}
