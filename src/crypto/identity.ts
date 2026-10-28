import { createHash as createDigest } from 'node:crypto';
import { calculateJwkThumbprint, importJWK, type CryptoKey, type JWK } from 'jose';
import { LicenseApiError } from '../errors.js';

export type PublicIdentityJwk = JWK & {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
};

export async function validateIdentityJwk(input: unknown): Promise<{ jwk: PublicIdentityJwk; jkt: string; key: CryptoKey }> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new LicenseApiError(400, 'INVALID_IDENTITY_KEY');
  const record = input as Record<string, unknown>;
  if (Object.keys(record).sort().join(',') !== 'crv,kty,x' || record['kty'] !== 'OKP' || record['crv'] !== 'Ed25519' || typeof record['x'] !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(record['x'])) {
    throw new LicenseApiError(400, 'INVALID_IDENTITY_KEY');
  }
  const jwk: PublicIdentityJwk = { kty: 'OKP', crv: 'Ed25519', x: record['x'] };
  try {
    const key = await importJWK(jwk, 'Ed25519') as CryptoKey;
    const jkt = await calculateJwkThumbprint(jwk, 'sha256');
    return { jwk, jkt, key };
  } catch {
    throw new LicenseApiError(400, 'INVALID_IDENTITY_KEY');
  }
}

export function validateActivationCode(code: unknown): string {
  if (typeof code !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(code)) throw new LicenseApiError(400, 'INVALID_ACTIVATION_CODE');
  const bytes = Buffer.from(code, 'base64url');
  if (bytes.byteLength !== 32 || bytes.toString('base64url') !== code) throw new LicenseApiError(400, 'INVALID_ACTIVATION_CODE');
  return createHash(code);
}

export function sha256Base64url(value: string | Uint8Array): string {
  return createHash(value);
}

function createHash(value: string | Uint8Array): string {
  return createDigest('sha256').update(value).digest('base64url');
}
