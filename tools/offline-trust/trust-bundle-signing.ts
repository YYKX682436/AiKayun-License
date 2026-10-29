import { createHash } from 'node:crypto';
import { CompactSign, calculateJwkThumbprint, compactVerify, importJWK } from 'jose';
import type { CryptoKey, JWK } from 'jose';
import canonicalize from 'canonicalize';
import {
  MAX_TRUST_BUNDLE_BYTES,
  OFFLINE_ROOT_ISSUER,
  TRUST_BUNDLE_AUDIENCE,
  TRUST_BUNDLE_SCHEMA,
  TRUST_BUNDLE_TYP,
  validateTrustBundleClaimsForSigning,
} from '../../src/trust/trust-bundle.js';
import type {
  Ed25519PublicJwk,
  TrustBundleSigningInput,
  TrustBundleSigningPreview,
  TrustBundleClaims,
} from '../../src/trust/trust-bundle.js';

function sha256Hex(value: Uint8Array | string): string {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalPayloadBytes(claims: TrustBundleClaims): Buffer {
  const canonical = canonicalize(claims);
  if (typeof canonical !== 'string') throw new Error('Unable to serialize trust bundle payload');
  return Buffer.from(canonical, 'utf8');
}

export async function buildTrustBundleClaims(
  expectedCenterIssuer: string,
  input: TrustBundleSigningInput,
  rootPublicJwk?: Ed25519PublicJwk,
): Promise<TrustBundleClaims> {
  const payload = {
    iss: OFFLINE_ROOT_ISSUER,
    aud: TRUST_BUNDLE_AUDIENCE,
    sub: expectedCenterIssuer,
    bundle_schema: TRUST_BUNDLE_SCHEMA,
    bundle_version: input.bundle_version,
    iat: input.iat,
    nbf: input.nbf,
    exp: input.exp,
    propagation_budget_seconds: input.propagation_budget_seconds,
    keys: input.keys,
  };
  const rootKid = rootPublicJwk ? await calculateJwkThumbprint(rootPublicJwk as JWK, 'sha256') : undefined;
  return validateTrustBundleClaimsForSigning(payload, expectedCenterIssuer, rootKid);
}

export async function previewTrustBundleSigning(
  claims: TrustBundleClaims,
  rootPublicJwk: Ed25519PublicJwk,
): Promise<TrustBundleSigningPreview> {
  if (Object.keys(rootPublicJwk).sort().join(',') !== 'crv,kty,x' || rootPublicJwk.kty !== 'OKP' ||
    rootPublicJwk.crv !== 'Ed25519' || !/^[A-Za-z0-9_-]{43}$/.test(rootPublicJwk.x) ||
    Buffer.from(rootPublicJwk.x, 'base64url').byteLength !== 32 ||
    Buffer.from(rootPublicJwk.x, 'base64url').toString('base64url') !== rootPublicJwk.x) {
    throw new Error('Invalid offline root public JWK');
  }
  const kid = await calculateJwkThumbprint(rootPublicJwk as JWK, 'sha256');
  const validated = await validateTrustBundleClaimsForSigning(claims, claims.sub, kid);
  if (validated.sub !== claims.sub || validated.iss !== OFFLINE_ROOT_ISSUER) throw new Error('Invalid signing claims');
  const header = { alg: 'Ed25519', kid, typ: TRUST_BUNDLE_TYP };
  const protectedSegment = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const payloadBytes = canonicalPayloadBytes(validated);
  const payloadSegment = payloadBytes.toString('base64url');
  if (Buffer.byteLength(`${protectedSegment}.${payloadSegment}.${'A'.repeat(86)}`, 'utf8') > MAX_TRUST_BUNDLE_BYTES) {
    throw new Error('Trust bundle signing input exceeds the JWS size limit');
  }
  return {
    rootKid: kid,
    bundleVersion: validated.bundle_version,
    centerIssuer: validated.sub,
    issuedAt: validated.iat,
    notBefore: validated.nbf,
    expiresAt: validated.exp,
    propagationBudgetSeconds: validated.propagation_budget_seconds,
    keys: validated.keys.map((entry) => ({ ...entry })),
    payloadSha256: sha256Hex(payloadBytes),
    signingInputSha256: sha256Hex(`${protectedSegment}.${payloadSegment}`),
  };
}

export async function signTrustBundle(
  claims: TrustBundleClaims,
  rootPrivateKey: CryptoKey,
  rootPublicJwk: Ed25519PublicJwk,
): Promise<{ token: string; preview: TrustBundleSigningPreview }> {
  const preview = await previewTrustBundleSigning(claims, rootPublicJwk);
  const safeClaims = await validateTrustBundleClaimsForSigning(claims, claims.sub, preview.rootKid);
  const payload = canonicalPayloadBytes(safeClaims);
  const token = await new CompactSign(payload)
    .setProtectedHeader({ alg: 'Ed25519', kid: preview.rootKid, typ: TRUST_BUNDLE_TYP })
    .sign(rootPrivateKey);
  if (Buffer.byteLength(token, 'utf8') > MAX_TRUST_BUNDLE_BYTES || token.split('.').length !== 3) throw new Error('Signed trust bundle exceeds size limit');
  await compactVerify(token, await importJWK(rootPublicJwk as JWK, 'Ed25519') as CryptoKey, { algorithms: ['Ed25519'] });
  const inputDigest = sha256Hex(token.split('.').slice(0, 2).join('.'));
  if (inputDigest !== preview.signingInputSha256) throw new Error('JOSE protected header serialization did not match the reviewed signing digest');
  return { token, preview };
}
