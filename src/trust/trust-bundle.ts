import { createHash } from 'node:crypto';
import { calculateJwkThumbprint, compactVerify, importJWK } from 'jose';
import type { CryptoKey, JWK } from 'jose';
import { parseStrictJsonSegment } from '../strict-json.js';

export const TRUST_BUNDLE_TYP = 'aikayun-license-trust-bundle+jwt';
export const TRUST_BUNDLE_AUDIENCE = 'aikayun-license-signing-keys';
export const OFFLINE_ROOT_ISSUER = 'urn:aikayun:license:offline-release-root:v1';
export const TRUST_BUNDLE_SCHEMA = 1;
export const MAX_TRUST_BUNDLE_BYTES = 16 * 1024;
export const MAX_TRUST_BUNDLE_KEYS = 32;
export const MAX_TRUSTED_KEY_TOMBSTONES = 256;
export const MAX_BUNDLE_LIFETIME_SECONDS = 90 * 24 * 60 * 60;
export const MIN_KEY_RETIREMENT_RETENTION_SECONDS = 7 * 24 * 60 * 60;

export const CENTER_JWT_AUDIENCE_BY_TYP = Object.freeze({
  'aikayun-license+jwt': 'aikayun-commerce',
  'aikayun-license-status+jwt': 'aikayun-commerce',
  'aikayun-license-operation+jwt': 'aikayun-commerce',
  'aikayun-license-challenge+jwt': 'aikayun-commerce',
  'aikayun-license-transfer-ticket+jwt': 'aikayun-commerce',
  'aikayun-license-transfer+jwt': 'aikayun-commerce',
  'aikayun-license-disaster-transfer-ticket+jwt': 'aikayun-commerce',
  'aikayun-license-disaster-transfer+jwt': 'aikayun-commerce',
  'aikayun-license-disaster-binding+jwt': 'aikayun-commerce',
  'aikayun-time-anchor+jwt': 'aikayun-time-bootstrap',
  'aikayun-time-reset+jwt': 'aikayun-time-recovery',
} as const);

const HEADER_FIELDS = ['alg', 'kid', 'typ'] as const;
const CLAIM_FIELDS = [
  'iss', 'aud', 'sub', 'bundle_schema', 'bundle_version', 'iat', 'nbf', 'exp',
  'propagation_budget_seconds', 'keys',
] as const;
const KEY_FIELDS = [
  'kid', 'alg', 'kty', 'crv', 'x', 'not_before', 'retire_after', 'verify_until', 'revoked_at',
] as const;
const versionPattern = /^[1-9][0-9]{0,18}$/;
const base64url32Pattern = /^[A-Za-z0-9_-]{43}$/;

export interface Ed25519PublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
}

export interface TrustBundleKeyRecord extends Ed25519PublicJwk {
  kid: string;
  alg: 'Ed25519';
  not_before: number;
  retire_after: number | null;
  verify_until: number | null;
  revoked_at: number | null;
}

export interface TrustBundleClaims {
  iss: typeof OFFLINE_ROOT_ISSUER;
  aud: typeof TRUST_BUNDLE_AUDIENCE;
  sub: string;
  bundle_schema: typeof TRUST_BUNDLE_SCHEMA;
  bundle_version: string;
  iat: number;
  nbf: number;
  exp: number;
  propagation_budget_seconds: number;
  keys: TrustBundleKeyRecord[];
}

export interface TrustedOfflineRootPin {
  /** Public JWK provisioned by the signed application/release artifact. Never read from the bundle. */
  publicJwk: Ed25519PublicJwk;
  kid: string;
}

export interface TrustBundleSigningInput {
  bundle_version: string;
  iat: number;
  nbf: number;
  exp: number;
  propagation_budget_seconds: number;
  keys: unknown;
}

const rootAuthenticatedBrand: unique symbol = Symbol('root-authenticated-trust-bundle');
export interface RootAuthenticatedTrustBundleCandidate {
  readonly [rootAuthenticatedBrand]: true;
  readonly token: string;
  readonly artifactSha256: string;
  readonly rootKid: string;
  readonly claims: Readonly<TrustBundleClaims>;
}

export interface TrustBundleSigningPreview {
  rootKid: string;
  bundleVersion: string;
  centerIssuer: string;
  issuedAt: number;
  notBefore: number;
  expiresAt: number;
  propagationBudgetSeconds: number;
  keys: TrustBundleKeyRecord[];
  payloadSha256: string;
  signingInputSha256: string;
}

const candidateKeys = new WeakMap<object, Map<string, CryptoKey>>();

function canonicalCenterIssuer(value: unknown): string {
  if (typeof value !== 'string' || value.length > 256) throw new Error('Invalid expected center issuer');
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error('Invalid expected center issuer'); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash || value !== parsed.origin) {
    throw new Error('Expected center issuer must be an exact HTTPS origin');
  }
  return value;
}

function isCanonicalBase64Url32(value: unknown): value is string {
  return typeof value === 'string' && base64url32Pattern.test(value) &&
    Buffer.from(value, 'base64url').byteLength === 32 && Buffer.from(value, 'base64url').toString('base64url') === value;
}

function assertExactFields(value: Record<string, unknown>, fields: readonly string[], label: string): void {
  if (Object.keys(value).sort().join('\n') !== [...fields].sort().join('\n')) throw new Error(`Unexpected ${label} fields`);
}

function assertInteger(value: unknown, label: string, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) throw new Error(`Invalid ${label}`);
  return value;
}

function assertVersion(value: unknown): string {
  if (typeof value !== 'string' || !versionPattern.test(value)) throw new Error('bundle_version must be a positive decimal string');
  return value;
}

function sha256Base64url(value: Uint8Array | string): string {
  return createHash('sha256').update(value).digest('base64url');
}

async function validateRootPin(pin: TrustedOfflineRootPin): Promise<{ kid: string; publicKey: CryptoKey }> {
  assertExactFields(pin as unknown as Record<string, unknown>, ['kid', 'publicJwk'], 'offline root pin');
  assertExactFields(pin.publicJwk as unknown as Record<string, unknown>, ['kty', 'crv', 'x'], 'offline root JWK');
  const jwk = pin.publicJwk;
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !isCanonicalBase64Url32(jwk.x)) throw new Error('Invalid preconfigured offline root public key');
  const kid = await calculateJwkThumbprint(jwk as JWK, 'sha256');
  if (pin.kid !== kid) throw new Error('Preconfigured offline root kid does not match its JWK thumbprint');
  return { kid, publicKey: await importJWK(jwk as JWK, 'Ed25519') as CryptoKey };
}

async function validateKeyRecords(
  value: unknown,
  input: { propagationBudgetSeconds: number; bundleIat: number; rootKid?: string },
): Promise<{ records: TrustBundleKeyRecord[]; keys: Map<string, CryptoKey> }> {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_TRUST_BUNDLE_KEYS) throw new Error('Invalid trust bundle key count');
  const seenKids = new Set<string>();
  const seenPublicKeys = new Set<string>();
  const records: TrustBundleKeyRecord[] = [];
  const keys = new Map<string, CryptoKey>();

  for (const raw of value) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Invalid trust bundle key entry');
    const row = raw as Record<string, unknown>;
    assertExactFields(row, KEY_FIELDS, 'trust bundle key');
    if (row['alg'] !== 'Ed25519' || row['kty'] !== 'OKP' || row['crv'] !== 'Ed25519' || !isCanonicalBase64Url32(row['x'])) {
      throw new Error('Trust bundle keys must be canonical public OKP Ed25519 JWKs');
    }
    const publicJwk: Ed25519PublicJwk = { kty: 'OKP', crv: 'Ed25519', x: row['x'] };
    const kid = await calculateJwkThumbprint(publicJwk as JWK, 'sha256');
    if (row['kid'] !== kid || (input.rootKid !== undefined && kid === input.rootKid)) throw new Error('Trust bundle key kid is not its JWK thumbprint or aliases the offline root');
    if (seenKids.has(kid) || seenPublicKeys.has(publicJwk.x)) throw new Error('Duplicate or conflicting trust bundle key identity');
    seenKids.add(kid);
    seenPublicKeys.add(publicJwk.x);

    const notBefore = assertInteger(row['not_before'], 'key not_before', 1);
    const retireAfter = row['retire_after'] === null ? null : assertInteger(row['retire_after'], 'key retire_after', 1);
    const verifyUntil = row['verify_until'] === null ? null : assertInteger(row['verify_until'], 'key verify_until', 1);
    const revokedAt = row['revoked_at'] === null ? null : assertInteger(row['revoked_at'], 'key revoked_at', 1);
    if (retireAfter === null ? verifyUntil !== null :
      verifyUntil === null || retireAfter < notBefore ||
      BigInt(verifyUntil) < BigInt(retireAfter) + BigInt(MIN_KEY_RETIREMENT_RETENTION_SECONDS) + BigInt(input.propagationBudgetSeconds)) {
      throw new Error('Invalid key retirement or verification window');
    }
    if (revokedAt !== null && revokedAt > input.bundleIat) throw new Error('Key revocation cannot be future-dated');

    const record: TrustBundleKeyRecord = {
      kid, alg: 'Ed25519', kty: 'OKP', crv: 'Ed25519', x: publicJwk.x,
      not_before: notBefore, retire_after: retireAfter, verify_until: verifyUntil, revoked_at: revokedAt,
    };
    records.push(record);
    try {
      keys.set(kid, await importJWK(publicJwk as JWK, 'Ed25519') as CryptoKey);
    } catch {
      throw new Error('Trust bundle contains an invalid Ed25519 public key');
    }
  }
  return { records, keys };
}

async function validateClaims(value: unknown, expectedCenterIssuer: string, rootKid?: string): Promise<{
  claims: TrustBundleClaims;
  keys: Map<string, CryptoKey>;
}> {
  const issuer = canonicalCenterIssuer(expectedCenterIssuer);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid trust bundle payload');
  const payload = value as Record<string, unknown>;
  assertExactFields(payload, CLAIM_FIELDS, 'trust bundle claim set');
  const bundleIat = assertInteger(payload['iat'], 'bundle iat', 1);
  const notBefore = assertInteger(payload['nbf'], 'bundle nbf', 1);
  const expiresAt = assertInteger(payload['exp'], 'bundle exp', 1);
  const propagationBudgetSeconds = assertInteger(payload['propagation_budget_seconds'], 'publication propagation budget', 1);
  if (propagationBudgetSeconds > MAX_BUNDLE_LIFETIME_SECONDS || payload['bundle_schema'] !== TRUST_BUNDLE_SCHEMA ||
    payload['iss'] !== OFFLINE_ROOT_ISSUER || payload['aud'] !== TRUST_BUNDLE_AUDIENCE || payload['sub'] !== issuer ||
    bundleIat > notBefore || notBefore >= expiresAt || expiresAt - bundleIat > MAX_BUNDLE_LIFETIME_SECONDS) {
    throw new Error('Invalid trust bundle issuer, audience, schema, or validity window');
  }
  const bundleVersion = assertVersion(payload['bundle_version']);
  const validatedKeys = await validateKeyRecords(payload['keys'], { propagationBudgetSeconds, bundleIat, ...(rootKid === undefined ? {} : { rootKid }) });
  return {
    claims: {
      iss: OFFLINE_ROOT_ISSUER,
      aud: TRUST_BUNDLE_AUDIENCE,
      sub: issuer,
      bundle_schema: TRUST_BUNDLE_SCHEMA,
      bundle_version: bundleVersion,
      iat: bundleIat,
      nbf: notBefore,
      exp: expiresAt,
      propagation_budget_seconds: propagationBudgetSeconds,
      keys: validatedKeys.records,
    },
    keys: validatedKeys.keys,
  };
}

/** Shared strict claim validator; private-key operations live only under tools/offline-trust. */
export async function validateTrustBundleClaimsForSigning(
  claims: unknown,
  expectedCenterIssuer: string,
  rootKid?: string,
): Promise<TrustBundleClaims> {
  return (await validateClaims(claims, expectedCenterIssuer, rootKid)).claims;
}

function validateCompactJws(token: unknown): { segments: [string, string, string]; header: Record<string, unknown>; payload: Record<string, unknown> } {
  if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') > MAX_TRUST_BUNDLE_BYTES) throw new Error('Trust bundle JWS exceeds size limit');
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((part) => part.length > 0)) throw new Error('Invalid compact trust bundle JWS');
  const [protectedSegment, payloadSegment, signatureSegment] = parts as [string, string, string];
  const header = parseStrictJsonSegment(protectedSegment);
  const payload = parseStrictJsonSegment(payloadSegment);
  if (!/^[A-Za-z0-9_-]+$/.test(signatureSegment) || Buffer.from(signatureSegment, 'base64url').toString('base64url') !== signatureSegment) {
    throw new Error('Invalid compact trust bundle signature encoding');
  }
  assertExactFields(header, HEADER_FIELDS, 'trust bundle protected header');
  if (header['alg'] !== 'Ed25519' || header['typ'] !== TRUST_BUNDLE_TYP || typeof header['kid'] !== 'string' || !isCanonicalBase64Url32(header['kid'])) {
    throw new Error('Unexpected trust bundle protected header');
  }
  return { segments: [protectedSegment, payloadSegment, signatureSegment], header, payload };
}

export async function verifyTrustBundleSignature(
  token: unknown,
  input: { trustedRoot: TrustedOfflineRootPin; expectedCenterIssuer: string },
): Promise<RootAuthenticatedTrustBundleCandidate> {
  const root = await validateRootPin(input.trustedRoot);
  const jws = validateCompactJws(token);
  if (jws.header['kid'] !== root.kid) throw new Error('Trust bundle root kid is not preconfigured');
  const { claims, keys } = await validateClaims(jws.payload, input.expectedCenterIssuer, root.kid);
  const result = await compactVerify(token as string, root.publicKey, { algorithms: ['Ed25519'] });
  if (result.protectedHeader['alg'] !== 'Ed25519' || result.protectedHeader['kid'] !== root.kid || result.protectedHeader['typ'] !== TRUST_BUNDLE_TYP) {
    throw new Error('Trust bundle root signature header mismatch');
  }
  const immutableClaims = Object.freeze({
    ...claims,
    keys: Object.freeze(claims.keys.map((entry) => Object.freeze({ ...entry }))) as unknown as TrustBundleKeyRecord[],
  });
  const candidate = Object.freeze({
    [rootAuthenticatedBrand]: true as const,
    token: token as string,
    artifactSha256: sha256Base64url(token as string),
    rootKid: root.kid,
    claims: immutableClaims,
  }) as RootAuthenticatedTrustBundleCandidate;
  candidateKeys.set(candidate as object, keys);
  return candidate;
}

export function assertRootAuthenticatedCandidate(candidate: RootAuthenticatedTrustBundleCandidate): void {
  if (!candidate || typeof candidate !== 'object' || !candidateKeys.has(candidate as object)) throw new Error('Trust bundle is not root-authenticated in this process');
}

export function assertTrustBundleValidAt(candidate: RootAuthenticatedTrustBundleCandidate, trustedTime: number): void {
  assertRootAuthenticatedCandidate(candidate);
  const now = assertInteger(trustedTime, 'trusted time', 1);
  const claims = candidate.claims;
  if (claims.iat > now || claims.nbf > now || now >= claims.exp) throw new Error('Trust bundle is not valid at the supplied trusted time');
}

export function getRootAuthenticatedCandidateKey(
  candidate: RootAuthenticatedTrustBundleCandidate,
  kid: string,
): { record: TrustBundleKeyRecord; publicKey: CryptoKey } {
  assertRootAuthenticatedCandidate(candidate);
  if (!isCanonicalBase64Url32(kid)) throw new Error('Invalid center signing key id');
  const record = candidate.claims.keys.find((entry) => entry.kid === kid);
  const publicKey = candidateKeys.get(candidate as object)?.get(kid);
  if (!record || !publicKey) throw new Error('Center signing key is absent from root-authenticated trust bundle');
  return { record, publicKey };
}

export function compareBundleVersions(left: string, right: string): number {
  const a = BigInt(assertVersion(left));
  const b = BigInt(assertVersion(right));
  return a < b ? -1 : a > b ? 1 : 0;
}

export function assertMinimumBundleVersion(value: unknown): string {
  return assertVersion(value);
}

export function trustBundleArtifactDigest(token: string): string {
  return sha256Base64url(token);
}

export function trustBundleKeyAudience(jwtTyp: string): string {
  if (!(jwtTyp in CENTER_JWT_AUDIENCE_BY_TYP)) throw new Error('Unsupported center JWT purpose');
  return CENTER_JWT_AUDIENCE_BY_TYP[jwtTyp as keyof typeof CENTER_JWT_AUDIENCE_BY_TYP];
}
