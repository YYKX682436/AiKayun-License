import { SignJWT, compactVerify } from 'jose';
import type { CryptoKey } from 'jose';
import { parseStrictJsonSegment } from '../strict-json.js';
import type { SigningContext, VerificationContext } from './signing-types.js';

const MAX_TOKEN_BYTES = 16 * 1024;
const LICENSE_HEADER = ['alg', 'kid', 'typ'];

export interface VerifiedJwt {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
}

export interface TrustedSigningKeyResolver {
  resolveKey(input: {
    kid: string;
    targetIssuer: string;
    jwtTyp: string;
    audience: string;
    trustedTime: number;
    issuedAt: number;
    expiresAt: number;
  }): Promise<{ publicKey: CryptoKey; verifyUntil: number | null }>;
}

export async function signTypedJwt(
  signer: SigningContext,
  typ: string,
  claims: Record<string, unknown>,
  options: { allowExpiredTestToken?: boolean } = {},
): Promise<string> {
  await signer.assertIssuanceAllowed(claims, options);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'Ed25519', kid: signer.kid, typ })
    .sign(signer.privateKey);
}

type TypedJwtVerificationInput = VerificationContext & {
    typ: string;
    requiredClaims: readonly string[];
    audience: string;
    now: Date;
    allowExpired?: boolean;
  };

export async function verifyTypedJwt(token: unknown, input: TypedJwtVerificationInput): Promise<VerifiedJwt>;
export async function verifyTypedJwt(
  token: unknown,
  context: VerificationContext,
  typ: string,
  requiredClaims: readonly string[],
  now: Date,
  allowExpired?: boolean,
): Promise<VerifiedJwt>;
export async function verifyTypedJwt(
  token: unknown,
  input: TypedJwtVerificationInput | VerificationContext,
  typ?: string,
  requiredClaims?: readonly string[],
  now?: Date,
  allowExpired?: boolean,
): Promise<VerifiedJwt> {
  const normalized: TypedJwtVerificationInput = 'typ' in input
    ? input
    : {
      ...input,
      typ: typ!,
      requiredClaims: requiredClaims!,
      audience: typ === 'aikayun-license-time-reset+jwt' ? 'aikayun-license-time-reset' : 'aikayun-commerce',
      now: now!,
      ...(allowExpired ? { allowExpired: true } : {}),
    };
  return verifyTypedJwtWithResolver(token, normalized);
}

async function parseTypedJwt(
  token: unknown,
  typ: string,
  requiredClaims: readonly string[],
  expectedKid?: string,
): Promise<{ token: string; header: Record<string, unknown>; claims: Record<string, unknown> }> {
  if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) throw new Error('Invalid signed token');
  const segments = token.split('.');
  if (segments.length !== 3 || !segments.every((part) => part.length > 0)) throw new Error('Invalid compact JWS');
  const header = parseStrictJsonSegment(segments[0]!);
  const claims = parseStrictJsonSegment(segments[1]!);
  const signature = segments[2]!;
  if (!/^[A-Za-z0-9_-]+$/.test(signature) || Buffer.from(signature, 'base64url').toString('base64url') !== signature) {
    throw new Error('Invalid compact JWS signature encoding');
  }
  if (Object.keys(header).sort().join(',') !== LICENSE_HEADER.join(',')) throw new Error('Unexpected protected JWS header');
  if (header['alg'] !== 'Ed25519' || header['typ'] !== typ || typeof header['kid'] !== 'string' ||
    (expectedKid !== undefined && header['kid'] !== expectedKid)) throw new Error('Unexpected protected JWS header');
  for (const name of requiredClaims) if (!(name in claims)) throw new Error('Required signed claim missing');
  return { token, header, claims };
}

export async function verifyTypedJwtWithKey(
  token: unknown,
  input: {
    publicKey: CryptoKey;
    keyId: string;
    issuer: string;
    audience: string;
    typ: string;
    requiredClaims: readonly string[];
    now: Date;
    allowExpired?: boolean;
  },
): Promise<VerifiedJwt> {
  const parsed = await parseTypedJwt(token, input.typ, input.requiredClaims, input.keyId);
  const verified = await compactVerify(parsed.token, input.publicKey, { algorithms: ['Ed25519'] });
  if (verified.protectedHeader['alg'] !== 'Ed25519' || verified.protectedHeader['kid'] !== input.keyId || verified.protectedHeader['typ'] !== input.typ) {
    throw new Error('Unexpected protected JWS header');
  }
  const nowSeconds = Math.floor(input.now.getTime() / 1000);
  const claims = parsed.claims;
  const issuedAt = claims['iat'];
  const notBefore = claims['nbf'];
  const expiresAt = claims['exp'];
  if (claims['iss'] !== input.issuer || claims['aud'] !== input.audience ||
    typeof issuedAt !== 'number' || !Number.isSafeInteger(issuedAt) || issuedAt <= 0 || issuedAt > nowSeconds ||
    typeof notBefore !== 'number' || !Number.isSafeInteger(notBefore) || notBefore > nowSeconds ||
    typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt) || expiresAt <= issuedAt ||
    (!input.allowExpired && expiresAt <= nowSeconds)) {
    throw new Error('Signed token issuer, audience, or time claims are invalid');
  }
  return { header: parsed.header, claims: parsed.claims };
}

export async function verifyTypedJwtWithResolver(
  token: unknown,
  input: {
    resolver: TrustedSigningKeyResolver;
    issuer: string;
    audience: string;
    typ: string;
    requiredClaims: readonly string[];
    now: Date;
    allowExpired?: boolean;
  },
): Promise<VerifiedJwt> {
  const parsed = await parseTypedJwt(token, input.typ, input.requiredClaims);
  if (parsed.claims['iss'] !== input.issuer || parsed.claims['aud'] !== input.audience) throw new Error('Unexpected signed token issuer or audience');
  const issuedAt = parsed.claims['iat'];
  const expiresAt = parsed.claims['exp'];
  if (typeof issuedAt !== 'number' || !Number.isSafeInteger(issuedAt) || issuedAt <= 0 ||
    typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt) || expiresAt <= issuedAt) {
    throw new Error('Invalid signed token key-selection time');
  }
  const kid = parsed.header['kid'];
  if (typeof kid !== 'string') throw new Error('Invalid signed token key id');
  const trustedTime = Math.floor(input.now.getTime() / 1000);
  if (!Number.isSafeInteger(trustedTime) || trustedTime <= 0) throw new Error('Invalid trusted verification time');
  const selected = await input.resolver.resolveKey({
    kid,
    targetIssuer: input.issuer,
    jwtTyp: input.typ,
    audience: input.audience,
    trustedTime,
    issuedAt,
    expiresAt,
  });
  const verified = await verifyTypedJwtWithKey(token, {
    publicKey: selected.publicKey,
    keyId: kid,
    issuer: input.issuer,
    audience: input.audience,
    typ: input.typ,
    requiredClaims: input.requiredClaims,
    now: input.now,
    ...(input.allowExpired ? { allowExpired: true } : {}),
  });
  if (selected.verifyUntil !== null && (trustedTime >= selected.verifyUntil || expiresAt > selected.verifyUntil)) {
    throw new Error('Signed token exceeds its trusted key verification window');
  }
  return verified;
}

export function assertExactClaims(claims: Record<string, unknown>, names: readonly string[]): void {
  if (Object.keys(claims).sort().join('\n') !== [...names].sort().join('\n')) throw new Error('Unexpected signed claim set');
}

export function assertIntegerClaim(claims: Record<string, unknown>, name: string, minimum = 0): number {
  const value = claims[name];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) throw new Error('Invalid signed integer claim');
  return Number(value);
}

export function assertStringClaim(claims: Record<string, unknown>, name: string, maxLength = 1024): string {
  const value = claims[name];
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) throw new Error('Invalid signed string claim');
  return value;
}
