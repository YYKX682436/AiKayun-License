import { SignJWT, jwtVerify } from 'jose';
import type { RuntimeConfig } from '../config.js';
import { parseStrictJsonSegment } from '../strict-json.js';

const MAX_TOKEN_BYTES = 16 * 1024;
const LICENSE_HEADER = ['alg', 'kid', 'typ'];

export interface VerifiedJwt {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
}

export async function signTypedJwt(
  config: RuntimeConfig,
  typ: string,
  claims: Record<string, unknown>,
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'Ed25519', kid: config.signingKeyId, typ })
    .sign(config.signingPrivateKey);
}

export async function verifyTypedJwt(
  token: unknown,
  config: RuntimeConfig,
  typ: string,
  requiredClaims: string[],
  now: Date,
): Promise<VerifiedJwt> {
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
  if (header['alg'] !== 'Ed25519' || header['kid'] !== config.signingKeyId || header['typ'] !== typ) throw new Error('Unexpected protected JWS header');
  for (const name of requiredClaims) if (!(name in claims)) throw new Error('Required signed claim missing');
  const verified = await jwtVerify(token, config.signingPublicKey, {
    algorithms: ['Ed25519'],
    issuer: config.issuer,
    audience: 'aikayun-commerce',
    currentDate: now,
    clockTolerance: 0,
  });
  if (verified.protectedHeader['alg'] !== 'Ed25519' || verified.protectedHeader['kid'] !== config.signingKeyId || verified.protectedHeader['typ'] !== typ) {
    throw new Error('Unexpected protected JWS header');
  }
  return { header, claims };
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
