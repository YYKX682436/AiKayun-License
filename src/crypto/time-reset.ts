import { randomUUID } from 'node:crypto';
import { jwtVerify } from 'jose';
import type { CryptoKey } from 'jose';
import type { RuntimeConfig } from '../config.js';
import { signTypedJwt, assertExactClaims, assertIntegerClaim, assertStringClaim } from './jwt.js';
import { parseStrictJsonSegment } from '../strict-json.js';

export const TIME_ANCHOR_TYP = 'aikayun-time-anchor+jwt';
export const TIME_ANCHOR_AUDIENCE = 'aikayun-time-bootstrap';
export const TIME_RESET_TYP = 'aikayun-time-reset+jwt';
export const TIME_RESET_AUDIENCE = 'aikayun-time-recovery';
const MAX_TOKEN_BYTES = 16 * 1024;
const MAX_ANCHOR_RTT_MS = 5_000;
const HEADER_NAMES = ['alg', 'kid', 'typ'] as const;
const TIME_ANCHOR_CLAIMS = [
  'v', 'iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'server_time', 'client_nonce',
] as const;
const TIME_RESET_CLAIMS = [
  'v', 'iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'server_time', 'license_id', 'database_id',
  'instance_id', 'identity_jkt', 'activation_generation', 'management_revision', 'entitlement_revision',
  'old_time_epoch', 'new_time_epoch', 'old_watermark_digest', 'operation_id', 'intent_digest',
  'request_nonce', 'client_nonce', 'request_digest', 'admin_approval_id', 'admin_operation_id',
  'admin_approval_digest', 'admin_os_uid', 'admin_os_username', 'admin_database_role', 'admin_reason',
  'admin_audit_reference',
] as const;
const noncePattern = /^[A-Za-z0-9_-]{43}$/;
const decimalPattern = /^(0|[1-9][0-9]{0,18})$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isCanonical256BitValue(value: string): boolean {
  return noncePattern.test(value) && Buffer.from(value, 'base64url').byteLength === 32 &&
    Buffer.from(value, 'base64url').toString('base64url') === value;
}

function assertHeader(token: string, typ: string, kid?: string): Record<string, unknown> {
  if (Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) throw new Error('Signed token too large');
  const segments = token.split('.');
  if (segments.length !== 3 || !segments.every((segment) => segment.length > 0)) throw new Error('Invalid compact JWS');
  const header = parseStrictJsonSegment(segments[0]!);
  if (Object.keys(header).sort().join(',') !== [...HEADER_NAMES].sort().join(',') || header['alg'] !== 'Ed25519' || header['typ'] !== typ ||
    (kid !== undefined && header['kid'] !== kid) || typeof header['kid'] !== 'string') {
    throw new Error('Unexpected time token header');
  }
  return header;
}

export async function signTimeAnchor(config: RuntimeConfig, clientNonce: string, now: Date): Promise<string> {
  if (!isCanonical256BitValue(clientNonce)) throw new Error('Invalid client nonce');
  const serverTime = Math.floor(now.getTime() / 1000);
  return signTypedJwt(config, TIME_ANCHOR_TYP, {
    v: 1,
    iss: config.issuer,
    aud: TIME_ANCHOR_AUDIENCE,
    sub: 'license-center-time',
    jti: randomUUID(),
    iat: serverTime,
    nbf: serverTime,
    exp: serverTime + 30,
    server_time: serverTime,
    client_nonce: clientNonce,
  });
}

export interface VerifiedTimeAnchor {
  tokenId: string;
  serverTime: number;
  expiresAt: number;
  clientNonce: string;
}

/** Verify against an out-of-band trusted key without consulting the host wall clock. */
export async function verifyTimeAnchor(
  token: unknown,
  input: { publicKey: CryptoKey; issuer: string; keyId: string; clientNonce: string; roundTripMs: number },
): Promise<VerifiedTimeAnchor> {
  if (typeof token !== 'string' || !Number.isFinite(input.roundTripMs) || input.roundTripMs < 0 || input.roundTripMs > MAX_ANCHOR_RTT_MS ||
    !isCanonical256BitValue(input.clientNonce)) {
    throw new Error('Time anchor request is not fresh');
  }
  const header = assertHeader(token, TIME_ANCHOR_TYP, input.keyId);
  const segments = token.split('.');
  const rawClaims = parseStrictJsonSegment(segments[1]!);
  const serverTime = rawClaims['server_time'];
  if (typeof serverTime !== 'number' || !Number.isSafeInteger(serverTime) || serverTime <= 0) throw new Error('Invalid server time');
  const verified = await jwtVerify(token, input.publicKey, {
    algorithms: ['Ed25519'], issuer: input.issuer, audience: TIME_ANCHOR_AUDIENCE,
    currentDate: new Date(serverTime * 1000), clockTolerance: 0,
  });
  const claims = verified.payload as Record<string, unknown>;
  if (verified.protectedHeader['alg'] !== 'Ed25519' || verified.protectedHeader['typ'] !== TIME_ANCHOR_TYP ||
    verified.protectedHeader['kid'] !== header['kid']) throw new Error('Unexpected time anchor header');
  assertExactClaims(claims, TIME_ANCHOR_CLAIMS);
  const iat = assertIntegerClaim(claims, 'iat', 1);
  const nbf = assertIntegerClaim(claims, 'nbf', 1);
  const exp = assertIntegerClaim(claims, 'exp', 1);
  const nonce = assertStringClaim(claims, 'client_nonce', 128);
  const jti = assertStringClaim(claims, 'jti', 36);
  if (assertIntegerClaim(claims, 'v') !== 1 || claims['iss'] !== input.issuer || claims['aud'] !== TIME_ANCHOR_AUDIENCE ||
    claims['sub'] !== 'license-center-time' || iat !== serverTime || nbf !== serverTime || exp !== serverTime + 30 ||
    nonce !== input.clientNonce || !uuidPattern.test(jti)) throw new Error('Invalid time anchor claims');
  return { tokenId: jti, serverTime, expiresAt: exp, clientNonce: nonce };
}

export interface TimeResetReceiptClaims {
  license_id: string;
  database_id: string;
  instance_id: string;
  identity_jkt: string;
  activation_generation: string;
  management_revision: string;
  entitlement_revision: string;
  old_time_epoch: string;
  new_time_epoch: string;
  old_watermark_digest: string;
  operation_id: string;
  intent_digest: string;
  request_nonce: string;
  client_nonce: string;
  request_digest: string;
  admin_approval_id: string;
  admin_operation_id: string;
  admin_approval_digest: string;
  admin_os_uid: number;
  admin_os_username: string;
  admin_database_role: string;
  admin_reason: string;
  admin_audit_reference: string;
}

export async function signTimeResetReceipt(
  config: RuntimeConfig,
  claims: TimeResetReceiptClaims,
  now: Date,
): Promise<string> {
  const serverTime = Math.floor(now.getTime() / 1000);
  return signTypedJwt(config, TIME_RESET_TYP, {
    v: 1,
    iss: config.issuer,
    aud: TIME_RESET_AUDIENCE,
    sub: claims.license_id,
    jti: randomUUID(),
    iat: serverTime,
    nbf: serverTime,
    exp: serverTime + 10 * 60,
    server_time: serverTime,
    ...claims,
  });
}

/** Verify reset evidence against an already verified center time anchor and exact pending identity. */
export async function verifyTimeResetReceipt(
  token: unknown,
  input: {
    publicKey: CryptoKey;
    issuer: string;
    keyId: string;
    trustedServerTime: number;
    expected: Pick<TimeResetReceiptClaims,
      'license_id' | 'database_id' | 'instance_id' | 'identity_jkt' | 'activation_generation' | 'management_revision' |
      'entitlement_revision' | 'old_time_epoch' | 'new_time_epoch' | 'old_watermark_digest' | 'operation_id' | 'intent_digest' |
      'request_nonce' | 'client_nonce' | 'request_digest' | 'admin_approval_id' | 'admin_operation_id' | 'admin_approval_digest'>;
  },
): Promise<TimeResetReceiptClaims & { server_time: number; expires_at: number; receipt_id: string }> {
  if (typeof token !== 'string' || !Number.isSafeInteger(input.trustedServerTime) || input.trustedServerTime <= 0) throw new Error('Invalid reset receipt input');
  const header = assertHeader(token, TIME_RESET_TYP, input.keyId);
  const segments = token.split('.');
  const rawClaims = parseStrictJsonSegment(segments[1]!);
  const serverTime = rawClaims['server_time'];
  if (typeof serverTime !== 'number' || !Number.isSafeInteger(serverTime) || input.trustedServerTime < serverTime ||
    input.trustedServerTime - serverTime > 10 * 60) throw new Error('Reset evidence is outside its fresh window');
  const verified = await jwtVerify(token, input.publicKey, {
    algorithms: ['Ed25519'], issuer: input.issuer, audience: TIME_RESET_AUDIENCE,
    currentDate: new Date(input.trustedServerTime * 1000), clockTolerance: 0,
  });
  const claims = verified.payload as Record<string, unknown>;
  if (verified.protectedHeader['alg'] !== 'Ed25519' || verified.protectedHeader['typ'] !== TIME_RESET_TYP ||
    verified.protectedHeader['kid'] !== header['kid']) throw new Error('Unexpected time reset header');
  assertExactClaims(claims, TIME_RESET_CLAIMS);
  const iat = assertIntegerClaim(claims, 'iat', 1);
  const nbf = assertIntegerClaim(claims, 'nbf', 1);
  const exp = assertIntegerClaim(claims, 'exp', 1);
  const receiptId = assertStringClaim(claims, 'jti', 36);
  if (!uuidPattern.test(receiptId) || assertIntegerClaim(claims, 'v') !== 1 || claims['iss'] !== input.issuer ||
    claims['aud'] !== TIME_RESET_AUDIENCE || claims['sub'] !== input.expected.license_id || iat !== serverTime ||
    nbf !== serverTime || exp !== serverTime + 10 * 60 || exp <= input.trustedServerTime ||
    assertIntegerClaim(claims, 'server_time', 1) !== serverTime ||
    BigInt(assertStringClaim(claims, 'new_time_epoch', 20)) !== BigInt(assertStringClaim(claims, 'old_time_epoch', 20)) + 1n ||
    !Number.isSafeInteger(claims['admin_os_uid']) || (claims['admin_os_uid'] as number) < 0) {
    throw new Error('Invalid time reset receipt claims');
  }
  for (const name of [
    'license_id', 'database_id', 'instance_id', 'identity_jkt', 'activation_generation', 'management_revision',
    'entitlement_revision', 'old_time_epoch', 'new_time_epoch', 'old_watermark_digest', 'operation_id', 'intent_digest',
    'request_nonce', 'client_nonce', 'request_digest', 'admin_approval_id', 'admin_operation_id', 'admin_approval_digest',
    'admin_os_username', 'admin_database_role', 'admin_reason', 'admin_audit_reference',
  ]) assertStringClaim(claims, name, name === 'admin_reason' ? 1000 : 1024);
  for (const [name, expected] of Object.entries(input.expected)) {
    if (claims[name] !== expected) throw new Error(`Time reset receipt binding mismatch: ${name}`);
  }
  const nonce = assertStringClaim(claims, 'request_nonce', 128);
  const clientNonce = assertStringClaim(claims, 'client_nonce', 128);
  for (const value of [nonce, clientNonce]) if (!isCanonical256BitValue(value)) throw new Error('Invalid reset nonce');
  for (const name of ['identity_jkt', 'old_watermark_digest', 'intent_digest', 'request_digest', 'admin_approval_digest']) {
    const value = assertStringClaim(claims, name, 64);
    if (!isCanonical256BitValue(value)) throw new Error('Invalid reset digest');
  }
  for (const name of ['activation_generation', 'management_revision', 'entitlement_revision', 'old_time_epoch', 'new_time_epoch']) {
    if (!decimalPattern.test(assertStringClaim(claims, name, 20))) throw new Error('Invalid reset watermark');
  }
  if (BigInt(assertStringClaim(claims, 'activation_generation', 20)) < 1n ||
    BigInt(assertStringClaim(claims, 'management_revision', 20)) < 1n ||
    BigInt(assertStringClaim(claims, 'entitlement_revision', 20)) < 1n ||
    !uuidPattern.test(assertStringClaim(claims, 'operation_id', 36)) ||
    !uuidPattern.test(assertStringClaim(claims, 'admin_approval_id', 36)) ||
    claims['admin_operation_id'] !== claims['admin_approval_id'] ||
    claims['admin_audit_reference'] !== `license_admin_audit_events:${claims['admin_approval_id']}`) {
    throw new Error('Invalid time reset identity or audit reference');
  }
  return {
    ...(claims as unknown as TimeResetReceiptClaims),
    server_time: serverTime,
    expires_at: exp,
    receipt_id: receiptId,
  };
}
