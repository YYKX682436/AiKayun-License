import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { sql, type Kysely, type Transaction } from 'kysely';
import type { FastifyRequest } from 'fastify';
import type { RuntimeConfig } from '../config.js';
import type { Database } from '../db/types.js';
import { LicenseApiError } from '../errors.js';
import { verifyTypedJwt, assertExactClaims, assertIntegerClaim, assertStringClaim } from '../crypto/jwt.js';
import { validateIdentityJwk } from '../crypto/identity.js';
import { verifyHttpMessage, type VerifiedHttpSignature } from '../crypto/http-signature.js';

export type ChallengeOperation = 'activation' | 'renewal' | 'recovery' | 'query' | 'continue' | 'transfer_prepare' | 'transfer_commit' | 'disaster_transfer_prepare' | 'disaster_transfer_commit';
export interface ChallengeRequestBody {
  operation: ChallengeOperation;
  operation_id: string;
  intent_digest: string;
  instance_id: string;
  public_jwk: unknown;
  client_nonce: string;
}

export interface AuthenticatedBody {
  operation_id: string;
  intent_digest: string;
  instance_id: string;
  identity_jkt: string;
  public_jwk: unknown;
  challenge: string;
  attempt_no: number;
}

export interface ChallengeClaims {
  token: string;
  operation: ChallengeOperation;
  operationId: string;
  intentDigest: string;
  instanceId: string;
  identityJkt: string;
  clientNonce: string;
  serverNonce: string;
  nonceHash: string;
  clientNonceHash: string;
  issuedAt: number;
  expiresAt: number;
  fresh: boolean;
}

export interface AuthenticatedRequest {
  challenge: ChallengeClaims;
  signature: VerifiedHttpSignature;
  requestDigest: string;
  receivedAt: Date;
}

export function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('base64url');
}

export function newNonce(): string {
  return randomBytes(32).toString('base64url');
}

export function validateNonce(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.byteLength === 32 && bytes.toString('base64url') === value;
}

export function validateDigest(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
}

export async function databaseNow(db: Kysely<Database> | Transaction<Database>): Promise<Date> {
  const result = await sql<{ now: Date }>`SELECT clock_timestamp() AS now`.execute(db);
  return result.rows[0]!.now;
}

export async function issueChallenge(
  db: Kysely<Database>,
  config: RuntimeConfig,
  request: ChallengeRequestBody,
  http: VerifiedHttpSignature,
  now: Date,
): Promise<string> {
  const { signTypedJwt } = await import('../crypto/jwt.js');
  const serverNonce = newNonce();
  const iat = Math.floor(now.getTime() / 1000);
  const claims = {
    v: 1,
    iss: config.issuer,
    aud: 'aikayun-commerce',
    sub: request.instance_id,
    jti: randomUUID(),
    iat,
    nbf: iat,
    exp: iat + 5 * 60,
    operation: request.operation,
    operation_id: request.operation_id,
    intent_digest: request.intent_digest,
    instance_id: request.instance_id,
    identity_jkt: http.identityJkt,
    client_nonce: request.client_nonce,
    server_nonce: serverNonce,
  };
  const token = await signTypedJwt(config, 'aikayun-license-challenge+jwt', claims);
  try {
    await db.insertInto('request_nonces').values({
      nonce_hash: sha256(serverNonce),
      operation: request.operation,
      operation_id: request.operation_id,
      intent_digest: request.intent_digest,
      instance_id: request.instance_id,
      identity_jkt: http.identityJkt,
      client_nonce_hash: sha256(request.client_nonce),
      challenge_jws_digest: sha256(token),
      created_at: now,
      expires_at: new Date(now.getTime() + 5 * 60 * 1000),
      consumed_at: null,
    }).execute();
  } catch {
    throw new LicenseApiError(409, 'CHALLENGE_NONCE_REPLAY');
  }
  return token;
}

async function verifyChallengeToken(token: string, config: RuntimeConfig, now: Date): Promise<ChallengeClaims> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new LicenseApiError(401, 'CHALLENGE_INVALID');
  let issuedAt: number;
  try {
    const decoded = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
    if (!Number.isSafeInteger(decoded['iat'])) throw new Error('iat');
    issuedAt = Number(decoded['iat']);
  } catch {
    throw new LicenseApiError(401, 'CHALLENGE_INVALID');
  }
  let claims: Record<string, unknown>;
  try {
    const verified = await verifyTypedJwt(token, config, 'aikayun-license-challenge+jwt', [
      'v', 'iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'operation', 'operation_id', 'intent_digest',
      'instance_id', 'identity_jkt', 'client_nonce', 'server_nonce',
    ], new Date(issuedAt * 1000));
    claims = verified.claims;
  } catch {
    throw new LicenseApiError(401, 'CHALLENGE_INVALID');
  }
  const expected = [
    'v', 'iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'operation', 'operation_id', 'intent_digest',
    'instance_id', 'identity_jkt', 'client_nonce', 'server_nonce',
  ];
  try { assertExactClaims(claims, expected); } catch { throw new LicenseApiError(401, 'CHALLENGE_INVALID'); }
  const iat = assertIntegerClaim(claims, 'iat');
  const nbf = assertIntegerClaim(claims, 'nbf');
  const exp = assertIntegerClaim(claims, 'exp');
  const operation = assertStringClaim(claims, 'operation', 32) as ChallengeOperation;
  if (!['activation', 'renewal', 'recovery', 'query', 'continue', 'transfer_prepare', 'transfer_commit', 'disaster_transfer_prepare', 'disaster_transfer_commit'].includes(operation) || nbf !== iat || exp <= iat || exp > iat + 300) {
    throw new LicenseApiError(401, 'CHALLENGE_INVALID');
  }
  const clientNonce = assertStringClaim(claims, 'client_nonce', 128);
  const serverNonce = assertStringClaim(claims, 'server_nonce', 128);
  if (!validateNonce(clientNonce) || !validateNonce(serverNonce)) throw new LicenseApiError(401, 'CHALLENGE_INVALID');
  const instanceId = assertStringClaim(claims, 'instance_id', 36);
  const identityJkt = assertStringClaim(claims, 'identity_jkt', 64);
  const operationId = assertStringClaim(claims, 'operation_id', 36);
  const intentDigest = assertStringClaim(claims, 'intent_digest', 64);
  if (claims['sub'] !== instanceId || claims['aud'] !== 'aikayun-commerce' || !validateDigest(intentDigest)) {
    throw new LicenseApiError(401, 'CHALLENGE_INVALID');
  }
  return {
    token,
    operation,
    operationId,
    intentDigest,
    instanceId,
    identityJkt,
    clientNonce,
    serverNonce,
    nonceHash: sha256(serverNonce),
    clientNonceHash: sha256(clientNonce),
    issuedAt: iat,
    expiresAt: exp,
    fresh: now.getTime() >= iat * 1000 && Math.floor(now.getTime() / 1000) < exp,
  };
}

export interface RawBodyRequest extends FastifyRequest {
  rawBody: Buffer;
}

export async function authenticateChallengeRequest(
  request: SignedHttpRequestInput,
  body: ChallengeRequestBody,
  config: RuntimeConfig,
  now: Date,
): Promise<VerifiedHttpSignature> {
  const key = await validateIdentityJwk(body.public_jwk);
  if (!validateNonce(body.client_nonce) || !validateDigest(body.intent_digest)) throw new LicenseApiError(400, 'INVALID_CHALLENGE_REQUEST');
  const signature = await verifyHttpMessage(request, body.public_jwk, config.publicOrigin, body.client_nonce, now);
  if (signature.identityJkt !== key.jkt) throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
  return signature;
}

export interface SignedHttpRequestInput {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  rawHeaders: string[];
  body: Uint8Array;
}

export async function authenticateOperationRequest(
  request: SignedHttpRequestInput,
  body: AuthenticatedBody,
  config: RuntimeConfig,
  now: Date,
  expectedOperation: ChallengeOperation,
): Promise<AuthenticatedRequest> {
  const identity = await validateIdentityJwk(body.public_jwk);
  if (body.identity_jkt !== identity.jkt || !validateDigest(body.intent_digest) || !Number.isSafeInteger(body.attempt_no) || body.attempt_no < 1) {
    throw new LicenseApiError(400, 'INVALID_OPERATION_REQUEST');
  }
  const challenge = await verifyChallengeToken(body.challenge, config, now);
  if (challenge.operation !== expectedOperation || challenge.operationId !== body.operation_id || challenge.intentDigest !== body.intent_digest ||
    challenge.instanceId !== body.instance_id || challenge.identityJkt !== identity.jkt) {
    throw new LicenseApiError(401, 'CHALLENGE_BINDING_INVALID');
  }
  const signature = await verifyHttpMessage(request, body.public_jwk, config.publicOrigin, challenge.serverNonce, now);
  if (signature.identityJkt !== identity.jkt) throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
  return { challenge, signature, requestDigest: signature.requestDigest, receivedAt: now };
}

export function challengeClaimsMatchRow(row: {
  nonce_hash: string;
  operation: string;
  operation_id: string;
  intent_digest: string;
  instance_id: string;
  identity_jkt: string;
  client_nonce_hash: string;
}, challenge: ChallengeClaims): boolean {
  return row.nonce_hash === challenge.nonceHash && row.operation === challenge.operation && row.operation_id === challenge.operationId &&
    row.intent_digest === challenge.intentDigest && row.instance_id === challenge.instanceId && row.identity_jkt === challenge.identityJkt &&
    row.client_nonce_hash === challenge.clientNonceHash;
}
