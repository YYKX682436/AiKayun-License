import { randomUUID } from 'node:crypto';
import type { RuntimeConfig } from './config.js';
import { signTypedJwt } from './crypto/jwt.js';
import { assertExactClaims, assertIntegerClaim, assertStringClaim, verifyTypedJwt } from './crypto/jwt.js';
import type { BillingPlan } from './entitlements/calendar.js';

export interface LeaseInput {
  licenseId: string;
  instanceId: string;
  databaseId: string;
  identityJkt: string;
  generation: string;
  entitlementRevision: string;
  plan: BillingPlan;
  subscriptionEnd: Date;
  requestNonce: string;
  requestDigest: string;
  now: Date;
}

export async function signLicenseLease(config: RuntimeConfig, input: LeaseInput): Promise<{ token: string; exp: number; iat: number }> {
  const iat = Math.floor(input.now.getTime() / 1000);
  const subscriptionEnd = Math.floor(input.subscriptionEnd.getTime() / 1000);
  const exp = Math.min(iat + 7 * 24 * 60 * 60, subscriptionEnd);
  if (exp <= iat) throw new Error('Cannot sign an expired lease');
  const renewAfter = Math.min(iat + 6 * 60 * 60, exp);
  const token = await signTypedJwt(config, 'aikayun-license+jwt', {
    v: 1,
    iss: config.issuer,
    aud: 'aikayun-commerce',
    sub: input.licenseId,
    jti: randomUUID(),
    iat,
    nbf: iat,
    exp,
    instance_id: input.instanceId,
    database_id: input.databaseId,
    identity_jkt: input.identityJkt,
    activation_generation: input.generation,
    entitlement_revision: input.entitlementRevision,
    plan: input.plan,
    subscription_end: subscriptionEnd,
    renew_after: renewAfter,
    grants: ['create_order', 'create_top_up'],
    request_nonce: input.requestNonce,
    request_digest: input.requestDigest,
  });
  return { token, exp, iat };
}

export async function signStatusReceipt(config: RuntimeConfig, input: {
  licenseId: string;
  instanceId: string;
  identityJkt: string;
  generation: string;
  currentGeneration: string;
  entitlementRevision: string;
  subscriptionEnd: Date;
  status: 'expired' | 'revoked' | 'superseded';
  requestNonce: string;
  requestDigest: string;
  now: Date;
}): Promise<string> {
  const iat = Math.floor(input.now.getTime() / 1000);
  return signTypedJwt(config, 'aikayun-license-status+jwt', {
    v: 1,
    iss: config.issuer,
    aud: 'aikayun-commerce',
    sub: input.licenseId,
    jti: randomUUID(),
    iat,
    nbf: iat,
    exp: iat + 5 * 60,
    instance_id: input.instanceId,
    identity_jkt: input.identityJkt,
    activation_generation: input.generation,
    current_generation: input.currentGeneration,
    entitlement_revision: input.entitlementRevision,
    subscription_end: Math.floor(input.subscriptionEnd.getTime() / 1000),
    status: input.status,
    request_nonce: input.requestNonce,
    request_digest: input.requestDigest,
  });
}

export type OperationState = 'not_found' | 'committed' | 'rejected' | 'cancelled';

export async function signOperationReceipt(config: RuntimeConfig, input: {
  licenseId: string;
  identityJkt: string;
  operationId: string;
  intentDigest: string;
  state: OperationState;
  outcomeCode: string | null;
  attemptNo: number;
  requestNonceHash: string;
  requestDigest: string;
  committedAttemptNo?: number | null;
  committedRequestNonceHash?: string | null;
  committedRequestDigest?: string | null;
  resultJws?: string | null;
  now: Date;
}): Promise<string> {
  const iat = Math.floor(input.now.getTime() / 1000);
  return signTypedJwt(config, 'aikayun-license-operation+jwt', {
    v: 1,
    iss: config.issuer,
    aud: 'aikayun-commerce',
    sub: input.licenseId,
    jti: randomUUID(),
    iat,
    nbf: iat,
    exp: iat + 5 * 60,
    actor_jkt: input.identityJkt,
    operation_id: input.operationId,
    intent_digest: input.intentDigest,
    state: input.state,
    outcome_code: input.outcomeCode,
    attempt_no: input.attemptNo,
    request_nonce_hash: input.requestNonceHash,
    request_digest: input.requestDigest,
    committed_attempt_no: input.committedAttemptNo ?? null,
    committed_request_nonce_hash: input.committedRequestNonceHash ?? null,
    committed_request_digest: input.committedRequestDigest ?? null,
    result_jws: input.resultJws ?? null,
  });
}

export interface TransferTicketClaims {
  plan_id: string;
  approval_operation_id: string;
  prepare_operation_id: string;
  prepare_intent_digest: string;
  prepare_request_nonce: string;
  prepare_request_digest: string;
  license_id: string;
  database_id: string;
  source_instance_id: string;
  source_identity_jkt: string;
  source_activation_generation: string;
  target_instance_id: string;
  target_identity_jkt: string;
  expected_binding_revision: string;
  expected_revision: string;
  entitlement_revision: string;
}

export async function signTransferTicket(config: RuntimeConfig, input: TransferTicketClaims & { now: Date }): Promise<string> {
  const iat = Math.floor(input.now.getTime() / 1000);
  const claims = { ...input } as Record<string, unknown>;
  delete claims['now'];
  return signTypedJwt(config, 'aikayun-license-transfer-ticket+jwt', {
    v: 1,
    iss: config.issuer,
    aud: 'aikayun-commerce',
    sub: input.license_id,
    jti: input.plan_id,
    iat,
    nbf: iat,
    exp: iat + 10 * 60,
    ...claims,
  });
}

export async function verifyTransferTicket(
  token: unknown,
  config: RuntimeConfig,
  validationTime: Date,
): Promise<{ token: string; claims: Record<string, unknown>; expired: boolean }> {
  if (typeof token !== 'string') throw new Error('Invalid transfer ticket');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid transfer ticket');
  let issuedAt: number;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
    if (!Number.isSafeInteger(payload['iat'])) throw new Error('iat');
    issuedAt = Number(payload['iat']);
  } catch {
    throw new Error('Invalid transfer ticket');
  }
  const names = [
    'v', 'iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'plan_id', 'approval_operation_id',
    'prepare_operation_id', 'prepare_intent_digest', 'prepare_request_nonce', 'prepare_request_digest',
    'license_id', 'database_id', 'source_instance_id', 'source_identity_jkt', 'source_activation_generation',
    'target_instance_id', 'target_identity_jkt', 'expected_binding_revision', 'expected_revision', 'entitlement_revision',
  ];
  const verified = await verifyTypedJwt(token, config, 'aikayun-license-transfer-ticket+jwt', names, new Date(issuedAt * 1000));
  assertExactClaims(verified.claims, names);
  if (assertIntegerClaim(verified.claims, 'v') !== 1 || assertStringClaim(verified.claims, 'sub', 36) !== assertStringClaim(verified.claims, 'license_id', 36) ||
    assertStringClaim(verified.claims, 'jti', 36) !== assertStringClaim(verified.claims, 'plan_id', 36) ||
    assertIntegerClaim(verified.claims, 'nbf') !== issuedAt || assertIntegerClaim(verified.claims, 'exp') <= issuedAt ||
    assertIntegerClaim(verified.claims, 'exp') > issuedAt + 10 * 60 || verified.claims['aud'] !== 'aikayun-commerce' ||
    issuedAt <= 0 || issuedAt > Math.floor(validationTime.getTime() / 1000) + 60) {
    throw new Error('Invalid transfer ticket claims');
  }
  for (const name of [
    'approval_operation_id', 'prepare_operation_id', 'license_id', 'database_id', 'source_instance_id',
    'source_activation_generation', 'target_instance_id', 'expected_binding_revision', 'expected_revision', 'entitlement_revision',
  ]) assertStringClaim(verified.claims, name, 36);
  for (const name of ['prepare_intent_digest', 'prepare_request_digest', 'source_identity_jkt', 'target_identity_jkt']) {
    const value = assertStringClaim(verified.claims, name, 64);
    if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error('Invalid transfer ticket digest');
  }
  const prepareNonce = assertStringClaim(verified.claims, 'prepare_request_nonce', 128);
  if (!/^[A-Za-z0-9_-]{43}$/.test(prepareNonce)) throw new Error('Invalid transfer ticket nonce');
  const exp = assertIntegerClaim(verified.claims, 'exp');
  const nowSeconds = Math.floor(validationTime.getTime() / 1000);
  return { token, claims: verified.claims, expired: nowSeconds >= exp };
}

export async function signTransferReceipt(config: RuntimeConfig, input: {
  licenseId: string;
  databaseId: string;
  sourceInstanceId: string;
  sourceIdentityJkt: string;
  sourceGeneration: string;
  targetInstanceId: string;
  targetIdentityJkt: string;
  targetGeneration: string;
  expectedBindingRevision: string;
  expectedRevision: string;
  resultRevision: string;
  entitlementRevision: string;
  operationId: string;
  intentDigest: string;
  requestNonce: string;
  requestDigest: string;
  newLease: string;
  subscriptionEnd: Date;
  now: Date;
}): Promise<string> {
  const iat = Math.floor(input.now.getTime() / 1000);
  const exp = Math.min(iat + 10 * 60, Math.floor(input.subscriptionEnd.getTime() / 1000));
  if (exp <= iat) throw new Error('Cannot sign an expired transfer receipt');
  return signTypedJwt(config, 'aikayun-license-transfer+jwt', {
    v: 1,
    iss: config.issuer,
    aud: 'aikayun-commerce',
    sub: input.licenseId,
    jti: randomUUID(),
    iat,
    nbf: iat,
    exp,
    operation_id: input.operationId,
    intent_digest: input.intentDigest,
    request_nonce: input.requestNonce,
    request_digest: input.requestDigest,
    license_id: input.licenseId,
    database_id: input.databaseId,
    source_instance_id: input.sourceInstanceId,
    source_identity_jkt: input.sourceIdentityJkt,
    source_activation_generation: input.sourceGeneration,
    target_instance_id: input.targetInstanceId,
    target_identity_jkt: input.targetIdentityJkt,
    target_activation_generation: input.targetGeneration,
    expected_binding_revision: input.expectedBindingRevision,
    expected_revision: input.expectedRevision,
    result_revision: input.resultRevision,
    entitlement_revision: input.entitlementRevision,
    new_lease: input.newLease,
  });
}
