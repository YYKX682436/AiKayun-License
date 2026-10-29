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
    subscription_end: Math.floor(input.subscriptionEnd.getTime() / 1000),
    new_lease: input.newLease,
  });
}

const leaseClaims = [
  'v', 'iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'instance_id', 'database_id', 'identity_jkt',
  'activation_generation', 'entitlement_revision', 'plan', 'subscription_end', 'renew_after', 'grants',
  'request_nonce', 'request_digest',
] as const;

const transferReceiptClaims = [
  'v', 'iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'operation_id', 'intent_digest', 'request_nonce',
  'request_digest', 'license_id', 'database_id', 'source_instance_id', 'source_identity_jkt',
  'source_activation_generation', 'target_instance_id', 'target_identity_jkt', 'target_activation_generation',
  'expected_binding_revision', 'expected_revision', 'result_revision', 'entitlement_revision', 'subscription_end',
  'new_lease',
] as const;

function validateBoundedTimes(claims: Record<string, unknown>, now: Date, maxLifetime: number): {
  iat: number; nbf: number; exp: number;
} {
  const iat = assertIntegerClaim(claims, 'iat', 1);
  const nbf = assertIntegerClaim(claims, 'nbf', 1);
  const exp = assertIntegerClaim(claims, 'exp', 1);
  if (nbf !== iat || exp <= iat || exp - iat > maxLifetime || iat > Math.floor(now.getTime() / 1000)) {
    throw new Error('Invalid signed token lifetime');
  }
  return { iat, nbf, exp };
}

function decimalValue(claims: Record<string, unknown>, name: string, minimum = 0): bigint {
  const value = assertStringClaim(claims, name, 19);
  if (!decimalClaim.test(value)) throw new Error('Invalid signed decimal claim');
  const parsed = BigInt(value);
  if (parsed < BigInt(minimum)) throw new Error('Invalid signed decimal claim');
  return parsed;
}

function assertUuid(claims: Record<string, unknown>, name: string): string {
  const value = assertStringClaim(claims, name, 36);
  if (!uuidClaim.test(value)) throw new Error('Invalid signed identifier');
  return value;
}

function assertDigest(claims: Record<string, unknown>, name: string): string {
  const value = assertStringClaim(claims, name, 64);
  if (!digestClaim.test(value)) throw new Error('Invalid signed digest');
  return value;
}

export async function verifyLicenseLease(
  token: unknown,
  config: RuntimeConfig,
  now: Date,
): Promise<Record<string, unknown>> {
  const verified = await verifyTypedJwt(token, config, 'aikayun-license+jwt', [...leaseClaims], now);
  assertExactClaims(verified.claims, leaseClaims);
  const { iat, exp } = validateBoundedTimes(verified.claims, now, 7 * 24 * 60 * 60);
  if (assertIntegerClaim(verified.claims, 'v') !== 1 || verified.claims['aud'] !== 'aikayun-commerce' ||
    !['monthly', 'yearly'].includes(String(verified.claims['plan']))) throw new Error('Invalid license lease');
  assertUuid(verified.claims, 'sub');
  assertUuid(verified.claims, 'jti');
  assertUuid(verified.claims, 'instance_id');
  assertUuid(verified.claims, 'database_id');
  assertDigest(verified.claims, 'identity_jkt');
  assertDigest(verified.claims, 'request_nonce');
  assertDigest(verified.claims, 'request_digest');
  decimalValue(verified.claims, 'activation_generation', 1);
  decimalValue(verified.claims, 'entitlement_revision', 1);
  const subscriptionEnd = assertIntegerClaim(verified.claims, 'subscription_end', 1);
  const renewAfter = assertIntegerClaim(verified.claims, 'renew_after', 1);
  if (subscriptionEnd <= iat || exp !== Math.min(iat + 7 * 24 * 60 * 60, subscriptionEnd) ||
    renewAfter !== Math.min(iat + 6 * 60 * 60, exp) || !Array.isArray(verified.claims['grants']) ||
    verified.claims['grants'].length !== 2 || verified.claims['grants'][0] !== 'create_order' ||
    verified.claims['grants'][1] !== 'create_top_up') throw new Error('Invalid license lease claims');
  return verified.claims;
}

export async function verifyTransferReceipt(
  token: unknown,
  config: RuntimeConfig,
  now: Date,
): Promise<Record<string, unknown>> {
  const verified = await verifyTypedJwt(token, config, 'aikayun-license-transfer+jwt', [...transferReceiptClaims], now);
  assertExactClaims(verified.claims, transferReceiptClaims);
  const { iat, exp } = validateBoundedTimes(verified.claims, now, 10 * 60);
  if (assertIntegerClaim(verified.claims, 'v') !== 1 || verified.claims['aud'] !== 'aikayun-commerce' ||
    assertUuid(verified.claims, 'sub') !== assertUuid(verified.claims, 'license_id')) throw new Error('Invalid transfer receipt');
  assertUuid(verified.claims, 'jti');
  assertUuid(verified.claims, 'operation_id');
  for (const name of ['database_id', 'source_instance_id', 'target_instance_id']) assertUuid(verified.claims, name);
  for (const name of ['intent_digest', 'request_nonce', 'request_digest', 'source_identity_jkt', 'target_identity_jkt']) assertDigest(verified.claims, name);
  const sourceGeneration = decimalValue(verified.claims, 'source_activation_generation', 1);
  const targetGeneration = decimalValue(verified.claims, 'target_activation_generation', 1);
  const expectedRevision = decimalValue(verified.claims, 'expected_revision', 1);
  const resultRevision = decimalValue(verified.claims, 'result_revision', 1);
  decimalValue(verified.claims, 'expected_binding_revision');
  const entitlementRevision = decimalValue(verified.claims, 'entitlement_revision', 1);
  const subscriptionEnd = assertIntegerClaim(verified.claims, 'subscription_end', 1);
  if (targetGeneration !== sourceGeneration + 1n || resultRevision !== expectedRevision + 1n ||
    verified.claims['source_identity_jkt'] === verified.claims['target_identity_jkt'] || subscriptionEnd <= iat ||
    exp !== Math.min(iat + 10 * 60, subscriptionEnd)) throw new Error('Invalid transfer receipt binding');
  const nested = await verifyLicenseLease(verified.claims['new_lease'], config, now);
  if (nested['sub'] !== verified.claims['license_id'] || nested['database_id'] !== verified.claims['database_id'] ||
    nested['instance_id'] !== verified.claims['target_instance_id'] || nested['identity_jkt'] !== verified.claims['target_identity_jkt'] ||
    nested['activation_generation'] !== verified.claims['target_activation_generation'] ||
    nested['entitlement_revision'] !== verified.claims['entitlement_revision'] ||
    nested['subscription_end'] !== verified.claims['subscription_end'] || nested['request_nonce'] !== verified.claims['request_nonce'] ||
    nested['request_digest'] !== verified.claims['request_digest'] || nested['iat'] !== iat ||
    BigInt(String(nested['entitlement_revision'])) !== entitlementRevision) {
    throw new Error('Nested transfer lease does not match its receipt');
  }
  return verified.claims;
}

export interface DisasterTransferTicketClaims {
  plan_id: string;
  request_id: string;
  approval_id: string;
  approval_request_digest: string;
  prepare_operation_id: string;
  prepare_intent_digest: string;
  prepare_request_nonce: string;
  prepare_request_digest: string;
  license_id: string;
  account_reference: string;
  database_id: string;
  source_activation_id: string;
  source_instance_id: string;
  source_identity_jkt: string;
  source_activation_generation: string;
  target_instance_id: string;
  target_identity_jkt: string;
  expected_binding_revision: string;
  expected_revision: string;
  entitlement_revision: string;
}

const uuidClaim = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const decimalClaim = /^(0|[1-9][0-9]{0,18})$/;
const digestClaim = /^[A-Za-z0-9_-]{43}$/;

export async function signDisasterTransferTicket(
  config: RuntimeConfig,
  input: DisasterTransferTicketClaims & { now: Date },
): Promise<string> {
  const iat = Math.floor(input.now.getTime() / 1000);
  const claims = { ...input } as Record<string, unknown>;
  delete claims['now'];
  return signTypedJwt(config, 'aikayun-license-disaster-transfer-ticket+jwt', {
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

export async function verifyDisasterTransferTicket(
  token: unknown,
  config: RuntimeConfig,
  validationTime: Date,
): Promise<{ token: string; claims: Record<string, unknown>; expired: boolean }> {
  if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') > 16 * 1024) throw new Error('Invalid disaster transfer ticket');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid disaster transfer ticket');
  let issuedAt: number;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
    if (!Number.isSafeInteger(payload['iat'])) throw new Error('iat');
    issuedAt = Number(payload['iat']);
  } catch {
    throw new Error('Invalid disaster transfer ticket');
  }
  const names = [
    'v', 'iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'plan_id', 'request_id', 'approval_id',
    'approval_request_digest', 'prepare_operation_id', 'prepare_intent_digest', 'prepare_request_nonce',
    'prepare_request_digest', 'license_id', 'account_reference', 'database_id', 'source_activation_id',
    'source_instance_id', 'source_identity_jkt', 'source_activation_generation', 'target_instance_id',
    'target_identity_jkt', 'expected_binding_revision', 'expected_revision', 'entitlement_revision',
  ];
  const verified = await verifyTypedJwt(token, config, 'aikayun-license-disaster-transfer-ticket+jwt', names, new Date(issuedAt * 1000));
  assertExactClaims(verified.claims, names);
  if (assertIntegerClaim(verified.claims, 'v') !== 1 || assertStringClaim(verified.claims, 'sub', 36) !== assertStringClaim(verified.claims, 'license_id', 36) ||
    assertStringClaim(verified.claims, 'jti', 36) !== assertStringClaim(verified.claims, 'plan_id', 36) ||
    assertIntegerClaim(verified.claims, 'nbf') !== issuedAt || assertIntegerClaim(verified.claims, 'exp') !== issuedAt + 600 ||
    verified.claims['aud'] !== 'aikayun-commerce' || issuedAt <= 0 || issuedAt > Math.floor(validationTime.getTime() / 1000) + 60) {
    throw new Error('Invalid disaster transfer ticket claims');
  }
  for (const name of ['plan_id', 'request_id', 'approval_id', 'prepare_operation_id', 'license_id', 'database_id',
    'source_activation_id', 'source_instance_id', 'target_instance_id']) {
    if (!uuidClaim.test(assertStringClaim(verified.claims, name, 36))) throw new Error('Invalid disaster transfer ticket identifier');
  }
  for (const name of ['approval_request_digest', 'prepare_intent_digest', 'prepare_request_digest',
    'source_identity_jkt', 'target_identity_jkt']) {
    if (!digestClaim.test(assertStringClaim(verified.claims, name, 64))) throw new Error('Invalid disaster transfer ticket digest');
  }
  const accountReference = assertStringClaim(verified.claims, 'account_reference', 200);
  if (accountReference.trim() !== accountReference) throw new Error('Invalid disaster transfer account reference');
  for (const name of ['source_activation_generation', 'expected_binding_revision', 'expected_revision', 'entitlement_revision']) {
    if (!decimalClaim.test(assertStringClaim(verified.claims, name, 19))) throw new Error('Invalid disaster transfer revision');
  }
  const nonce = assertStringClaim(verified.claims, 'prepare_request_nonce', 128);
  if (!digestClaim.test(nonce)) throw new Error('Invalid disaster transfer prepare nonce');
  return { token, claims: verified.claims, expired: Math.floor(validationTime.getTime() / 1000) >= assertIntegerClaim(verified.claims, 'exp') };
}

export async function signDisasterTransferResult(config: RuntimeConfig, input: {
  mode: 'active_lease' | 'binding_only';
  licenseId: string;
  databaseId: string;
  accountReference: string;
  sourceActivationId: string;
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
  subscriptionEnd: Date;
  licenseStatus: 'active' | 'revoked';
  lease?: string;
  now: Date;
}): Promise<string> {
  const iat = Math.floor(input.now.getTime() / 1000);
  const exp = input.mode === 'active_lease'
    ? Math.min(iat + 10 * 60, Math.floor(input.subscriptionEnd.getTime() / 1000))
    : iat + 10 * 60;
  if (exp <= iat) throw new Error('Cannot sign an expired disaster transfer result');
  const binding = {
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
    account_reference: input.accountReference,
    database_id: input.databaseId,
    source_activation_id: input.sourceActivationId,
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
    subscription_end: Math.floor(input.subscriptionEnd.getTime() / 1000),
  };
  if (input.mode === 'active_lease') {
    if (!input.lease || input.licenseStatus !== 'active') throw new Error('Active disaster result requires an active lease');
    return signTypedJwt(config, 'aikayun-license-disaster-transfer+jwt', {
      ...binding,
      result_mode: 'active_lease',
      license_status: 'active',
      new_lease: input.lease,
    });
  }
  const entitlementState = input.licenseStatus === 'revoked' ? 'revoked' : 'expired';
  return signTypedJwt(config, 'aikayun-license-disaster-binding+jwt', {
    ...binding,
    result_mode: 'binding_only',
    purpose: 'historical_obligations_identity_rebinding',
    entitlement_state: entitlementState,
    license_status: input.licenseStatus,
  });
}

const disasterResultClaims = [
  'v', 'iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'operation_id', 'intent_digest', 'request_nonce',
  'request_digest', 'license_id', 'account_reference', 'database_id', 'source_activation_id', 'source_instance_id',
  'source_identity_jkt', 'source_activation_generation', 'target_instance_id', 'target_identity_jkt',
  'target_activation_generation', 'expected_binding_revision', 'expected_revision', 'result_revision',
  'entitlement_revision', 'subscription_end',
] as const;

function validateDisasterResultBinding(claims: Record<string, unknown>): void {
  if (assertIntegerClaim(claims, 'v') !== 1 || claims['aud'] !== 'aikayun-commerce' ||
    assertStringClaim(claims, 'sub', 36) !== assertStringClaim(claims, 'license_id', 36)) throw new Error('Invalid disaster result binding');
  for (const name of ['operation_id', 'license_id', 'database_id', 'source_activation_id', 'source_instance_id', 'target_instance_id']) {
    if (!uuidClaim.test(assertStringClaim(claims, name, 36))) throw new Error('Invalid disaster result identifier');
  }
  for (const name of ['intent_digest', 'request_digest', 'source_identity_jkt', 'target_identity_jkt']) {
    if (!digestClaim.test(assertStringClaim(claims, name, 64))) throw new Error('Invalid disaster result digest');
  }
  if (!digestClaim.test(assertStringClaim(claims, 'request_nonce', 128))) throw new Error('Invalid disaster result nonce');
  assertStringClaim(claims, 'account_reference', 200);
  for (const name of ['source_activation_generation', 'target_activation_generation', 'expected_binding_revision',
    'expected_revision', 'result_revision', 'entitlement_revision']) {
    if (!decimalClaim.test(assertStringClaim(claims, name, 19))) throw new Error('Invalid disaster result revision');
  }
  assertIntegerClaim(claims, 'subscription_end');
}

export async function verifyDisasterTransferReceipt(
  token: unknown,
  config: RuntimeConfig,
  now: Date,
): Promise<Record<string, unknown>> {
  const claims = [...disasterResultClaims, 'result_mode', 'license_status', 'new_lease'];
  const verified = await verifyTypedJwt(token, config, 'aikayun-license-disaster-transfer+jwt', claims, now);
  assertExactClaims(verified.claims, claims);
  validateDisasterResultBinding(verified.claims);
  const { iat, exp } = validateBoundedTimes(verified.claims, now, 10 * 60);
  if (verified.claims['result_mode'] !== 'active_lease' || verified.claims['license_status'] !== 'active') {
    throw new Error('Invalid active disaster transfer receipt');
  }
  const sourceGeneration = decimalValue(verified.claims, 'source_activation_generation', 1);
  const targetGeneration = decimalValue(verified.claims, 'target_activation_generation', 1);
  const expectedRevision = decimalValue(verified.claims, 'expected_revision', 1);
  const resultRevision = decimalValue(verified.claims, 'result_revision', 1);
  const subscriptionEnd = assertIntegerClaim(verified.claims, 'subscription_end', 1);
  if (targetGeneration !== sourceGeneration + 1n || resultRevision !== expectedRevision + 1n || subscriptionEnd <= iat ||
    exp !== Math.min(iat + 10 * 60, subscriptionEnd)) throw new Error('Invalid active disaster transfer lifetime or revision');
  const nested = await verifyLicenseLease(verified.claims['new_lease'], config, now);
  if (nested['sub'] !== verified.claims['sub'] || nested['sub'] !== verified.claims['license_id'] ||
    nested['database_id'] !== verified.claims['database_id'] || nested['instance_id'] !== verified.claims['target_instance_id'] ||
    nested['identity_jkt'] !== verified.claims['target_identity_jkt'] ||
    nested['activation_generation'] !== verified.claims['target_activation_generation'] ||
    nested['entitlement_revision'] !== verified.claims['entitlement_revision'] ||
    nested['subscription_end'] !== verified.claims['subscription_end'] ||
    nested['request_nonce'] !== verified.claims['request_nonce'] || nested['request_digest'] !== verified.claims['request_digest'] ||
    nested['iat'] !== iat) {
    throw new Error('Nested disaster transfer lease does not match its receipt');
  }
  return verified.claims;
}

export async function verifyDisasterBindingReceipt(
  token: unknown,
  config: RuntimeConfig,
  now: Date,
): Promise<Record<string, unknown>> {
  const claims = [...disasterResultClaims, 'result_mode', 'purpose', 'entitlement_state', 'license_status'];
  const verified = await verifyTypedJwt(token, config, 'aikayun-license-disaster-binding+jwt', claims, now);
  assertExactClaims(verified.claims, claims);
  validateDisasterResultBinding(verified.claims);
  const { iat, exp } = validateBoundedTimes(verified.claims, now, 10 * 60);
  const sourceGeneration = decimalValue(verified.claims, 'source_activation_generation', 1);
  const targetGeneration = decimalValue(verified.claims, 'target_activation_generation', 1);
  const expectedRevision = decimalValue(verified.claims, 'expected_revision', 1);
  const resultRevision = decimalValue(verified.claims, 'result_revision', 1);
  const subscriptionEnd = assertIntegerClaim(verified.claims, 'subscription_end');
  if (verified.claims['result_mode'] !== 'binding_only' ||
    verified.claims['purpose'] !== 'historical_obligations_identity_rebinding' ||
    !['expired', 'revoked'].includes(String(verified.claims['entitlement_state'])) ||
    !['active', 'revoked'].includes(String(verified.claims['license_status'])) || exp !== iat + 10 * 60 ||
    targetGeneration !== sourceGeneration + 1n || resultRevision !== expectedRevision + 1n) {
    throw new Error('Invalid disaster binding receipt');
  }
  if ((verified.claims['entitlement_state'] === 'revoked') !== (verified.claims['license_status'] === 'revoked')) {
    throw new Error('Disaster binding receipt entitlement state does not match license status');
  }
  if (verified.claims['entitlement_state'] === 'expired' && subscriptionEnd > iat) {
    throw new Error('Disaster binding receipt does not prove expired entitlement');
  }
  return verified.claims;
}
