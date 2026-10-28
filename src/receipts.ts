import { randomUUID } from 'node:crypto';
import type { RuntimeConfig } from './config.js';
import { signTypedJwt } from './crypto/jwt.js';
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
