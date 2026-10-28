import canonicalize from 'canonicalize';
import { sha256Base64url, validateActivationCode } from './crypto/identity.js';

function digestCanonical(value: Record<string, unknown>): string {
  const canonical = canonicalize(value);
  if (typeof canonical !== 'string') throw new Error('Unable to canonicalize operation intent');
  return sha256Base64url(canonical);
}

export function activationIntentDigest(input: {
  licenseId: string;
  activationCode: string;
  instanceId: string;
  databaseId: string;
  identityJkt: string;
  origin: string | null;
}): string {
  const codeHash = validateActivationCode(input.activationCode);
  return digestCanonical({
    v: 1,
    kind: 'activation',
    license_id: input.licenseId,
    activation_code_sha256: codeHash,
    instance_id: input.instanceId,
    database_id: input.databaseId,
    identity_jkt: input.identityJkt,
    origin: input.origin,
  });
}

export function renewalIntentDigest(input: {
  kind: 'renewal' | 'recovery';
  licenseId: string;
  databaseId: string;
  instanceId: string;
  identityJkt: string;
  expectedGeneration: string;
  knownRevision: string;
  recoveryOfOperationId?: string;
}): string {
  return digestCanonical({
    v: 1,
    kind: input.kind,
    license_id: input.licenseId,
    database_id: input.databaseId,
    instance_id: input.instanceId,
    identity_jkt: input.identityJkt,
    expected_generation: input.expectedGeneration,
    known_revision: input.knownRevision,
    ...(input.recoveryOfOperationId ? { recovery_of_operation_id: input.recoveryOfOperationId } : {}),
  });
}

export function transferPrepareIntentDigest(input: {
  licenseId: string;
  databaseId: string;
  instanceId: string;
  sourceIdentityJkt: string;
  targetInstanceId: string;
  targetIdentityJkt: string;
  approvalId: string;
  sourceGeneration: string;
  expectedBindingRevision: string;
  expectedRevision: string;
}): string {
  return digestCanonical({
    v: 1,
    kind: 'transfer_prepare',
    license_id: input.licenseId,
    database_id: input.databaseId,
    source_instance_id: input.instanceId,
    source_identity_jkt: input.sourceIdentityJkt,
    target_instance_id: input.targetInstanceId,
    target_identity_jkt: input.targetIdentityJkt,
    approval_id: input.approvalId,
    source_generation: input.sourceGeneration,
    expected_binding_revision: input.expectedBindingRevision,
    expected_revision: input.expectedRevision,
  });
}

export function transferCommitIntentDigest(input: {
  licenseId: string;
  databaseId: string;
  instanceId: string;
  targetIdentityJkt: string;
  approvalId: string;
  prepareOperationId: string;
  ticketDigest: string;
}): string {
  return digestCanonical({
    v: 1,
    kind: 'transfer_commit',
    license_id: input.licenseId,
    database_id: input.databaseId,
    instance_id: input.instanceId,
    target_identity_jkt: input.targetIdentityJkt,
    approval_id: input.approvalId,
    prepare_operation_id: input.prepareOperationId,
    ticket_digest: input.ticketDigest,
  });
}
