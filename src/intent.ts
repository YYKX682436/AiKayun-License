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
