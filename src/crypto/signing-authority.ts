import { sql, type Kysely, type Transaction } from 'kysely';
import type { RuntimeConfig } from '../config.js';
import type { Database, LicenseSignerAuthorityRow, LicenseSignerTrustBundleRow } from '../db/types.js';
import { LicenseApiError } from '../errors.js';
import {
  assertTrustBundleValidAt, compareBundleVersions, getRootAuthenticatedCandidateKey, trustBundleArtifactDigest,
  verifyTrustBundleSignature,
} from '../trust/trust-bundle.js';
import type { RootAuthenticatedTrustBundleCandidate, TrustBundleKeyRecord } from '../trust/trust-bundle.js';
import { createTrustedSigningKeyResolver } from '../trust/trust-bundle-store.js';
import type { TrustedSigningKeyResolver } from './jwt.js';
import type { SigningContext, VerificationContext } from './signing-types.js';

type SigningTransaction = Transaction<Database>;
const SIGNER_LOCK_NAME = 'aikayun-license-center-signing-authority-v1';
const candidateCache = new Map<string, RootAuthenticatedTrustBundleCandidate>();

export interface LockedSigningAuthority {
  readonly signer: SigningContext;
  readonly authority: LicenseSignerAuthorityRow;
  readonly trustBundle: LicenseSignerTrustBundleRow;
  readonly candidate: RootAuthenticatedTrustBundleCandidate;
  readonly now: Date;
}

export async function lockSigningAuthorityForUpdate(trx: SigningTransaction): Promise<void> {
  await sql`SELECT pg_advisory_xact_lock(hashtextextended(${SIGNER_LOCK_NAME}, 0))`.execute(trx);
}

export async function lockSigningAuthorityForSigning(
  trx: SigningTransaction,
  config: RuntimeConfig,
  trustedNowOverride?: Date,
): Promise<LockedSigningAuthority> {
  await sql`SELECT pg_advisory_xact_lock_shared(hashtextextended(${SIGNER_LOCK_NAME}, 0))`.execute(trx);
  return loadLockedSigningAuthority(trx, config, trustedNowOverride);
}

export async function loadTrustedSigningContext(
  db: Kysely<Database>,
  config: RuntimeConfig,
): Promise<{ context: VerificationContext; candidate: RootAuthenticatedTrustBundleCandidate; revokedKids: string[]; retiredKids: string[] }> {
  return db.transaction().execute(async (trx) => {
    await sql`SELECT pg_advisory_xact_lock_shared(hashtextextended(${SIGNER_LOCK_NAME}, 0))`.execute(trx);
    const authority = await trx.selectFrom('license_signer_authority').selectAll()
      .where('singleton', '=', true).forShare().executeTakeFirst();
    if (!authority || !authority.bundle_version || !authority.artifact_sha256) {
      throw new LicenseApiError(503, 'SIGNING_TRUST_BUNDLE_UNINITIALIZED');
    }
    const bundle = await trx.selectFrom('license_signer_trust_bundles').selectAll()
      .where('bundle_version', '=', authority.bundle_version)
      .where('artifact_sha256', '=', authority.artifact_sha256)
      .forShare()
      .executeTakeFirst();
    if (!bundle) throw new LicenseApiError(503, 'SIGNING_TRUST_STATE_CORRUPT');
    const nowResult = await sql<{ now: Date }>`SELECT clock_timestamp() AS now`.execute(trx);
    const nowSeconds = Math.floor(nowResult.rows[0]!.now.getTime() / 1000);
    const candidate = await loadCandidate(bundle, config, nowSeconds);
    const revokedKids = checkedKidList(bundle.revoked_kids, 'revocation');
    const retiredKids = checkedKidList(bundle.retired_kids, 'retirement');
    if (revokedKids.some((kid) => retiredKids.includes(kid))) throw new LicenseApiError(503, 'SIGNING_TRUST_STATE_CORRUPT');
    return {
      context: { issuer: config.issuer, resolver: createTrustedSigningKeyResolver(candidate, { revokedKids, trustedTime: nowSeconds }), trustedTime: nowSeconds },
      candidate,
      revokedKids,
      retiredKids,
    };
  });
}

async function loadLockedSigningAuthority(
  trx: SigningTransaction,
  config: RuntimeConfig,
  trustedNowOverride?: Date,
): Promise<LockedSigningAuthority> {
  const authority = await trx.selectFrom('license_signer_authority').selectAll()
    .where('singleton', '=', true).forShare().executeTakeFirst();
  if (!authority || !authority.active_signing_kid || !authority.bundle_version || !authority.artifact_sha256) {
    throw new LicenseApiError(503, 'SIGNING_AUTHORITY_UNINITIALIZED');
  }
  const bundle = await trx.selectFrom('license_signer_trust_bundles').selectAll()
    .where('bundle_version', '=', authority.bundle_version)
    .where('artifact_sha256', '=', authority.artifact_sha256)
    .forShare()
    .executeTakeFirst();
  if (!bundle) throw new LicenseApiError(503, 'SIGNING_TRUST_STATE_CORRUPT');
  const nowResult = trustedNowOverride
    ? undefined
    : await sql<{ now: Date }>`SELECT clock_timestamp() AS now`.execute(trx);
  const now = trustedNowOverride ?? nowResult!.rows[0]!.now;
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const candidate = await loadCandidate(bundle, config, nowSeconds);
  const revokedKids = checkedKidList(bundle.revoked_kids, 'revocation');
  const retiredKids = checkedKidList(bundle.retired_kids, 'retirement');
  const revoked = new Set(revokedKids);
  const retired = new Set(retiredKids);
  const { record } = getRootAuthenticatedCandidateKey(candidate, authority.active_signing_kid);
  if (record.revoked_at !== null || revoked.has(record.kid) || retired.has(record.kid)) {
    throw new LicenseApiError(503, 'ACTIVE_SIGNING_KEY_REVOKED_OR_RETIRED');
  }
  if (nowSeconds < record.not_before || (record.retire_after !== null && nowSeconds >= record.retire_after) ||
    (record.verify_until !== null && nowSeconds >= record.verify_until)) {
    throw new LicenseApiError(503, nowSeconds < record.not_before ? 'ACTIVE_SIGNING_KEY_NOT_YET_VALID' : 'ACTIVE_SIGNING_KEY_OUTSIDE_LIFECYCLE');
  }
  const resolver: TrustedSigningKeyResolver = createTrustedSigningKeyResolver(candidate, { revokedKids, trustedTime: nowSeconds });
  const base = {
    issuer: config.issuer,
    resolver,
    signerRevision: authority.signer_revision.toString(),
    bundleVersion: bundle.bundle_version,
    artifactSha256: bundle.artifact_sha256,
  };
  const material = config.signingKeyring.get(authority.active_signing_kid);
  if (!material) throw new LicenseApiError(503, 'ACTIVE_SIGNING_KEY_MATERIAL_UNAVAILABLE');
  if (material.kid !== record.kid || material.publicJwk.x !== record.x || material.publicJwk.crv !== record.crv || material.publicJwk.kty !== record.kty) {
    throw new LicenseApiError(503, 'ACTIVE_SIGNING_KEY_MATERIAL_MISMATCH');
  }
  const signer: SigningContext = Object.freeze({
    ...base,
    kid: material.kid,
    privateKey: material.privateKey,
    publicKey: material.publicKey,
    publicJwk: material.publicJwk,
  });
  return { signer, authority, trustBundle: bundle, candidate, now };
}

async function loadCandidate(
  bundle: LicenseSignerTrustBundleRow,
  config: RuntimeConfig,
  trustedTime: number,
): Promise<RootAuthenticatedTrustBundleCandidate> {
  if (bundle.root_kid !== config.trustedOfflineRoot.kid || trustBundleArtifactDigest(bundle.bundle_jws) !== bundle.artifact_sha256) {
    throw new LicenseApiError(503, 'SIGNING_TRUST_ARTIFACT_MISMATCH');
  }
  if (compareBundleVersions(bundle.bundle_version, config.minimumTrustBundleVersion) < 0) {
    throw new LicenseApiError(503, 'SIGNING_TRUST_BUNDLE_BELOW_MINIMUM');
  }
  let candidate = candidateCache.get(bundle.artifact_sha256);
  if (!candidate) {
    try {
      candidate = await verifyTrustBundleSignature(bundle.bundle_jws, {
        trustedRoot: config.trustedOfflineRoot,
        expectedCenterIssuer: config.issuer,
      });
    } catch {
      throw new LicenseApiError(503, 'SIGNING_TRUST_BUNDLE_SIGNATURE_INVALID');
    }
    if (candidate.artifactSha256 !== bundle.artifact_sha256 || candidate.claims.bundle_version !== bundle.bundle_version ||
      candidate.claims.sub !== config.issuer || candidate.rootKid !== bundle.root_kid || candidate.rootKid !== config.trustedOfflineRoot.kid) {
      throw new LicenseApiError(503, 'SIGNING_TRUST_ARTIFACT_MISMATCH');
    }
    candidateCache.set(bundle.artifact_sha256, candidate);
    if (candidateCache.size > 16) candidateCache.delete(candidateCache.keys().next().value!);
  }
  if (candidate.claims.sub !== config.issuer || candidate.rootKid !== config.trustedOfflineRoot.kid) {
    throw new LicenseApiError(503, 'SIGNING_TRUST_ARTIFACT_MISMATCH');
  }
  try { assertTrustBundleValidAt(candidate, trustedTime); } catch { throw new LicenseApiError(503, 'SIGNING_TRUST_BUNDLE_OUTSIDE_VALIDITY'); }
  return candidate;
}

function checkedKidList(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length > 256 || value.some((kid) => typeof kid !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(kid))) {
    throw new LicenseApiError(503, `SIGNING_${label.toUpperCase()}_HISTORY_CORRUPT`);
  }
  const kids = value as string[];
  if (new Set(kids).size !== kids.length || [...kids].sort().join(',') !== kids.join(',')) {
    throw new LicenseApiError(503, `SIGNING_${label.toUpperCase()}_HISTORY_CORRUPT`);
  }
  return kids;
}

export function sameTrustKeyIdentity(
  left: TrustBundleKeyRecord,
  right: { kid: string; publicJwkX: string },
): boolean {
  return left.kid === right.kid && left.x === right.publicJwkX;
}
