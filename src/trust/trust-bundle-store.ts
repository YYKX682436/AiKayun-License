import { constants as fsConstants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rename, unlink, lstat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { hostname } from 'node:os';
import type { CryptoKey } from 'jose';
import { parseStrictJson } from '../strict-json.js';
import type { TrustedSigningKeyResolver } from '../crypto/jwt.js';
import {
  assertMinimumBundleVersion,
  assertRootAuthenticatedCandidate,
  assertTrustBundleValidAt,
  compareBundleVersions,
  getRootAuthenticatedCandidateKey,
  trustBundleKeyAudience,
  verifyTrustBundleSignature,
  MAX_TRUSTED_KEY_TOMBSTONES,
} from './trust-bundle.js';
import type {
  RootAuthenticatedTrustBundleCandidate,
  TrustedOfflineRootPin,
} from './trust-bundle.js';

const STATE_FILE_NAME = 'trust-bundle-state.json';
// Upgrade the old marker path in place: its old schema is rejected, never treated as a fresh install.
const CHECKPOINT_FILE_NAME = 'trust-bundle-store.marker.json';
const MAX_STATE_BYTES = 32 * 1024;
const MAX_CHECKPOINT_BYTES = 64 * 1024;
const STATE_FIELDS = ['state_schema', 'bundle_version', 'artifact_sha256', 'token', 'revoked_kids', 'retired_kids'] as const;
const RECORD_FIELDS = ['bundle_version', 'artifact_sha256', 'token', 'revoked_kids', 'retired_kids'] as const;
const CHECKPOINT_FIELDS = [
  'checkpoint_schema', 'expected_center_issuer', 'trusted_root_kid', 'minimum_bundle_version', 'committed', 'pending',
] as const;
const PENDING_FIELDS = ['accepted_at', 'previous_version', 'previous_artifact_sha256', 'next'] as const;
const digestPattern = /^[A-Za-z0-9_-]{43}$/;
const directoryQueues = new Map<string, Promise<void>>();

export type TrustStoreWriteStage =
  | 'checkpoint_prepare_before_write'
  | 'checkpoint_prepare_after_partial_write'
  | 'checkpoint_prepare_after_write'
  | 'checkpoint_prepare_after_file_fsync'
  | 'checkpoint_prepare_after_rename'
  | 'checkpoint_prepare_after_directory_fsync'
  | 'state_before_write'
  | 'state_after_partial_write'
  | 'state_after_write'
  | 'state_after_file_fsync'
  | 'state_after_rename'
  | 'state_after_directory_fsync'
  | 'checkpoint_commit_before_write'
  | 'checkpoint_commit_after_partial_write'
  | 'checkpoint_commit_after_write'
  | 'checkpoint_commit_after_file_fsync'
  | 'checkpoint_commit_after_rename'
  | 'checkpoint_commit_after_directory_fsync'
  | 'checkpoint_recovery_before_write'
  | 'checkpoint_recovery_after_partial_write'
  | 'checkpoint_recovery_after_write'
  | 'checkpoint_recovery_after_file_fsync'
  | 'checkpoint_recovery_after_rename'
  | 'checkpoint_recovery_after_directory_fsync';

export interface TrustBundleStoreOptions {
  directory: string;
  trustedRoot: TrustedOfflineRootPin;
  expectedCenterIssuer: string;
  /** Supplied by the trusted release artifact; never inferred from a downloaded package. */
  minimumBundleVersion: string;
  /** Deterministic fault injection for filesystem recovery tests. */
  faultAt?: (stage: TrustStoreWriteStage) => void | Promise<void>;
}

export interface AcceptedTrustBundle {
  readonly token: string;
  readonly artifactSha256: string;
  readonly bundleVersion: string;
  readonly centerIssuer: string;
  readonly acceptedIdempotently: boolean;
  readonly revokedKids: readonly string[];
  readonly retiredKids: readonly string[];
  readonly claims: RootAuthenticatedTrustBundleCandidate['claims'];
  readonly resolver: TrustedSigningKeyResolver;
}

interface BundleRecord {
  bundle_version: string;
  artifact_sha256: string;
  token: string;
  revoked_kids: string[];
  retired_kids: string[];
}

interface PendingRecord {
  accepted_at: number;
  previous_version: string | null;
  previous_artifact_sha256: string | null;
  next: BundleRecord;
}

interface DurableCheckpoint {
  checkpoint_schema: 2;
  expected_center_issuer: string;
  trusted_root_kid: string;
  minimum_bundle_version: string;
  committed: BundleRecord | null;
  pending: PendingRecord | null;
}

interface LoadedRecord {
  record: BundleRecord;
  candidate: RootAuthenticatedTrustBundleCandidate;
}

function isPrivateStateFileMode(value: number | bigint): boolean {
  const numeric = Number(value);
  const permission = numeric & 0o777;
  return (permission === 0o400 || permission === 0o600) && (numeric & 0o7000) === 0;
}

function exactFields(value: Record<string, unknown>, fields: readonly string[]): void {
  if (Object.keys(value).sort().join('\n') !== [...fields].sort().join('\n')) throw new Error('Trust bundle durable state has an invalid schema');
}

function positiveTrustedTime(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error('A trusted integer time is required');
  return value;
}

function safeDigest(value: unknown): string {
  if (typeof value !== 'string' || !digestPattern.test(value) || Buffer.from(value, 'base64url').toString('base64url') !== value) {
    throw new Error('Trust bundle durable digest is invalid');
  }
  return value;
}

function safeKid(value: unknown): string {
  return safeDigest(value);
}

function safeRevocations(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > MAX_TRUSTED_KEY_TOMBSTONES) throw new Error('Trust bundle revocation history is invalid');
  const revoked = value.map(safeKid);
  if (new Set(revoked).size !== revoked.length || [...revoked].sort().join(',') !== revoked.join(',')) {
    throw new Error('Trust bundle revocation history is not canonical');
  }
  return revoked;
}

function assertTombstoneCapacity(revokedKids: readonly string[], retiredKids: readonly string[]): void {
  if (revokedKids.some((kid) => retiredKids.includes(kid))) {
    throw new Error('Emergency revocation and permanent retirement tombstones must remain distinct');
  }
  if (revokedKids.length + retiredKids.length > MAX_TRUSTED_KEY_TOMBSTONES) {
    throw new Error('Trust key tombstone capacity is full; refusing to discard security history');
  }
}

function revokedKidsFor(candidate: RootAuthenticatedTrustBundleCandidate, previous: readonly string[]): string[] {
  const all = new Set(previous);
  for (const key of candidate.claims.keys) if (key.revoked_at !== null) all.add(key.kid);
  if (all.size > MAX_TRUSTED_KEY_TOMBSTONES) throw new Error('Trust bundle revocation history is full; refusing to discard revocation history');
  return [...all].sort();
}

function retiredKidsFor(
  previous: RootAuthenticatedTrustBundleCandidate | null,
  next: RootAuthenticatedTrustBundleCandidate,
  previousRevoked: readonly string[],
  previousRetired: readonly string[],
  acceptedAt: number,
): string[] {
  const retired = new Set(previousRetired);
  const nextKids = new Set(next.claims.keys.map((key) => key.kid));
  const revoked = new Set(previousRevoked);
  for (const key of previous?.claims.keys ?? []) {
    if (revoked.has(key.kid) || key.revoked_at !== null || nextKids.has(key.kid)) continue;
    if (key.retire_after !== null && key.verify_until !== null && acceptedAt >= key.verify_until) retired.add(key.kid);
  }
  if (retired.size > MAX_TRUSTED_KEY_TOMBSTONES) {
    throw new Error('Permanent retirement history is full; refusing to discard retired key identities');
  }
  return [...retired].sort();
}

function assertNoRevocationResurrection(
  candidate: RootAuthenticatedTrustBundleCandidate,
  revokedKids: readonly string[],
): void {
  const tombstones = new Set(revokedKids);
  for (const key of candidate.claims.keys) {
    if (tombstones.has(key.kid) && key.revoked_at === null) throw new Error('A previously revoked center key cannot be reactivated');
  }
}

function assertNoRetirementResurrection(
  candidate: RootAuthenticatedTrustBundleCandidate,
  retiredKids: readonly string[],
): void {
  const tombstones = new Set(retiredKids);
  for (const key of candidate.claims.keys) {
    if (tombstones.has(key.kid)) throw new Error('A permanently retired center key identity cannot be reused');
  }
}

function assertLifecycleTransition(
  previous: RootAuthenticatedTrustBundleCandidate,
  next: RootAuthenticatedTrustBundleCandidate,
  previousRevokedKids: readonly string[],
  acceptedAt: number,
): void {
  const nextByKid = new Map(next.claims.keys.map((record) => [record.kid, record]));
  const tombstones = new Set(previousRevokedKids);
  for (const oldKey of previous.claims.keys) {
    if (tombstones.has(oldKey.kid) || oldKey.revoked_at !== null) continue;
    const replacement = nextByKid.get(oldKey.kid);
    if (!replacement) {
      if (oldKey.retire_after === null || oldKey.verify_until === null || acceptedAt < oldKey.verify_until) {
        throw new Error(`Active signing key ${oldKey.kid} cannot be removed before retirement and verification retention complete`);
      }
      continue;
    }
    if (replacement.not_before !== oldKey.not_before) {
      throw new Error(`Signing key ${oldKey.kid} not_before is immutable after acceptance`);
    }
    if (oldKey.retire_after === null) {
      if (replacement.retire_after !== null && replacement.retire_after < acceptedAt) {
        throw new Error(`Signing key ${oldKey.kid} retirement cannot be backdated`);
      }
    } else if (replacement.retire_after !== oldKey.retire_after || replacement.verify_until !== oldKey.verify_until) {
      throw new Error(`Signing key ${oldKey.kid} retirement and verification windows are immutable once set`);
    }
  }

  const previousKeys = new Map(previous.claims.keys.map((record) => [record.kid, record]));
  for (const key of next.claims.keys) {
    const oldKey = previousKeys.get(key.kid);
    if (!oldKey) continue;
    if (tombstones.has(key.kid) && key.revoked_at === null) throw new Error('A previously revoked center key cannot be reactivated');
    if (oldKey.revoked_at !== null && key.revoked_at === null) throw new Error('A revoked center key cannot be reactivated');
    if (oldKey.revoked_at !== null && key.revoked_at !== oldKey.revoked_at) throw new Error('A key revocation timestamp is immutable');
  }
}

export function validateTrustBundleTransition(input: {
  previous: RootAuthenticatedTrustBundleCandidate | null;
  next: RootAuthenticatedTrustBundleCandidate;
  previousRevokedKids: readonly string[];
  previousRetiredKids: readonly string[];
  acceptedAt: number;
}): { revokedKids: string[]; retiredKids: string[] } {
  const now = positiveTrustedTime(input.acceptedAt);
  const revokedKids = revokedKidsFor(input.next, input.previousRevokedKids);
  assertNoRevocationResurrection(input.next, revokedKids);
  if (input.previous) assertLifecycleTransition(input.previous, input.next, input.previousRevokedKids, now);
  const retiredKids = retiredKidsFor(
    input.previous,
    input.next,
    input.previousRevokedKids,
    input.previousRetiredKids,
    now,
  );
  assertNoRetirementResurrection(input.next, retiredKids);
  assertTombstoneCapacity(revokedKids, retiredKids);
  return { revokedKids, retiredKids };
}

function sameRecord(left: BundleRecord | null, right: BundleRecord | null): boolean {
  if (left === null || right === null) return left === right;
  return left.bundle_version === right.bundle_version && left.artifact_sha256 === right.artifact_sha256 &&
    left.token === right.token && left.revoked_kids.join(',') === right.revoked_kids.join(',') &&
    left.retired_kids.join(',') === right.retired_kids.join(',');
}

function recordFromCandidate(
  candidate: RootAuthenticatedTrustBundleCandidate,
  revokedKids: readonly string[],
  retiredKids: readonly string[],
): BundleRecord {
  assertTombstoneCapacity(revokedKids, retiredKids);
  return {
    bundle_version: candidate.claims.bundle_version,
    artifact_sha256: candidate.artifactSha256,
    token: candidate.token,
    revoked_kids: [...revokedKids].sort(),
    retired_kids: [...retiredKids].sort(),
  };
}

function resolverFor(
  candidate: RootAuthenticatedTrustBundleCandidate,
  revokedKids: readonly string[],
  trustedTime: number,
  assertStillCurrent: () => Promise<void>,
): TrustedSigningKeyResolver {
  assertRootAuthenticatedCandidate(candidate);
  const now = positiveTrustedTime(trustedTime);
  assertTrustBundleValidAt(candidate, now);
  const tombstones = new Set(revokedKids);
  return Object.freeze({
    resolveKey: async (input: {
      kid: string;
      targetIssuer: string;
      jwtTyp: string;
      audience: string;
      trustedTime: number;
      issuedAt: number;
      expiresAt: number;
    }): Promise<{ publicKey: CryptoKey; verifyUntil: number | null }> => {
      await assertStillCurrent();
      if (input.targetIssuer !== candidate.claims.sub || input.trustedTime !== now ||
        trustBundleKeyAudience(input.jwtTyp) !== input.audience || !Number.isSafeInteger(input.issuedAt) ||
        !Number.isSafeInteger(input.expiresAt) || input.issuedAt <= 0 || input.expiresAt <= input.issuedAt ||
        input.issuedAt > now) throw new Error('Trust key request does not match the accepted bundle context');
      const { record, publicKey } = getRootAuthenticatedCandidateKey(candidate, input.kid);
      if (record.revoked_at !== null || tombstones.has(record.kid)) throw new Error('Center signing key has been emergency-revoked');
      if (input.issuedAt < record.not_before || (record.retire_after !== null && input.issuedAt > record.retire_after)) {
        throw new Error('JWT was signed outside the center key issuance window');
      }
      if (record.verify_until !== null && (now >= record.verify_until || input.expiresAt > record.verify_until)) {
        throw new Error('Center key verification-retention window has ended');
      }
      return { publicKey, verifyUntil: record.verify_until };
    },
  });
}

export function createTrustedSigningKeyResolver(
  candidate: RootAuthenticatedTrustBundleCandidate,
  input: { revokedKids?: readonly string[]; trustedTime: number },
): TrustedSigningKeyResolver {
  return resolverFor(candidate, input.revokedKids ?? [], input.trustedTime, async () => undefined);
}

export class TrustBundleStore {
  readonly directory: string;
  readonly trustedRoot: TrustedOfflineRootPin;
  readonly expectedCenterIssuer: string;
  readonly minimumBundleVersion: string;
  private readonly faultAt: ((stage: TrustStoreWriteStage) => void | Promise<void>) | undefined;

  constructor(options: TrustBundleStoreOptions) {
    this.directory = resolve(options.directory);
    this.trustedRoot = Object.freeze({
      kid: options.trustedRoot.kid,
      publicJwk: Object.freeze({ ...options.trustedRoot.publicJwk }),
    });
    this.expectedCenterIssuer = options.expectedCenterIssuer;
    this.minimumBundleVersion = assertMinimumBundleVersion(options.minimumBundleVersion);
    this.faultAt = options.faultAt;
  }

  async accept(token: unknown, trustedTime: number): Promise<AcceptedTrustBundle> {
    const now = positiveTrustedTime(trustedTime);
    const candidate = await verifyTrustBundleSignature(token, {
      trustedRoot: this.trustedRoot,
      expectedCenterIssuer: this.expectedCenterIssuer,
    });
    assertTrustBundleValidAt(candidate, now);
    if (compareBundleVersions(candidate.claims.bundle_version, this.minimumBundleVersion) < 0) {
      throw new Error('Trust bundle is below the release-pinned minimum version');
    }

    return this.withWriteLock(async () => {
      let checkpoint = await this.recoverCheckpoint();
      if (!checkpoint) {
        checkpoint = {
          checkpoint_schema: 2,
          expected_center_issuer: this.expectedCenterIssuer,
          trusted_root_kid: this.trustedRoot.kid,
          minimum_bundle_version: this.minimumBundleVersion,
          committed: null,
          pending: null,
        };
      } else if (compareBundleVersions(this.minimumBundleVersion, checkpoint.minimum_bundle_version) > 0) {
        checkpoint = { ...checkpoint, minimum_bundle_version: this.minimumBundleVersion };
        await this.writeCheckpoint(checkpoint, 'checkpoint_prepare');
      }

      const previousRecord = checkpoint.committed;
      const previous = previousRecord ? await this.loadRecord(previousRecord) : null;
      if (previousRecord) {
        const ordering = compareBundleVersions(candidate.claims.bundle_version, previousRecord.bundle_version);
        if (ordering < 0) throw new Error('Trust bundle version rollback rejected');
        if (ordering === 0) {
          if (candidate.artifactSha256 !== previousRecord.artifact_sha256 || candidate.token !== previousRecord.token) {
            throw new Error('Same trust bundle version has a different signed artifact');
          }
          return this.toAccepted(candidate, previousRecord.revoked_kids, previousRecord.retired_kids, now, true);
        }
      }

      const { revokedKids, retiredKids } = validateTrustBundleTransition({
        previous: previous?.candidate ?? null,
        next: candidate,
        previousRevokedKids: previousRecord?.revoked_kids ?? [],
        previousRetiredKids: previousRecord?.retired_kids ?? [],
        acceptedAt: now,
      });
      const next = recordFromCandidate(candidate, revokedKids, retiredKids);
      const pending: PendingRecord = {
        accepted_at: now,
        previous_version: previousRecord?.bundle_version ?? null,
        previous_artifact_sha256: previousRecord?.artifact_sha256 ?? null,
        next,
      };
      await this.writeCheckpoint({ ...checkpoint, pending }, 'checkpoint_prepare');
      await this.writeState(next, 'state');
      const committed: DurableCheckpoint = { ...checkpoint, committed: next, pending: null };
      await this.writeCheckpoint(committed, 'checkpoint_commit');
      return this.toAccepted(candidate, revokedKids, retiredKids, now, false);
    });
  }

  async getAccepted(trustedTime: number): Promise<AcceptedTrustBundle> {
    const now = positiveTrustedTime(trustedTime);
    return this.withWriteLock(async () => {
      const checkpoint = await this.recoverCheckpoint();
      if (!checkpoint?.committed) throw new Error('No accepted trust bundle is persisted');
      if (compareBundleVersions(checkpoint.committed.bundle_version, checkpoint.minimum_bundle_version) < 0 ||
        compareBundleVersions(checkpoint.committed.bundle_version, this.minimumBundleVersion) < 0) {
        throw new Error('Persisted trust bundle is below the release-pinned minimum version');
      }
      const loaded = await this.loadRecord(checkpoint.committed);
      assertTrustBundleValidAt(loaded.candidate, now);
      return this.toAccepted(loaded.candidate, checkpoint.committed.revoked_kids, checkpoint.committed.retired_kids, now, true);
    });
  }

  private toAccepted(
    candidate: RootAuthenticatedTrustBundleCandidate,
    revokedKids: readonly string[],
    retiredKids: readonly string[],
    trustedTime: number,
    acceptedIdempotently: boolean,
  ): AcceptedTrustBundle {
    return Object.freeze({
      token: candidate.token,
      artifactSha256: candidate.artifactSha256,
      bundleVersion: candidate.claims.bundle_version,
      centerIssuer: candidate.claims.sub,
      acceptedIdempotently,
      revokedKids: Object.freeze([...revokedKids]),
      retiredKids: Object.freeze([...retiredKids]),
      claims: candidate.claims,
      resolver: resolverFor(candidate, revokedKids, trustedTime, () => this.assertStillCurrent(candidate, revokedKids, retiredKids)),
    });
  }

  private async assertStillCurrent(
    candidate: RootAuthenticatedTrustBundleCandidate,
    revokedKids: readonly string[],
    retiredKids: readonly string[],
  ): Promise<void> {
    await this.withWriteLock(async () => {
      const checkpoint = await this.recoverCheckpoint();
      const current = checkpoint?.committed;
      if (!current || current.artifact_sha256 !== candidate.artifactSha256 ||
        current.bundle_version !== candidate.claims.bundle_version || current.revoked_kids.join(',') !== revokedKids.join(',') ||
        current.retired_kids.join(',') !== retiredKids.join(',')) {
        throw new Error('Trust key resolver is stale after a bundle or revocation update');
      }
    });
  }

  private async recoverCheckpoint(): Promise<DurableCheckpoint | null> {
    await this.ensurePrivateDirectory();
    const checkpoint = await this.readCheckpoint();
    const state = await this.readState();
    if (!checkpoint) {
      if (state) throw new Error('Trust bundle state exists without its independent monotonic checkpoint');
      return null;
    }
    if (compareBundleVersions(this.minimumBundleVersion, checkpoint.minimum_bundle_version) < 0) {
      throw new Error('Trusted release baseline is older than the durable checkpoint baseline');
    }
    if (checkpoint.pending) {
      const pending = checkpoint.pending;
      if (pending.previous_version !== (checkpoint.committed?.bundle_version ?? null) ||
        pending.previous_artifact_sha256 !== (checkpoint.committed?.artifact_sha256 ?? null)) {
        throw new Error('Trust bundle checkpoint pending transition does not extend its committed head');
      }
      const previous = checkpoint.committed ? await this.loadRecord(checkpoint.committed) : null;
      const next = await this.loadRecord(pending.next);
      const committedState = state?.record ?? null;
      if (sameRecord(committedState, checkpoint.committed)) {
        const aborted: DurableCheckpoint = { ...checkpoint, pending: null };
        await this.writeCheckpoint(aborted, 'checkpoint_recovery');
        return aborted;
      }
      if (sameRecord(committedState, pending.next)) {
        assertTrustBundleValidAt(next.candidate, positiveTrustedTime(pending.accepted_at));
        if (compareBundleVersions(next.candidate.claims.bundle_version, checkpoint.minimum_bundle_version) < 0) {
          throw new Error('Pending trust bundle is below the checkpoint minimum version');
        }
        if (previous) {
          if (compareBundleVersions(next.candidate.claims.bundle_version, previous.candidate.claims.bundle_version) <= 0) {
            throw new Error('Pending trust bundle does not advance its committed version');
          }
          assertLifecycleTransition(previous.candidate, next.candidate, checkpoint.committed!.revoked_kids, pending.accepted_at);
        }
        const expectedRevocations = revokedKidsFor(next.candidate, checkpoint.committed?.revoked_kids ?? []);
        if (expectedRevocations.join(',') !== pending.next.revoked_kids.join(',')) {
          throw new Error('Pending trust bundle revocation history is inconsistent');
        }
        const expectedRetirements = retiredKidsFor(
          previous?.candidate ?? null,
          next.candidate,
          checkpoint.committed?.revoked_kids ?? [],
          checkpoint.committed?.retired_kids ?? [],
          pending.accepted_at,
        );
        if (expectedRetirements.join(',') !== pending.next.retired_kids.join(',')) {
          throw new Error('Pending trust bundle permanent retirement history is inconsistent');
        }
        assertNoRevocationResurrection(next.candidate, expectedRevocations);
        assertNoRetirementResurrection(next.candidate, expectedRetirements);
        const committed: DurableCheckpoint = { ...checkpoint, committed: pending.next, pending: null };
        await this.writeCheckpoint(committed, 'checkpoint_recovery');
        return committed;
      }
      throw new Error('Trust bundle state does not match either side of its pending checkpoint transition');
    }
    if (!sameRecord(state?.record ?? null, checkpoint.committed)) {
      throw new Error('Trust bundle state does not match its independent monotonic checkpoint');
    }
    if (checkpoint.committed) await this.loadRecord(checkpoint.committed);
    if (compareBundleVersions(this.minimumBundleVersion, checkpoint.minimum_bundle_version) > 0) {
      const raised: DurableCheckpoint = { ...checkpoint, minimum_bundle_version: this.minimumBundleVersion };
      await this.writeCheckpoint(raised, 'checkpoint_recovery');
      return raised;
    }
    return checkpoint;
  }

  private async readCheckpoint(): Promise<DurableCheckpoint | null> {
    const file = join(this.directory, CHECKPOINT_FILE_NAME);
    let metadata;
    try { metadata = await lstat(file); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    }
    if (!metadata.isFile() || metadata.isSymbolicLink() || !isPrivateStateFileMode(metadata.mode) ||
      metadata.size <= 0 || metadata.size > MAX_CHECKPOINT_BYTES) throw new Error('Trust bundle checkpoint file is damaged');
    const bytes = await readFile(file);
    if (bytes.byteLength !== metadata.size) throw new Error('Trust bundle checkpoint changed while being read');
    const value = parseStrictJson(bytes);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Trust bundle checkpoint is malformed');
    const row = value as Record<string, unknown>;
    exactFields(row, CHECKPOINT_FIELDS);
    const minimum = assertMinimumBundleVersion(row['minimum_bundle_version']);
    if (row['checkpoint_schema'] !== 2 || row['expected_center_issuer'] !== this.expectedCenterIssuer ||
      row['trusted_root_kid'] !== this.trustedRoot.kid ||
      !(row['committed'] === null || (row['committed'] && typeof row['committed'] === 'object' && !Array.isArray(row['committed']))) ||
      !(row['pending'] === null || (row['pending'] && typeof row['pending'] === 'object' && !Array.isArray(row['pending'])))) {
      throw new Error('Trust bundle checkpoint does not match this trusted release');
    }
    const committed = row['committed'] === null ? null : await this.parseRecord(row['committed'] as Record<string, unknown>);
    let pending: PendingRecord | null = null;
    if (row['pending'] !== null) {
      const pendingRow = row['pending'] as Record<string, unknown>;
      exactFields(pendingRow, PENDING_FIELDS);
      const acceptedAt = positiveTrustedTime(pendingRow['accepted_at'] as number);
      const previousVersion = pendingRow['previous_version'];
      const previousDigest = pendingRow['previous_artifact_sha256'];
      if (!((previousVersion === null && previousDigest === null) ||
        (typeof previousVersion === 'string' && typeof previousDigest === 'string' && safeDigest(previousDigest)))) {
        throw new Error('Trust bundle checkpoint pending predecessor is malformed');
      }
      if (!pendingRow['next'] || typeof pendingRow['next'] !== 'object' || Array.isArray(pendingRow['next'])) {
        throw new Error('Trust bundle checkpoint pending package is malformed');
      }
      pending = {
        accepted_at: acceptedAt,
        previous_version: previousVersion as string | null,
        previous_artifact_sha256: previousDigest as string | null,
        next: await this.parseRecord(pendingRow['next'] as Record<string, unknown>),
      };
    }
    if (committed && compareBundleVersions(committed.bundle_version, minimum) < 0) {
      throw new Error('Trust bundle checkpoint head is below its pinned minimum version');
    }
    return {
      checkpoint_schema: 2,
      expected_center_issuer: this.expectedCenterIssuer,
      trusted_root_kid: this.trustedRoot.kid,
      minimum_bundle_version: minimum,
      committed,
      pending,
    };
  }

  private async readState(): Promise<LoadedRecord | null> {
    const file = join(this.directory, STATE_FILE_NAME);
    let metadata;
    try { metadata = await lstat(file); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    }
    if (!metadata.isFile() || metadata.isSymbolicLink() || !isPrivateStateFileMode(metadata.mode) ||
      metadata.size <= 0 || metadata.size > MAX_STATE_BYTES) throw new Error('Trust bundle state file is damaged');
    const bytes = await readFile(file);
    if (bytes.byteLength !== metadata.size) throw new Error('Trust bundle state changed while being read');
    const value = parseStrictJson(bytes);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Trust bundle state is malformed');
    const row = value as Record<string, unknown>;
    exactFields(row, STATE_FIELDS);
    if (row['state_schema'] !== 2) throw new Error('Trust bundle state schema is unsupported');
    const record = await this.parseRecord({
      bundle_version: row['bundle_version'],
      artifact_sha256: row['artifact_sha256'],
      token: row['token'],
      revoked_kids: row['revoked_kids'],
      retired_kids: row['retired_kids'],
    });
    return { record, candidate: (await this.loadRecord(record)).candidate };
  }

  private async parseRecord(value: Record<string, unknown>): Promise<BundleRecord> {
    exactFields(value, RECORD_FIELDS);
    const version = assertMinimumBundleVersion(value['bundle_version']);
    const digest = safeDigest(value['artifact_sha256']);
    if (typeof value['token'] !== 'string' || value['token'].length === 0) throw new Error('Trust bundle durable token is malformed');
    const revokedKids = safeRevocations(value['revoked_kids']);
    const retiredKids = safeRevocations(value['retired_kids']);
    assertTombstoneCapacity(revokedKids, retiredKids);
    return {
      bundle_version: version,
      artifact_sha256: digest,
      token: value['token'],
      revoked_kids: revokedKids,
      retired_kids: retiredKids,
    };
  }

  private async loadRecord(record: BundleRecord): Promise<LoadedRecord> {
    const candidate = await verifyTrustBundleSignature(record.token, {
      trustedRoot: this.trustedRoot,
      expectedCenterIssuer: this.expectedCenterIssuer,
    });
    if (candidate.artifactSha256 !== record.artifact_sha256 || candidate.claims.bundle_version !== record.bundle_version) {
      throw new Error('Persisted trust bundle does not match its durable checkpoint identity');
    }
    assertNoRevocationResurrection(candidate, record.revoked_kids);
    assertNoRetirementResurrection(candidate, record.retired_kids);
    for (const key of candidate.claims.keys) {
      if (key.revoked_at !== null && !record.revoked_kids.includes(key.kid)) {
        throw new Error('Durable checkpoint is missing a signed key revocation tombstone');
      }
    }
    return { record, candidate };
  }

  private async writeState(record: BundleRecord, prefix: 'state'): Promise<void> {
    const state = { state_schema: 2 as const, ...record };
    await this.writeAtomicJson(STATE_FILE_NAME, state, prefix, MAX_STATE_BYTES);
  }

  private async writeCheckpoint(checkpoint: DurableCheckpoint, prefix: 'checkpoint_prepare' | 'checkpoint_commit' | 'checkpoint_recovery'): Promise<void> {
    await this.writeAtomicJson(CHECKPOINT_FILE_NAME, checkpoint, prefix, MAX_CHECKPOINT_BYTES);
  }

  private async writeAtomicJson(
    fileName: string,
    value: unknown,
    prefix: 'state' | 'checkpoint_prepare' | 'checkpoint_commit' | 'checkpoint_recovery',
    maxBytes: number,
  ): Promise<void> {
    await this.ensurePrivateDirectory();
    const file = join(this.directory, fileName);
    try {
      const current = await lstat(file);
      if (!current.isFile() || current.isSymbolicLink()) throw new Error(`Refusing to replace a non-regular trust bundle ${fileName}`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    const bytes = Buffer.from(JSON.stringify(value), 'utf8');
    if (bytes.byteLength > maxBytes) throw new Error(`Trust bundle ${fileName} exceeds its storage limit`);
    const temporary = join(this.directory, `.${fileName}-${process.pid}-${randomBytes(12).toString('hex')}.tmp`);
    let handle;
    let renamed = false;
    try {
      handle = await open(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
      await this.faultAt?.(`${prefix}_before_write` as TrustStoreWriteStage);
      if (this.faultAt) {
        const half = Math.max(1, Math.floor(bytes.byteLength / 2));
        await handle.write(bytes.subarray(0, half), 0, half, 0);
        await this.faultAt(`${prefix}_after_partial_write` as TrustStoreWriteStage);
        await handle.write(bytes.subarray(half), 0, bytes.byteLength - half, half);
      } else {
        await handle.writeFile(bytes);
      }
      await this.faultAt?.(`${prefix}_after_write` as TrustStoreWriteStage);
      await handle.sync();
      await this.faultAt?.(`${prefix}_after_file_fsync` as TrustStoreWriteStage);
      await handle.close();
      handle = undefined;
      await rename(temporary, file);
      renamed = true;
      await this.faultAt?.(`${prefix}_after_rename` as TrustStoreWriteStage);
      const directoryHandle = await open(this.directory, fsConstants.O_RDONLY);
      try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
      await this.faultAt?.(`${prefix}_after_directory_fsync` as TrustStoreWriteStage);
    } finally {
      await handle?.close().catch(() => undefined);
      if (!renamed) await unlink(temporary).catch(() => undefined);
    }
  }

  private async ensurePrivateDirectory(): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const metadata = await lstat(this.directory);
    const mode = Number(metadata.mode);
    const permissions = mode & 0o777;
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || (permissions & 0o077) !== 0 ||
      (permissions & 0o700) !== 0o700 || (mode & 0o7000) !== 0) {
      throw new Error('Trust bundle state directory must be a private regular directory');
    }
  }

  private async withWriteLock<T>(work: () => Promise<T>): Promise<T> {
    const directory = this.directory;
    const previous = directoryQueues.get(directory) ?? Promise.resolve();
    let release!: () => void;
    const hold = new Promise<void>((resolveHold) => { release = resolveHold; });
    const tail = previous.catch(() => undefined).then(() => hold);
    directoryQueues.set(directory, tail);
    await previous.catch(() => undefined);
    try {
      await this.acquireFilesystemLock();
      try { return await work(); } finally { await this.releaseFilesystemLock(); }
    } finally {
      release();
      if (directoryQueues.get(directory) === tail) directoryQueues.delete(directory);
    }
  }

  private async acquireFilesystemLock(): Promise<void> {
    await this.ensurePrivateDirectory();
    const path = join(this.directory, '.trust-bundle-write.lock');
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const handle = await open(path, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
        try {
          await handle.writeFile(JSON.stringify({ pid: process.pid, host: hostname() }));
          await handle.sync();
        } finally {
          await handle.close();
        }
        const directoryHandle = await open(this.directory, fsConstants.O_RDONLY);
        try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
        return;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
        const metadata = await lstat(path);
        if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 512 || !isPrivateStateFileMode(metadata.mode)) {
          throw new Error('Trust bundle writer lock is damaged');
        }
        const parsed = parseStrictJson(await readFile(path));
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Trust bundle writer lock is malformed');
        const lock = parsed as Record<string, unknown>;
        exactFields(lock, ['pid', 'host']);
        if (!Number.isSafeInteger(lock['pid']) || (lock['pid'] as number) < 1 || typeof lock['host'] !== 'string') {
          throw new Error('Trust bundle writer lock is malformed');
        }
        if (lock['host'] !== hostname()) throw new Error('Trust bundle store has an active writer on another host');
        let alive = true;
        try { process.kill(lock['pid'] as number, 0); } catch (probeError) {
          if ((probeError as NodeJS.ErrnoException).code === 'ESRCH') alive = false;
          else if ((probeError as NodeJS.ErrnoException).code !== 'EPERM') throw probeError;
        }
        if (alive) throw new Error('Trust bundle store already has an active writer');
        await unlink(path);
        const directoryHandle = await open(this.directory, fsConstants.O_RDONLY);
        try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
      }
    }
    throw new Error('Could not acquire trust bundle writer lock');
  }

  private async releaseFilesystemLock(): Promise<void> {
    const path = join(this.directory, '.trust-bundle-write.lock');
    await unlink(path);
    const directoryHandle = await open(this.directory, fsConstants.O_RDONLY);
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  }
}
