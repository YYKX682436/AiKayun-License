import { constants as fsConstants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { lstat, mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
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
} from './trust-bundle.js';
import type {
  RootAuthenticatedTrustBundleCandidate,
  TrustedOfflineRootPin,
} from './trust-bundle.js';

const STATE_FILE_NAME = 'trust-bundle-state.json';
const MARKER_FILE_NAME = 'trust-bundle-store.marker.json';
const MAX_STATE_BYTES = 32 * 1024;
const STATE_FIELDS = [
  'state_schema', 'minimum_bundle_version', 'highest_bundle_version', 'artifact_sha256', 'token', 'revoked_kids',
] as const;
const digestPattern = /^[A-Za-z0-9_-]{43}$/;
const directoryQueues = new Map<string, Promise<void>>();

function isPrivateStateFileMode(value: number | bigint): boolean {
  const numeric = Number(value);
  const permission = numeric & 0o777;
  return (permission === 0o400 || permission === 0o600) && (numeric & 0o7000) === 0;
}

export type TrustStoreWriteStage =
  | 'before_write'
  | 'after_partial_write'
  | 'after_write'
  | 'after_file_fsync'
  | 'after_rename'
  | 'after_directory_fsync';

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
  readonly claims: RootAuthenticatedTrustBundleCandidate['claims'];
  readonly resolver: TrustedSigningKeyResolver;
}

interface PersistedState {
  state_schema: 1;
  minimum_bundle_version: string;
  highest_bundle_version: string;
  artifact_sha256: string;
  token: string;
  revoked_kids: string[];
}

function exactFields(value: Record<string, unknown>, fields: readonly string[]): void {
  if (Object.keys(value).sort().join('\n') !== [...fields].sort().join('\n')) throw new Error('Trust bundle store has an invalid schema');
}

function positiveTrustedTime(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error('A trusted integer time is required');
  return value;
}

function safeDigest(value: unknown): string {
  if (typeof value !== 'string' || !digestPattern.test(value) || Buffer.from(value, 'base64url').toString('base64url') !== value) {
    throw new Error('Trust bundle store digest is invalid');
  }
  return value;
}

function safeKid(value: unknown): string {
  return safeDigest(value);
}

function revokedKidsFor(candidate: RootAuthenticatedTrustBundleCandidate, previous: readonly string[]): string[] {
  const all = new Set(previous);
  for (const key of candidate.claims.keys) if (key.revoked_at !== null) all.add(key.kid);
  if (all.size > 256) throw new Error('Trust bundle revocation history exceeds the supported local bound');
  return [...all].sort();
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
      const previous = await this.readPersistedState();
      if (previous) {
        const ordering = compareBundleVersions(candidate.claims.bundle_version, previous.highest_bundle_version);
        if (ordering < 0) throw new Error('Trust bundle version rollback rejected');
        if (ordering === 0) {
          if (candidate.artifactSha256 !== previous.artifact_sha256 || candidate.token !== previous.token) {
            throw new Error('Same trust bundle version has a different signed artifact');
          }
          if (compareBundleVersions(previous.highest_bundle_version, this.minimumBundleVersion) < 0) {
            throw new Error('Stored trust bundle is below the release-pinned minimum version');
          }
          return this.toAccepted(candidate, previous.revoked_kids, now, true);
        }
      }

      const revokedKids = revokedKidsFor(candidate, previous?.revoked_kids ?? []);
      assertNoRevocationResurrection(candidate, revokedKids);
      const nextBaseline = previous && compareBundleVersions(previous.minimum_bundle_version, this.minimumBundleVersion) > 0
        ? previous.minimum_bundle_version
        : this.minimumBundleVersion;
      const state: PersistedState = {
        state_schema: 1,
        minimum_bundle_version: nextBaseline,
        highest_bundle_version: candidate.claims.bundle_version,
        artifact_sha256: candidate.artifactSha256,
        token: candidate.token,
        revoked_kids: revokedKids,
      };
      await this.writePersistedState(state);
      return this.toAccepted(candidate, revokedKids, now, false);
    });
  }

  async getAccepted(trustedTime: number): Promise<AcceptedTrustBundle> {
    const now = positiveTrustedTime(trustedTime);
    const state = await this.readPersistedState();
    if (!state) throw new Error('No accepted trust bundle is persisted');
    const requiredMinimum = compareBundleVersions(state.minimum_bundle_version, this.minimumBundleVersion) > 0
      ? state.minimum_bundle_version
      : this.minimumBundleVersion;
    if (compareBundleVersions(state.highest_bundle_version, requiredMinimum) < 0) {
      throw new Error('Persisted trust bundle is below the release-pinned minimum version');
    }
    const candidate = await this.candidateFromState(state);
    assertTrustBundleValidAt(candidate, now);
    return this.toAccepted(candidate, state.revoked_kids, now, true);
  }

  private toAccepted(
    candidate: RootAuthenticatedTrustBundleCandidate,
    revokedKids: readonly string[],
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
      claims: candidate.claims,
      resolver: resolverFor(candidate, revokedKids, trustedTime, () => this.assertStillCurrent(candidate, revokedKids)),
    });
  }

  private async assertStillCurrent(candidate: RootAuthenticatedTrustBundleCandidate, revokedKids: readonly string[]): Promise<void> {
    const state = await this.readPersistedState();
    if (!state || state.artifact_sha256 !== candidate.artifactSha256 ||
      state.highest_bundle_version !== candidate.claims.bundle_version || state.revoked_kids.join(',') !== revokedKids.join(',')) {
      throw new Error('Trust key resolver is stale after a bundle or revocation update');
    }
  }

  private async candidateFromState(state: PersistedState): Promise<RootAuthenticatedTrustBundleCandidate> {
    const candidate = await verifyTrustBundleSignature(state.token, {
      trustedRoot: this.trustedRoot,
      expectedCenterIssuer: this.expectedCenterIssuer,
    });
    if (candidate.artifactSha256 !== state.artifact_sha256 || candidate.claims.bundle_version !== state.highest_bundle_version) {
      throw new Error('Persisted trust bundle does not match its durable version record');
    }
    assertNoRevocationResurrection(candidate, state.revoked_kids);
    return candidate;
  }

  private async readPersistedState(): Promise<PersistedState | null> {
    await this.ensurePrivateDirectory();
    const file = join(this.directory, STATE_FILE_NAME);
    let metadata;
    try { metadata = await lstat(file); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        const marker = await this.readMarker();
        if (marker) throw new Error('Trust bundle state is missing after this store was initialized');
        return null;
      }
      throw error;
    }
    if (!metadata.isFile() || metadata.isSymbolicLink() || !isPrivateStateFileMode(metadata.mode)) {
      throw new Error('Trust bundle state file is not a private regular file');
    }
    if (metadata.size <= 0 || metadata.size > MAX_STATE_BYTES) throw new Error('Trust bundle state file has an invalid size');
    const bytes = await readFile(file);
    if (bytes.byteLength !== metadata.size) throw new Error('Trust bundle state changed while being read');
    const value = parseStrictJson(bytes);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Trust bundle state is malformed');
    const row = value as Record<string, unknown>;
    exactFields(row, STATE_FIELDS);
    if (row['state_schema'] !== 1 || typeof row['token'] !== 'string' || row['token'].length === 0 ||
      !Array.isArray(row['revoked_kids']) || row['revoked_kids'].length > 256) {
      throw new Error('Trust bundle state has an invalid schema');
    }
    const minimumVersion = assertMinimumBundleVersion(row['minimum_bundle_version']);
    const highestVersion = assertMinimumBundleVersion(row['highest_bundle_version']);
    if (compareBundleVersions(minimumVersion, highestVersion) > 0) throw new Error('Trust bundle version watermark is inconsistent');
    const artifactSha = safeDigest(row['artifact_sha256']);
    const revokedKids = row['revoked_kids'].map(safeKid);
    if (new Set(revokedKids).size !== revokedKids.length || [...revokedKids].sort().join(',') !== revokedKids.join(',')) {
      throw new Error('Trust bundle revocation tombstones are not canonical');
    }
    const state: PersistedState = {
      state_schema: 1,
      minimum_bundle_version: minimumVersion,
      highest_bundle_version: highestVersion,
      artifact_sha256: artifactSha,
      token: row['token'],
      revoked_kids: revokedKids,
    };
    await this.candidateFromState(state);
    const marker = await this.readMarker();
    if (!marker) await this.writeMarker();
    else if (compareBundleVersions(this.minimumBundleVersion, marker.minimum_bundle_version) < 0) {
      throw new Error('Trusted release baseline is older than the store initialization baseline');
    }
    if (compareBundleVersions(state.minimum_bundle_version, this.minimumBundleVersion) > 0) {
      throw new Error('Trusted release baseline is older than the persisted baseline');
    }
    return state;
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

  private async writePersistedState(state: PersistedState): Promise<void> {
    await this.ensurePrivateDirectory();
    const file = join(this.directory, STATE_FILE_NAME);
    try {
      const current = await lstat(file);
      if (!current.isFile() || current.isSymbolicLink()) throw new Error('Refusing to replace a non-regular trust bundle state file');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }

    const temporary = join(this.directory, `.trust-bundle-state-${process.pid}-${randomBytes(12).toString('hex')}.tmp`);
    const bytes = Buffer.from(JSON.stringify(state), 'utf8');
    if (bytes.byteLength > MAX_STATE_BYTES) throw new Error('Trust bundle state exceeds its storage limit');
    let handle;
    let renamed = false;
    try {
      handle = await open(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
      await this.faultAt?.('before_write');
      if (this.faultAt) {
        const half = Math.max(1, Math.floor(bytes.byteLength / 2));
        await handle.write(bytes.subarray(0, half), 0, half, 0);
        await this.faultAt('after_partial_write');
        await handle.write(bytes.subarray(half), 0, bytes.byteLength - half, half);
      } else {
        await handle.writeFile(bytes);
      }
      await this.faultAt?.('after_write');
      await handle.sync();
      await this.faultAt?.('after_file_fsync');
      await handle.close();
      handle = undefined;
      await rename(temporary, file);
      renamed = true;
      await this.faultAt?.('after_rename');
      const directoryHandle = await open(this.directory, fsConstants.O_RDONLY);
      try {
        await directoryHandle.sync();
      } finally {
        await directoryHandle.close();
      }
      await this.writeMarker();
      await this.faultAt?.('after_directory_fsync');
    } finally {
      await handle?.close().catch(() => undefined);
      if (!renamed) await unlink(temporary).catch(() => undefined);
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

  private async readMarker(): Promise<{ minimum_bundle_version: string } | null> {
    const file = join(this.directory, MARKER_FILE_NAME);
    let metadata;
    try { metadata = await lstat(file); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    }
    if (!metadata.isFile() || metadata.isSymbolicLink() || !isPrivateStateFileMode(metadata.mode) || metadata.size > 1024) {
      throw new Error('Trust bundle initialization marker is damaged');
    }
    const value = parseStrictJson(await readFile(file));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Trust bundle initialization marker is malformed');
    const row = value as Record<string, unknown>;
    exactFields(row, ['marker_schema', 'expected_center_issuer', 'trusted_root_kid', 'minimum_bundle_version']);
    const minimum = assertMinimumBundleVersion(row['minimum_bundle_version']);
    if (row['marker_schema'] !== 1 || row['expected_center_issuer'] !== this.expectedCenterIssuer ||
      row['trusted_root_kid'] !== this.trustedRoot.kid) throw new Error('Trust bundle initialization marker does not match this trusted release');
    return { minimum_bundle_version: minimum };
  }

  private async writeMarker(): Promise<void> {
    const file = join(this.directory, MARKER_FILE_NAME);
    const value = {
      marker_schema: 1,
      expected_center_issuer: this.expectedCenterIssuer,
      trusted_root_kid: this.trustedRoot.kid,
      minimum_bundle_version: this.minimumBundleVersion,
    };
    const bytes = Buffer.from(JSON.stringify(value), 'utf8');
    const temporary = join(this.directory, `.trust-bundle-marker-${process.pid}-${randomBytes(12).toString('hex')}.tmp`);
    let handle;
    let renamed = false;
    try {
      try {
        const existing = await lstat(file);
        if (!existing.isFile() || existing.isSymbolicLink()) throw new Error('Refusing to replace a damaged trust bundle marker');
        const current = await readFile(file);
        if (!current.equals(bytes)) {
          const parsed = parseStrictJson(current);
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Trust bundle marker is malformed');
          const row = parsed as Record<string, unknown>;
          exactFields(row, ['marker_schema', 'expected_center_issuer', 'trusted_root_kid', 'minimum_bundle_version']);
          if (row['marker_schema'] !== 1 || row['expected_center_issuer'] !== this.expectedCenterIssuer || row['trusted_root_kid'] !== this.trustedRoot.kid) {
            throw new Error('Trust bundle initialization marker does not match this trusted release');
          }
          if (compareBundleVersions(assertMinimumBundleVersion(row['minimum_bundle_version']), this.minimumBundleVersion) > 0) {
            throw new Error('Trusted release baseline is older than the store initialization baseline');
          }
          return;
        }
        return;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      handle = await open(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
      await handle.writeFile(bytes);
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(temporary, file);
      renamed = true;
      const dirHandle = await open(this.directory, fsConstants.O_RDONLY);
      try { await dirHandle.sync(); } finally { await dirHandle.close(); }
    } finally {
      await handle?.close().catch(() => undefined);
      if (!renamed) await unlink(temporary).catch(() => undefined);
    }
  }
}
