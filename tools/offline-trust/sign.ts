import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, readFile, rename, unlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { importPKCS8 } from 'jose';
import type { CryptoKey } from 'jose';
import { parseStrictJson } from '../../src/strict-json.js';
import {
  buildTrustBundleClaims,
  previewTrustBundleSigning,
  signTrustBundle,
} from '../../src/trust/trust-bundle.js';
import type { Ed25519PublicJwk, TrustBundleSigningInput } from '../../src/trust/trust-bundle.js';

const MAX_ROOT_FILE_BYTES = 8 * 1024;
const MAX_INPUT_BYTES = 24 * 1024;
const INPUT_FIELDS = [
  'bundle_version', 'iat', 'nbf', 'exp', 'propagation_budget_seconds', 'keys',
] as const;

export interface LoadedOfflineRootKey {
  privateKey: CryptoKey;
  publicJwk: Ed25519PublicJwk;
}

export type ArtifactWriteStage = 'after_write' | 'after_file_fsync' | 'after_rename' | 'after_directory_fsync';

function assertExactFields(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  if (Object.keys(value).sort().join('\n') !== [...expected].sort().join('\n')) throw new Error(`Unexpected ${label} fields`);
}

function assertPrivateFilePermissions(metadata: Awaited<ReturnType<typeof lstat>>): void {
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) throw new Error('Offline root key must be a normal private file, not a symlink or hard link');
  if (process.platform === 'win32') throw new Error('Offline root signing requires POSIX file ownership and permissions');
  const effectiveUid = process.geteuid?.();
  if (effectiveUid === undefined || metadata.uid !== effectiveUid) throw new Error('Offline root key must be owned by the invoking user');
  const mode = Number(metadata.mode) & 0o777;
  if ((mode !== 0o400 && mode !== 0o600) || (Number(metadata.mode) & 0o7000) !== 0) {
    throw new Error('Offline root key permissions must be private, non-executable 0400 or 0600');
  }
}

export async function loadOfflineRootKey(explicitPath: string): Promise<LoadedOfflineRootKey> {
  const keyPath = resolve(explicitPath);
  const before = await lstat(keyPath);
  assertPrivateFilePermissions(before);
  if (before.size <= 0 || before.size > MAX_ROOT_FILE_BYTES) throw new Error('Offline root key file size is invalid');
  const handle = await open(keyPath, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  let privateBytes: Buffer | undefined;
  try {
    const opened = await handle.stat();
    assertPrivateFilePermissions(opened);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) throw new Error('Offline root key changed while opening');
    privateBytes = await handle.readFile();
    if (privateBytes.byteLength !== opened.size || privateBytes.byteLength > MAX_ROOT_FILE_BYTES) throw new Error('Offline root key changed while reading');
    const privatePem = privateBytes.toString('utf8');
    const privateKey = await importPKCS8(privatePem, 'Ed25519');
    const exported = createPublicKey(privatePem).export({ format: 'jwk' });
    if (exported.kty !== 'OKP' || exported.crv !== 'Ed25519' || typeof exported.x !== 'string' ||
      Object.keys(exported).sort().join(',') !== 'crv,kty,x') throw new Error('Offline root key must be an Ed25519 PKCS#8 private key');
    return {
      privateKey,
      publicJwk: { kty: 'OKP', crv: 'Ed25519', x: exported.x },
    };
  } finally {
    privateBytes?.fill(0);
    await handle.close();
  }
}

export async function readUnsignedBundleInput(path: string): Promise<TrustBundleSigningInput> {
  const inputPath = resolve(path);
  const metadata = await lstat(inputPath);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size <= 0 || metadata.size > MAX_INPUT_BYTES) {
    throw new Error('Unsigned trust bundle input must be a bounded regular file');
  }
  const bytes = await readFile(inputPath);
  if (bytes.byteLength !== metadata.size) throw new Error('Unsigned trust bundle input changed while reading');
  const value = parseStrictJson(bytes);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Unsigned trust bundle input must be a JSON object');
  const row = value as Record<string, unknown>;
  assertExactFields(row, INPUT_FIELDS, 'unsigned trust bundle input');
  return {
    bundle_version: row['bundle_version'] as string,
    iat: row['iat'] as number,
    nbf: row['nbf'] as number,
    exp: row['exp'] as number,
    propagation_budget_seconds: row['propagation_budget_seconds'] as number,
    keys: row['keys'],
  };
}

export async function atomicWritePublicArtifact(
  outputPath: string,
  bytes: Uint8Array,
  faultAt?: (stage: ArtifactWriteStage) => void | Promise<void>,
): Promise<void> {
  const destination = resolve(outputPath);
  const directory = dirname(destination);
  const directoryMetadata = await lstat(directory);
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) throw new Error('Trust bundle output parent must be a normal directory');
  try {
    const current = await lstat(destination);
    if (!current.isFile() || current.isSymbolicLink()) throw new Error('Trust bundle output must replace a regular file');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  const temporary = `${destination}.tmp-${process.pid}-${randomBytes(12).toString('hex')}`;
  const handle = await open(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), 0o644);
  let replaced = false;
  try {
    await handle.writeFile(bytes);
    await faultAt?.('after_write');
    await handle.sync();
    await faultAt?.('after_file_fsync');
    await handle.close();
    await rename(temporary, destination);
    replaced = true;
    await faultAt?.('after_rename');
    const dirHandle = await open(directory, fsConstants.O_RDONLY);
    try { await dirHandle.sync(); } finally { await dirHandle.close(); }
    await faultAt?.('after_directory_fsync');
  } finally {
    await handle.close().catch(() => undefined);
    if (!replaced) await unlink(temporary).catch(() => undefined);
  }
}

function parseArguments(args: string[]): { command: 'preview' | 'sign'; flags: Map<string, string> } {
  const command = args[0];
  if (command !== 'preview' && command !== 'sign') throw new Error('Usage: trust-bundle:offline <preview|sign> --center-issuer URL --root-key-file PATH --bundle-input PATH [--confirm-digest HEX --output PATH]');
  const flags = new Map<string, string>();
  for (let index = 1; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!name?.startsWith('--') || !value || flags.has(name) || !['--center-issuer', '--root-key-file', '--bundle-input', '--confirm-digest', '--output'].includes(name)) {
      throw new Error('Invalid or duplicate offline trust-bundle argument');
    }
    flags.set(name, value);
  }
  for (const required of ['--center-issuer', '--root-key-file', '--bundle-input']) {
    if (!flags.has(required)) throw new Error(`Missing ${required}`);
  }
  return { command, flags };
}

function previewJson(preview: Awaited<ReturnType<typeof previewTrustBundleSigning>>): string {
  return JSON.stringify({
    message: 'Review this public trust bundle. Signing requires a second invocation with --confirm-digest equal to signingInputSha256.',
    ...preview,
  }, null, 2);
}

export async function runOfflineTrustBundleCli(args: string[]): Promise<void> {
  const { command, flags } = parseArguments(args);
  const issuer = flags.get('--center-issuer')!;
  const keyFile = resolve(flags.get('--root-key-file')!);
  const inputFile = resolve(flags.get('--bundle-input')!);
  const root = await loadOfflineRootKey(keyFile);
  const input = await readUnsignedBundleInput(inputFile);
  const claims = await buildTrustBundleClaims(issuer, input, root.publicJwk);
  const preview = await previewTrustBundleSigning(claims, root.publicJwk);
  if (command === 'preview') {
    if (flags.has('--confirm-digest') || flags.has('--output')) throw new Error('Preview does not accept signing confirmation or output flags');
    process.stdout.write(`${previewJson(preview)}\n`);
    return;
  }
  const confirmation = flags.get('--confirm-digest');
  const output = flags.get('--output');
  if (!confirmation || !/^[a-f0-9]{64}$/.test(confirmation) || confirmation !== preview.signingInputSha256 || !output) {
    throw new Error('Signing requires the exact reviewed --confirm-digest and an explicit --output path');
  }
  const outputPath = resolve(output);
  if (outputPath === keyFile || outputPath === inputFile) throw new Error('Output path must not replace the root key or unsigned input');
  const { token, preview: signedPreview } = await signTrustBundle(claims, root.privateKey, root.publicJwk);
  if (signedPreview.signingInputSha256 !== confirmation) throw new Error('Signing content changed after review');
  await atomicWritePublicArtifact(outputPath, Buffer.from(token, 'utf8'));
  process.stdout.write(`${JSON.stringify({
    message: 'Signed trust bundle atomically written.',
    output: outputPath,
    bundleVersion: signedPreview.bundleVersion,
    artifactSha256: createArtifactSha256(token),
    signingInputSha256: signedPreview.signingInputSha256,
  }, null, 2)}\n`);
}

function createArtifactSha256(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  runOfflineTrustBundleCli(process.argv.slice(2)).catch((error: unknown) => {
    const message = error instanceof Error ? error.message : 'Offline trust bundle operation failed';
    process.stderr.write(`offline trust bundle: ${message}\n`);
    process.exitCode = 1;
  });
}
