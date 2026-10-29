import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  atomicWritePublicArtifact,
  loadOfflineRootKey,
  runOfflineTrustBundleCli,
} from '../../tools/offline-trust/sign.js';
import { verifyTrustBundleSignature } from '../../src/trust/trust-bundle.js';
import type { TrustedOfflineRootPin } from '../../src/trust/trust-bundle.js';

const CENTER_ISSUER = 'https://license.example.test';
const temporaryDirectories: string[] = [];

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'aikayun-offline-root-'));
  temporaryDirectories.push(directory);
  const rootPath = join(directory, 'offline-root.pem');
  const inputPath = join(directory, 'unsigned-bundle.json');
  const outputPath = join(directory, 'trust-bundle.jws');
  const pair = generateKeyPairSync('ed25519');
  const privatePem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  await writeFile(rootPath, privatePem, { mode: 0o600, flag: 'wx' });
  const exported = createPublicKey(privatePem).export({ format: 'jwk' });
  const keyPair = generateKeyPairSync('ed25519');
  const publicCenter = keyPair.publicKey.export({ format: 'jwk' });
  const { calculateJwkThumbprint } = await import('jose');
  const publicJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: publicCenter.x! };
  const centerKid = await calculateJwkThumbprint(publicJwk, 'sha256');
  const rootJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: exported.x! };
  const rootKid = await calculateJwkThumbprint(rootJwk, 'sha256');
  const now = Math.floor(Date.now() / 1000);
  const input = {
    bundle_version: '1',
    iat: now - 30,
    nbf: now - 20,
    exp: now + 30 * 24 * 60 * 60,
    propagation_budget_seconds: 3_600,
    keys: [{
      kid: centerKid,
      alg: 'Ed25519',
      ...publicJwk,
      not_before: now - 100,
      retire_after: null,
      verify_until: null,
      revoked_at: null,
    }],
  };
  await writeFile(inputPath, JSON.stringify(input), { mode: 0o600, flag: 'wx' });
  return {
    directory, rootPath, inputPath, outputPath, privatePem,
    trustedRoot: { publicJwk: rootJwk, kid: rootKid } as TrustedOfflineRootPin,
    centerKid,
  };
}

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('offline trust-bundle signer boundary', () => {
  it('requires a non-symlink, invoking-user-owned private POSIX root file', async () => {
    const item = await fixture();
    await expect(loadOfflineRootKey(item.rootPath)).resolves.toMatchObject({ publicJwk: { kty: 'OKP', crv: 'Ed25519' } });
    await chmod(item.rootPath, 0o644);
    await expect(loadOfflineRootKey(item.rootPath)).rejects.toThrow(/permissions/i);
    await chmod(item.rootPath, 0o600);
    const linkPath = join(item.directory, 'root-link.pem');
    await symlink(item.rootPath, linkPath);
    await expect(loadOfflineRootKey(linkPath)).rejects.toThrow(/symlink/i);
  });

  it('uses a two-invocation digest confirmation and atomically publishes only the reviewed bytes', async () => {
    const item = await fixture();
    const writes: string[] = [];
    const outputSpy = vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array) => {
      writes.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
      return true;
    }) as typeof process.stdout.write);
    const common = ['--center-issuer', CENTER_ISSUER, '--root-key-file', item.rootPath, '--bundle-input', item.inputPath];
    await runOfflineTrustBundleCli(['preview', ...common]);
    const previewOutput = writes.join('');
    const preview = JSON.parse(previewOutput) as { signingInputSha256: string; keys: Array<{ kid: string }> };
    expect(preview.signingInputSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(preview.keys.map(({ kid }) => kid)).toContain(item.centerKid);
    expect(previewOutput).not.toContain('PRIVATE KEY');
    expect(previewOutput).not.toContain(item.privatePem);

    await writeFile(item.outputPath, 'previous-trusted-publication', { mode: 0o644, flag: 'wx' });
    await expect(runOfflineTrustBundleCli(['sign', ...common, '--confirm-digest', '0'.repeat(64), '--output', item.outputPath]))
      .rejects.toThrow(/confirm-digest/i);
    expect(await readFile(item.outputPath, 'utf8')).toBe('previous-trusted-publication');

    const currentInput = JSON.parse(await readFile(item.inputPath, 'utf8')) as Record<string, unknown>;
    await writeFile(item.inputPath, JSON.stringify({ ...currentInput, bundle_version: '2' }));
    await expect(runOfflineTrustBundleCli(['sign', ...common, '--confirm-digest', preview.signingInputSha256, '--output', item.outputPath]))
      .rejects.toThrow(/confirm-digest/i);
    expect(await readFile(item.outputPath, 'utf8')).toBe('previous-trusted-publication');

    await writeFile(item.inputPath, JSON.stringify(currentInput));
    writes.length = 0;
    await runOfflineTrustBundleCli(['sign', ...common, '--confirm-digest', preview.signingInputSha256, '--output', item.outputPath]);
    const token = await readFile(item.outputPath, 'utf8');
    const candidate = await verifyTrustBundleSignature(token, { trustedRoot: item.trustedRoot, expectedCenterIssuer: CENTER_ISSUER });
    expect(candidate.claims.bundle_version).toBe('1');
    expect(writes.join('')).not.toContain('PRIVATE KEY');
  });

  it('keeps an existing publication intact when an atomic replacement is interrupted before rename', async () => {
    const item = await fixture();
    await writeFile(item.outputPath, 'last-good-public-artifact', { mode: 0o644, flag: 'wx' });
    await expect(atomicWritePublicArtifact(item.outputPath, Buffer.from('replacement'), (stage) => {
      if (stage === 'after_file_fsync') throw new Error('simulated output interruption');
    })).rejects.toThrow(/interruption/i);
    expect(await readFile(item.outputPath, 'utf8')).toBe('last-good-public-artifact');
    await atomicWritePublicArtifact(item.outputPath, Buffer.from('fully-signed-public-artifact'));
    expect(await readFile(item.outputPath, 'utf8')).toBe('fully-signed-public-artifact');
  });
});
