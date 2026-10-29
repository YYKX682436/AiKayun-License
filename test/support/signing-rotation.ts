import { randomUUID } from 'node:crypto';
import { chmod, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { Kysely } from 'kysely';
import type { Database } from '../../src/db/types.js';
import { loadTrustedSigningContext } from '../../src/crypto/signing-authority.js';
import {
  acceptSignerTrustBundleRequestDigest, rotateSignerRequestDigest,
} from '../../src/admin/signing-service.js';
import { trustBundleArtifactDigest } from '../../src/trust/trust-bundle.js';
import type { TestOnlineKey, TestSigningRuntime } from './runtime.js';

export async function publishAndRotateTo(
  db: Kysely<Database>,
  runtime: TestSigningRuntime,
  target: TestOnlineKey,
  bundleVersion: string,
): Promise<{ bundleJws: string; context: Awaited<ReturnType<typeof loadTrustedSigningContext>>['context'] }> {
  const bundleJws = await runtime.createBundle(bundleVersion, [runtime.onlineKey.record, target.record]);
  const artifactSha256 = trustBundleArtifactDigest(bundleJws);
  const service = runtime.createAdminService(db);
  const accept = {
    operationId: randomUUID(),
    expectedSignerRevision: '1',
    bundleJws,
    reason: `publish signing bundle ${bundleVersion}`,
  };
  await service.acceptTrustBundle({
    ...accept,
    rolloutGate: 'isolated-development-confirmed',
    confirmedRequestDigest: acceptSignerTrustBundleRequestDigest(accept),
  });
  (runtime.config.signingKeyring as Map<string, TestOnlineKey>).set(target.kid, target);
  const privateKeyFile = join(dirname(runtime.keyringFile), `signing-${target.kid}.pem`);
  await writeFile(privateKeyFile, target.privatePem, { mode: 0o600, flag: 'wx' });
  await chmod(privateKeyFile, 0o600);
  runtime.keyFiles.set(target.kid, privateKeyFile);
  const manifest = {
    schema: 1,
    keys: [...runtime.config.signingKeyring.keys()].map((kid) => {
      const path = runtime.keyFiles.get(kid);
      if (!path) throw new Error(`Missing test key path for ${kid}`);
      return { kid, path };
    }),
  };
  await writeFile(runtime.keyringFile, JSON.stringify(manifest), { mode: 0o600 });
  await chmod(runtime.keyringFile, 0o600);
  const rotate = {
    operationId: randomUUID(),
    expectedSignerRevision: '1',
    targetKid: target.kid,
    bundleVersion,
    artifactSha256,
    reason: `rotate online signer to ${target.kid}`,
  };
  await service.rotate({
    ...rotate,
    rolloutGate: 'isolated-development-confirmed',
    confirmedRequestDigest: rotateSignerRequestDigest(rotate),
  });
  const trusted = await loadTrustedSigningContext(db, runtime.config);
  return { bundleJws, context: trusted.context };
}
