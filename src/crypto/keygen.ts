import { generateKeyPairSync } from 'node:crypto';
import { open, unlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { mkdir } from 'node:fs/promises';

const [privateArg, publicArg] = process.argv.slice(2);
if (!privateArg || !publicArg) {
  process.stderr.write('Usage: npm run keygen -- <private-pkcs8.pem> <public-spki.pem>\n');
  process.exitCode = 2;
} else {
  const privatePath = resolve(privateArg);
  const publicPath = resolve(publicArg);
  if (privatePath === publicPath) throw new Error('Private and public key paths must differ');
  await mkdir(dirname(privatePath), { recursive: true, mode: 0o700 });
  await mkdir(dirname(publicPath), { recursive: true, mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateHandle = await open(privatePath, 'wx', 0o600);
  try {
    await privateHandle.writeFile(privatePem, 'utf8');
    await privateHandle.sync();
  } catch (error) {
    await privateHandle.close();
    await unlink(privatePath).catch(() => undefined);
    throw error;
  }
  await privateHandle.close();
  try {
    const publicHandle = await open(publicPath, 'wx', 0o644);
    await publicHandle.writeFile(publicPem, 'utf8');
    await publicHandle.sync();
    await publicHandle.close();
  } catch (error) {
    await unlink(privatePath).catch(() => undefined);
    throw error;
  }
  process.stdout.write(`Wrote private key (mode 0600) and public key to ${privatePath} and ${publicPath}\n`);
}
