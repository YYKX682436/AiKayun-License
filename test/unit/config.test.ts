import { generateKeyPairSync } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config.js';

const execFile = promisify(execFileCallback);

const temporaryDirectories: string[] = [];

async function createPrivateKeyFile(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'aikayun-license-config-'));
  temporaryDirectories.push(directory);
  const file = join(directory, 'signing-key.pem');
  const pair = generateKeyPairSync('ed25519');
  const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  await writeFile(file, privatePem, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  return file;
}

async function createTlsFiles(): Promise<{ keyFile: string; certFile: string }> {
  const directory = await mkdtemp(join(tmpdir(), 'aikayun-license-tls-config-'));
  temporaryDirectories.push(directory);
  const keyFile = join(directory, 'tls-key.pem');
  const certFile = join(directory, 'tls-cert.pem');
  await execFile('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=license.example.test', '-addext', 'subjectAltName=DNS:license.example.test',
    '-keyout', keyFile, '-out', certFile,
  ]);
  await chmod(keyFile, 0o600);
  return { keyFile, certFile };
}

const baseEnvironment = {
  LICENSE_DATABASE_URL: 'postgres://license:local-only@127.0.0.1:55432/license_center',
  LICENSE_ISSUER: 'https://license.example.test',
  LICENSE_PUBLIC_ORIGIN: 'https://license.example.test',
  LICENSE_HTTP_PORT: '4318',
};

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('secure startup configuration', () => {
  it('refuses to start without an explicitly supplied signing key and never creates one', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'aikayun-license-missing-key-'));
    temporaryDirectories.push(directory);
    const keyFile = join(directory, 'missing.pem');
    await expect(loadConfig({
      ...baseEnvironment, NODE_ENV: 'production', LICENSE_SIGNING_KEY_FILE: keyFile,
    })).rejects.toThrow();
    await expect(import('node:fs/promises').then(({ stat }) => stat(keyFile))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('requires loopback outside the explicitly isolated local Compose container', async () => {
    const keyFile = await createPrivateKeyFile();
    const tls = await createTlsFiles();
    const environment = {
      ...baseEnvironment, NODE_ENV: 'development', LICENSE_SIGNING_KEY_FILE: keyFile,
      LICENSE_TLS_KEY_FILE: tls.keyFile, LICENSE_TLS_CERT_FILE: tls.certFile, LICENSE_LISTEN_HOST: '0.0.0.0',
    };
    await expect(loadConfig(environment)).rejects.toThrow(/loopback/);
    await expect(loadConfig({ ...environment, LICENSE_ISOLATED_CONTAINER: 'compose' })).resolves.toMatchObject({
      listenHost: '0.0.0.0', nodeEnv: 'development',
    });
    await expect(loadConfig({ ...environment, NODE_ENV: 'production', LICENSE_ISOLATED_CONTAINER: 'compose' }))
      .rejects.toThrow(/loopback/);
  });
});
