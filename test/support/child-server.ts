import { spawn, type ChildProcess } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createServer, connect } from 'node:net';
import { registerTestHttpsEndpoint } from './http.js';

export interface ChildLicenseServer {
  process: ChildProcess;
  port: number;
  stop(signal?: NodeJS.Signals): Promise<void>;
}

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const port = (server.address() as { port: number }).port;
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

function tcpConnect(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const client = connect(port, '127.0.0.1');
    client.setTimeout(250);
    client.once('connect', () => { client.destroy(); resolve(true); });
    client.once('timeout', () => { client.destroy(); resolve(false); });
    client.once('error', () => resolve(false));
  });
}

export async function startChildLicenseServer(input: {
  databaseUrl: string;
  issuer: string;
  publicOrigin: string;
  keyringFile: string;
  offlineRootJwkFile: string;
  minimumTrustBundleVersion: string;
  tlsKeyFile: string;
  tlsCertFile: string;
}): Promise<ChildLicenseServer> {
  const port = await reservePort();
  const source = new URL('../../src/main.ts', import.meta.url);
  const child = spawn(process.execPath, ['--import', 'tsx', source.pathname], {
    cwd: process.cwd(),
    stdio: ['ignore', 'ignore', 'pipe'],
    env: {
      ...process.env,
      NODE_ENV: 'development',
      LICENSE_DATABASE_URL: input.databaseUrl,
      LICENSE_ISSUER: input.issuer,
      LICENSE_PUBLIC_ORIGIN: input.publicOrigin,
      LICENSE_SIGNING_KEYRING_FILE: input.keyringFile,
      LICENSE_OFFLINE_ROOT_JWK_FILE: input.offlineRootJwkFile,
      LICENSE_TRUST_BUNDLE_MIN_VERSION: input.minimumTrustBundleVersion,
      LICENSE_TLS_KEY_FILE: input.tlsKeyFile,
      LICENSE_TLS_CERT_FILE: input.tlsCertFile,
      LICENSE_HTTP_PORT: String(port),
      LICENSE_LISTEN_HOST: '127.0.0.1',
    },
  });
  let stderr = '';
  child.stderr?.on('data', (chunk: Buffer) => {
    stderr = `${stderr}${chunk.toString('utf8')}`.slice(-2048);
  });
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`License child exited during startup (${child.exitCode}): ${stderr.trim() || 'no diagnostic output'}`);
    }
    if (await tcpConnect(port)) {
      registerTestHttpsEndpoint(port, await readFile(input.tlsCertFile), new URL(input.publicOrigin).hostname);
      return {
        process: child,
        port,
        stop: async (signal = 'SIGTERM') => {
          if (child.exitCode !== null || child.signalCode !== null) return;
          await new Promise<void>((resolve) => {
            child.once('exit', () => resolve());
            child.kill(signal);
          });
        },
      };
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  child.kill('SIGKILL');
  throw new Error('Timed out waiting for local license child process to listen');
}
