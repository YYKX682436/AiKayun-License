import { request as httpsRequest } from 'node:https';
import * as signatures from '@misskey-dev/node-http-message-signatures';
import { ByteSequence, serializeDictionary } from 'structured-headers';
import type { RuntimeConfig } from '../../src/config.js';
import type { TestIdentity } from './runtime.js';
import { newClientNonce } from './runtime.js';

export interface RunningTestServer {
  port: number;
  stop(): Promise<void>;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  json: Record<string, unknown>;
  body: Buffer;
}

export async function startAppServer(app: { listen(options: { host: string; port: number }): Promise<string>; close(): Promise<void> }): Promise<RunningTestServer> {
  const address = await app.listen({ host: '127.0.0.1', port: 0 });
  return { port: Number(new URL(address).port), stop: () => app.close() };
}

export async function signPost(input: {
  port: number;
  origin: string;
  path: string;
  body: unknown;
  identity: TestIdentity;
  nonce: string;
  created?: number;
  signPath?: string;
  sendPath?: string;
  rawBodyOverride?: Buffer;
  headerOverrides?: Record<string, string>;
}): Promise<HttpResponse> {
  const rawBody = Buffer.from(JSON.stringify(input.body));
  const host = new URL(input.origin).host;
  const signedRequest = {
    method: 'POST',
    url: input.signPath ?? input.path,
    headers: { host, 'content-type': 'application/json' } as Record<string, string>,
  };
  const digestEntries = await signatures.genSingleRFC9530DigestHeader(rawBody, 'SHA-256');
  const [digestName, [bytes, params]] = digestEntries[0]!;
  const digestHeader = serializeDictionary(new Map([[digestName, [new ByteSequence(bytes.toBase64()), params]]]));
  signedRequest.headers['content-digest'] = digestHeader;
  const signed = await signatures.signAsRFC9421ToRequestOrResponse(signedRequest, {
    sig1: {
      key: { privateKeyJwk: input.identity.privateJwk, keyId: input.identity.jkt },
      identifiers: ['@method', '@target-uri', 'content-type', 'content-digest'],
      created: input.created ?? Math.floor(Date.now() / 1000),
      expiresAfter: 60,
      nonce: input.nonce,
      tag: 'aikayun-license-v1',
    },
  }, { scheme: 'https' });
  const wireBody = input.rawBodyOverride ?? rawBody;
  const wireHeaders: Record<string, string> = {
    host,
    'content-type': 'application/json',
    'content-digest': digestHeader,
    'signature-input': signed.inputHeader,
    signature: signed.signatureHeader,
    'content-length': String(wireBody.byteLength),
    connection: 'close',
    ...input.headerOverrides,
  };
  return new Promise((resolve, reject) => {
    const request = httpsRequest({
      host: '127.0.0.1', port: input.port, path: input.sendPath ?? input.path, method: 'POST', headers: wireHeaders,
      rejectUnauthorized: false,
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      response.on('end', () => {
        const body = Buffer.concat(chunks);
        let json: Record<string, unknown> = {};
        try { json = JSON.parse(body.toString('utf8')) as Record<string, unknown>; } catch { /* caller can inspect raw body */ }
        resolve({ status: response.statusCode ?? 0, headers: response.headers, json, body });
      });
    });
    request.on('error', reject);
    request.end(wireBody);
  });
}

export async function requestChallenge(input: {
  port: number;
  config: RuntimeConfig;
  identity: TestIdentity;
  operation: 'activation' | 'renewal' | 'recovery' | 'query' | 'continue' | 'transfer_prepare' | 'transfer_commit' | 'disaster_transfer_prepare' | 'disaster_transfer_commit';
  operationId: string;
  intentDigest: string;
  instanceId: string;
  clientNonce?: string;
  created?: number;
}): Promise<{ token: string; clientNonce: string }> {
  const clientNonce = input.clientNonce ?? newClientNonce();
  const response = await signPost({
    port: input.port,
    origin: input.config.publicOrigin,
    path: '/v1/challenges',
    body: {
      operation: input.operation,
      operation_id: input.operationId,
      intent_digest: input.intentDigest,
      instance_id: input.instanceId,
      public_jwk: input.identity.publicJwk,
      client_nonce: clientNonce,
    },
    identity: input.identity,
    nonce: clientNonce,
    ...(input.created === undefined ? {} : { created: input.created }),
  });
  if (response.status !== 201 || typeof response.json['challenge'] !== 'string') {
    throw new Error(`Challenge request failed: HTTP ${response.status} ${JSON.stringify(response.json)}`);
  }
  return { token: response.json['challenge'], clientNonce };
}

export function buildChallengeBoundBody(input: {
  challenge: string;
  operationId: string;
  intentDigest: string;
  attemptNo: number;
  instanceId: string;
  identity: TestIdentity;
  licenseId: string;
  databaseId: string;
}): Record<string, unknown> {
  return {
    challenge: input.challenge,
    operation_id: input.operationId,
    intent_digest: input.intentDigest,
    attempt_no: input.attemptNo,
    instance_id: input.instanceId,
    identity_jkt: input.identity.jkt,
    public_jwk: input.identity.publicJwk,
    license_id: input.licenseId,
    database_id: input.databaseId,
  };
}
