import {
  parseRFC9421RequestOrResponse,
  verifyRFC9421Signature,
  verifyRFC9530DigestHeader,
} from '@misskey-dev/node-http-message-signatures';
import { ByteSequence, parseDictionary } from 'structured-headers';
import type { BareItem, Item, Parameters } from 'structured-headers';
import type { PublicIdentityJwk } from './identity.js';
import { sha256Base64url, validateIdentityJwk } from './identity.js';
import { LicenseApiError } from '../errors.js';

export interface SignedHttpRequest {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  rawHeaders: string[];
  body: Uint8Array;
}

export interface VerifiedHttpSignature {
  identityJwk: PublicIdentityJwk;
  identityJkt: string;
  nonce: string;
  created: number;
  expires: number;
  requestDigest: string;
}

export function assertVerifiedHttpSignatureFresh(signature: Pick<VerifiedHttpSignature, 'created' | 'expires'>, now: Date): void {
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (signature.created < nowSeconds - 60 || signature.created > nowSeconds + 60 || signature.expires < nowSeconds) {
    throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
  }
}

function getSingleHeader(request: SignedHttpRequest, name: string): string {
  let count = 0;
  let found = '';
  for (let i = 0; i < request.rawHeaders.length; i += 2) {
    if (request.rawHeaders[i]?.toLowerCase() === name) {
      count += 1;
      found = request.rawHeaders[i + 1] ?? '';
    }
  }
  if (count !== 1 || found.length === 0) throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
  return found;
}

function exactHeaderParams(raw: string, name: string, expected: readonly string[]): [BareItem | Item[], Parameters] {
  let parsed: ReturnType<typeof parseDictionary>;
  try { parsed = parseDictionary(raw); } catch { throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID'); }
  if (parsed.size !== 1 || !parsed.has(name)) throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
  const item = parsed.get(name)!;
  const params = item[1];
  const paramNames = [...params.keys()].sort();
  if (paramNames.join(',') !== [...expected].sort().join(',')) throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
  return item;
}

export async function verifyHttpMessage(
  request: SignedHttpRequest,
  identityInput: unknown,
  expectedOrigin: string,
  expectedNonce: string,
  now: Date,
): Promise<VerifiedHttpSignature> {
  try {
    const { jwk, jkt, key } = await validateIdentityJwk(identityInput);
    const host = getSingleHeader(request, 'host');
    const contentType = getSingleHeader(request, 'content-type');
    const contentDigest = getSingleHeader(request, 'content-digest');
    const signatureInput = getSingleHeader(request, 'signature-input');
    const signature = getSingleHeader(request, 'signature');
    const expectedHost = new URL(expectedOrigin).host;
    if (host !== expectedHost || contentType.toLowerCase() !== 'application/json') throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
    if (request.method !== 'POST' || !request.url.startsWith('/') || request.url.includes('?') || request.url.includes('#')) {
      throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
    }
    if (request.body.byteLength === 0 || request.body.byteLength > 32 * 1024) throw new LicenseApiError(400, 'INVALID_REQUEST_BODY');

    const [digestValue, digestParams] = exactHeaderParams(contentDigest, 'sha-256', []);
    if (digestParams.size !== 0 || Array.isArray(digestValue) || !(digestValue instanceof ByteSequence)) {
      throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
    }

    const [components, params] = exactHeaderParams(signatureInput, 'sig1', ['created', 'expires', 'nonce', 'keyid', 'alg', 'tag']);
    if (!Array.isArray(components)) throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
    const componentNames = components.map((entry) => Array.isArray(entry) ? entry[0] : entry);
    const requiredComponents = ['@method', '@target-uri', 'content-type', 'content-digest'];
    if (componentNames.length !== requiredComponents.length || componentNames.some((name, index) => name !== requiredComponents[index])) {
      throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
    }
    if (components.some((entry) => Array.isArray(entry) && entry[1].size !== 0)) throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
    const created = params.get('created');
    const expires = params.get('expires');
    const nonce = params.get('nonce');
    const keyid = params.get('keyid');
    const alg = params.get('alg');
    const tag = params.get('tag');
    if (typeof created !== 'number' || !Number.isSafeInteger(created) || typeof expires !== 'number' || !Number.isSafeInteger(expires) || typeof nonce !== 'string' ||
      typeof keyid !== 'string' || typeof alg !== 'string' || typeof tag !== 'string' ||
      keyid !== jkt || nonce !== expectedNonce || alg !== 'ed25519' || tag !== 'aikayun-license-v1' ||
      Number(expires) <= Number(created) || Number(expires) - Number(created) > 60) {
      throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
    }
    const verifiedTimestamp = { created, expires } as Pick<VerifiedHttpSignature, 'created' | 'expires'>;
    assertVerifiedHttpSignatureFresh(verifiedTimestamp, now);

    const headers: Record<string, string | string[] | undefined> = {};
    for (const [keyName, value] of Object.entries(request.headers)) headers[keyName.toLowerCase()] = value;
    headers['host'] = expectedHost;
    headers['content-type'] = 'application/json';
    headers['content-digest'] = contentDigest;
    headers['signature-input'] = signatureInput;
    headers['signature'] = signature;
    const libraryRequest = { method: request.method, url: request.url, headers, rawHeaders: request.rawHeaders };
    const signatureEntries = exactHeaderParams(signature, 'sig1', []);
    if (signatureEntries[1].size !== 0) throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
    const parsed = parseRFC9421RequestOrResponse(libraryRequest, {
      clockSkew: { now, delay: 60_000, forward: 60_000 },
      requiredComponents: { rfc9421: requiredComponents },
    });
    if (parsed.version !== 'rfc9421' || parsed.value.length !== 1 || parsed.value[0]?.[0] !== 'sig1') {
      throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
    }
    const parsedSignature = parsed.value[0][1];
    if (parsedSignature.keyid !== jkt || parsedSignature.nonce !== expectedNonce || parsedSignature.algorithm !== 'ed25519' ||
      parsedSignature.created !== created || parsedSignature.expires !== expires) {
      throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
    }
    const digestValid = await verifyRFC9530DigestHeader(libraryRequest, request.body, { algorithms: ['sha-256'], verifyAll: true });
    const signatureValid = await verifyRFC9421Signature(parsed.value, key, { verifyAll: true, algorithms: ['ed25519'] });
    if (!digestValid || !signatureValid) throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
    return { identityJwk: jwk, identityJkt: jkt, nonce, created: Number(created), expires: Number(expires), requestDigest: sha256Base64url(request.body) };
  } catch (error) {
    if (error instanceof LicenseApiError) throw error;
    throw new LicenseApiError(401, 'HTTP_SIGNATURE_INVALID');
  }
}
