import { describe, expect, it } from 'vitest';
import {
  calculateJwkThumbprint,
  importJWK,
  jwtVerify,
  SignJWT,
} from 'jose';
import type { CryptoKey } from 'jose';
import * as signatures from '@misskey-dev/node-http-message-signatures';
import { ByteSequence, serializeDictionary } from 'structured-headers';
import { verifyHttpMessage } from '../../src/crypto/http-signature.js';
import { parseStrictJson } from '../../src/strict-json.js';

const vectorPrivateJwk = {
  kty: 'OKP', crv: 'Ed25519',
  d: 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU',
  x: 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs',
};
const vectorPublicJwk = { kty: 'OKP', crv: 'Ed25519', x: vectorPrivateJwk.x };

function digestHeader(entries: Awaited<ReturnType<typeof signatures.genSingleRFC9530DigestHeader>>): string {
  const [name, [bytes, params]] = entries[0]!;
  return serializeDictionary(new Map([[name, [new ByteSequence(bytes.toBase64()), params]]]));
}

function runtimeConfig(publicKey: CryptoKey, signingKeyId: string) {
  return {
    nodeEnv: 'test' as const,
    databaseUrl: 'postgres://unit.invalid/license',
    issuer: 'https://license.example.test',
    publicOrigin: 'https://license.example.test',
    tlsKeyFile: 'unused-test-key.pem',
    tlsCertFile: 'unused-test-cert.pem',
    tlsPrivateKey: Buffer.from('test-only'),
    tlsCertificate: Buffer.from('test-only'),
    port: 4318,
    listenHost: '127.0.0.1',
    signingPrivateKey: publicKey,
    signingPublicKey: publicKey,
    signingPublicJwk: vectorPublicJwk,
    signingKeyId,
  };
}

describe('RFC interoperability vectors', () => {
  it('uses RFC 9864 Ed25519 as the JWS algorithm and rejects EdDSA fallback', async () => {
    const jkt = await calculateJwkThumbprint(vectorPublicJwk, 'sha256');
    const privateKey = await importJWK(vectorPrivateJwk, 'Ed25519');
    const publicKey = await importJWK(vectorPublicJwk, 'Ed25519');
    const now = 1_798_000_000;
    const token = await new SignJWT({ v: 1 })
      .setProtectedHeader({ alg: 'Ed25519', kid: jkt, typ: 'aikayun-license+jwt' })
      .setIssuer('https://license.example.test').setAudience('aikayun-commerce')
      .setIssuedAt(now).setNotBefore(now).setExpirationTime(now + 3600).sign(privateKey);
    const verified = await jwtVerify(token, publicKey, {
      algorithms: ['Ed25519'], issuer: 'https://license.example.test', audience: 'aikayun-commerce', currentDate: new Date(now * 1000),
    });
    expect(verified.protectedHeader.alg).toBe('Ed25519');
    await expect(jwtVerify(token, publicKey, { algorithms: ['EdDSA'], currentDate: new Date(now * 1000) })).rejects.toThrow();
  });

  it('rejects a wrong Ed25519 curve/key type', async () => {
    await expect(importJWK({ ...vectorPublicJwk, crv: 'Ed448' }, 'Ed25519')).rejects.toThrow();
  });

  it('matches the RFC 7638 published JWK thumbprint vector', async () => {
    const rsaJwk = {
      kty: 'RSA', e: 'AQAB',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
    };
    expect(await calculateJwkThumbprint(rsaJwk, 'sha256')).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });

  it('matches RFC 9530 Appendix D Content-Digest bytes', async () => {
    const body = new TextEncoder().encode('{"hello": "world"}');
    const header = digestHeader(await signatures.genSingleRFC9530DigestHeader(body, 'SHA-256'));
    expect(header).toBe('sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:');
    const request = { method: 'POST', url: '/v1/activations', headers: { 'content-digest': header } };
    expect(await signatures.verifyRFC9530DigestHeader(request, body, { algorithms: ['sha-256'] })).toBe(true);
    expect(await signatures.verifyRFC9530DigestHeader(request, new TextEncoder().encode('{"hello": "world"}!'), { algorithms: ['sha-256'] })).toBe(false);
  });

  it('accepts RFC 9421 Appendix B.2.6 Ed25519 signature vector', async () => {
    const publicKey = await importJWK(vectorPublicJwk, 'Ed25519');
    const request = {
      method: 'POST', url: '/foo',
      headers: {
        host: 'example.com', date: 'Tue, 20 Apr 2021 02:07:55 GMT', 'content-type': 'application/json', 'content-length': '18',
        'signature-input': 'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
        signature: 'sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:',
      },
    };
    const parsed = signatures.parseRFC9421RequestOrResponse(request, {
      clockSkew: { now: new Date('2021-04-20T02:07:55.000Z') },
      requiredComponents: { rfc9421: ['date', '@method', '@path', '@authority', 'content-type', 'content-length'] },
    });
    expect(await signatures.verifyRFC9421Signature(parsed.value, publicKey, { verifyAll: true, algorithms: ['ed25519'] })).toBe(true);
    const wrongKey = await importJWK({ ...vectorPublicJwk, x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, 'Ed25519');
    expect(await signatures.verifyRFC9421Signature(parsed.value, wrongKey, { verifyAll: true, algorithms: ['ed25519'] })).toBe(false);
  });

  it('verifies the exact profile request and rejects identity, algorithm, nonce, digest, and target changes', async () => {
    const jkt = await calculateJwkThumbprint(vectorPublicJwk, 'sha256');
    const identityKey = await importJWK(vectorPublicJwk, 'Ed25519');
    const body = Buffer.from('{"op":"activate","nonce":"n-1"}');
    const now = Math.floor(Date.now() / 1000);
    const request = { method: 'POST', url: '/v1/activations', headers: { host: 'license.example.test', 'content-type': 'application/json' } as Record<string, string> };
    request.headers['content-digest'] = digestHeader(await signatures.genSingleRFC9530DigestHeader(body, 'SHA-256'));
    const signed = await signatures.signAsRFC9421ToRequestOrResponse(request, {
      sig1: {
        key: { privateKeyJwk: vectorPrivateJwk, keyId: jkt },
        identifiers: ['@method', '@target-uri', 'content-type', 'content-digest'],
        created: now, expiresAfter: 60, nonce: 'server-challenge-nonce', tag: 'aikayun-license-v1',
      },
    }, { scheme: 'https' });
    delete request.headers['Signature-Input'];
    delete request.headers['Signature'];
    request.headers['signature-input'] = signed.inputHeader;
    request.headers['signature'] = signed.signatureHeader;
    const rawHeaders = Object.entries(request.headers).flatMap(([key, value]) => [key, value]);
    const base = { method: 'POST', url: '/v1/activations', headers: request.headers, rawHeaders, body };
    const config = runtimeConfig(identityKey as CryptoKey, jkt);
    const valid = await verifyHttpMessage(base, vectorPublicJwk, config.publicOrigin, 'server-challenge-nonce', new Date(now * 1000));
    expect(valid.identityJkt).toBe(jkt);

    await expect(verifyHttpMessage({ ...base, body: Buffer.from('{"op":"activate","nonce":"n-2"}') }, vectorPublicJwk,
      config.publicOrigin, 'server-challenge-nonce', new Date(now * 1000))).rejects.toMatchObject({ code: 'HTTP_SIGNATURE_INVALID' });
    await expect(verifyHttpMessage({ ...base, url: '/v1/operations/query' }, vectorPublicJwk,
      config.publicOrigin, 'server-challenge-nonce', new Date(now * 1000))).rejects.toMatchObject({ code: 'HTTP_SIGNATURE_INVALID' });
    await expect(verifyHttpMessage(base, vectorPublicJwk, config.publicOrigin, 'different-nonce', new Date(now * 1000)))
      .rejects.toMatchObject({ code: 'HTTP_SIGNATURE_INVALID' });
    await expect(verifyHttpMessage(base, vectorPublicJwk, config.publicOrigin, 'server-challenge-nonce', new Date((now + 1) * 1000)))
      .resolves.toBeTruthy();

    const changedAlgorithm = { ...base, headers: { ...base.headers, 'signature-input': signed.inputHeader.replace('alg="ed25519"', 'alg="hmac-sha256"') } };
    changedAlgorithm.rawHeaders = Object.entries(changedAlgorithm.headers).flatMap(([key, value]) => [key, value]);
    await expect(verifyHttpMessage(changedAlgorithm, vectorPublicJwk, config.publicOrigin, 'server-challenge-nonce', new Date(now * 1000)))
      .rejects.toMatchObject({ code: 'HTTP_SIGNATURE_INVALID' });

    const changedIdentity = { ...base, headers: { ...base.headers, 'signature-input': signed.inputHeader.replace(jkt, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') } };
    changedIdentity.rawHeaders = Object.entries(changedIdentity.headers).flatMap(([key, value]) => [key, value]);
    await expect(verifyHttpMessage(changedIdentity, vectorPublicJwk, config.publicOrigin, 'server-challenge-nonce', new Date(now * 1000)))
      .rejects.toMatchObject({ code: 'HTTP_SIGNATURE_INVALID' });
  });

  it('rejects duplicate JSON keys, invalid UTF-8, and nested over-limit bodies', () => {
    expect(() => parseStrictJson(Buffer.from('{"operation":"activation","operation":"renewal"}'))).toThrow(/Duplicate/);
    expect(() => parseStrictJson(Uint8Array.from([0xff, 0xfe]))).toThrow();
    expect(() => parseStrictJson(Buffer.from(`{"x":${'['.repeat(33)}0${']'.repeat(33)}}`))).toThrow(/nesting/);
  });
});
