import type { CryptoKey, JWK } from 'jose';
import type { TrustedSigningKeyResolver } from './jwt.js';

export interface SigningContext {
  readonly issuer: string;
  readonly kid: string;
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
  readonly publicJwk: JWK;
  readonly signerRevision: string;
  readonly bundleVersion: string;
  readonly artifactSha256: string;
  readonly resolver: TrustedSigningKeyResolver;
}

export interface VerificationContext {
  readonly issuer: string;
  readonly resolver: TrustedSigningKeyResolver;
  readonly trustedTime: number;
}
