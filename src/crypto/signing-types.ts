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
  /** Database-backed lifecycle guard attached only to a signer held under the authority transaction lock. */
  readonly assertIssuanceAllowed: (
    claims: Readonly<Record<string, unknown>>,
    options?: { allowExpiredTestToken?: boolean },
  ) => Promise<void>;
}

export interface VerificationContext {
  readonly issuer: string;
  readonly resolver: TrustedSigningKeyResolver;
  readonly trustedTime: number;
}
