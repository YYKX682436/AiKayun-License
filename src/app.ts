import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import type { Kysely } from 'kysely';
import type { RuntimeConfig } from './config.js';
import type { Database } from './db/types.js';
import { LicenseApiError } from './errors.js';
import { performance } from 'node:perf_hooks';
import { sha256Base64url } from './crypto/identity.js';
import {
  activationIntentDigest,
  disasterTransferCommitIntentDigest,
  disasterTransferPrepareIntentDigest,
  renewalIntentDigest,
  transferCommitIntentDigest,
  transferPrepareIntentDigest,
  timeResetIntentDigest,
} from './intent.js';
import { parseStrictJson } from './strict-json.js';
import {
  assertCenterTimeSourceHealthy,
  authenticateChallengeRequest,
  authenticateOperationRequest,
  databaseNow,
  issueChallenge,
  validateNonce,
} from './services/common.js';
import {
  continueOperation,
  processActivation,
  processDisasterTransferCommit,
  processDisasterTransferPrepare,
  processRenewal,
  processTransferCommit,
  processTransferPrepare,
  processTimeReset,
  queryOperation,
  type ActivationInput,
  type DisasterTransferCommitInput,
  type DisasterTransferPrepareInput,
  type MutationResult,
  type OperationQueryInput,
  type RenewalInput,
  type TransferCommitInput,
  type TransferPrepareInput,
  type TimeResetInput,
} from './services/operations.js';
import { signTimeAnchor } from './crypto/time-reset.js';
import { lockSigningAuthorityForSigning } from './crypto/signing-authority.js';

declare module 'fastify' {
  interface FastifyRequest {
    rawBody: Buffer | null;
  }
}

interface CreateAppOptions {
  config: RuntimeConfig;
  db: Kysely<Database>;
  now?: () => Promise<Date>;
  challengeNow?: () => Promise<Date>;
}

const uuid = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
const nonce = '^[A-Za-z0-9_-]{43}$';
const digest = '^[A-Za-z0-9_-]{43}$';
const jwkSchema = {
  type: 'object', additionalProperties: false, required: ['kty', 'crv', 'x'],
  properties: { kty: { const: 'OKP' }, crv: { const: 'Ed25519' }, x: { type: 'string', pattern: nonce } },
};
const challengeTokenSchema = { type: 'string', minLength: 100, maxLength: 16384 };
const commonMutationProperties = {
  operation_id: { type: 'string', pattern: uuid },
  intent_digest: { type: 'string', pattern: digest },
  attempt_no: { type: 'integer', minimum: 1, maximum: 2147483647 },
  license_id: { type: 'string', pattern: uuid },
  database_id: { type: 'string', pattern: uuid },
  instance_id: { type: 'string', pattern: uuid },
  identity_jkt: { type: 'string', pattern: digest },
  public_jwk: jwkSchema,
  challenge: challengeTokenSchema,
};

const activationSchema = {
  type: 'object', additionalProperties: false,
  required: [...Object.keys(commonMutationProperties), 'activation_code', 'origin'],
  properties: {
    ...commonMutationProperties,
    activation_code: { type: 'string', pattern: nonce },
    origin: { anyOf: [{ type: 'string', minLength: 8, maxLength: 255 }, { type: 'null' }] },
  },
};

const renewalSchema = {
  type: 'object', additionalProperties: false,
  required: [...Object.keys(commonMutationProperties), 'expected_generation', 'known_revision'],
  properties: {
    ...commonMutationProperties,
    expected_generation: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' },
    known_revision: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' },
  },
};

const recoverySchema = {
  type: 'object', additionalProperties: false,
  required: [...Object.keys(commonMutationProperties), 'expected_generation', 'known_revision', 'recovery_of_operation_id'],
  properties: {
    ...commonMutationProperties,
    expected_generation: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' },
    known_revision: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' },
    recovery_of_operation_id: { type: 'string', pattern: uuid },
  },
};

const continueActivationSchema = {
  ...activationSchema,
  properties: { ...activationSchema.properties, kind: { const: 'activation' } },
  required: [...activationSchema.required, 'kind'],
};
const continueRenewalSchema = {
  ...renewalSchema,
  properties: { ...renewalSchema.properties, kind: { const: 'renewal' } },
  required: [...renewalSchema.required, 'kind'],
};
const continueRecoverySchema = {
  ...recoverySchema,
  properties: { ...recoverySchema.properties, kind: { const: 'recovery' } },
  required: [...recoverySchema.required, 'kind'],
};

const querySchema = {
  type: 'object', additionalProperties: false,
  required: [...Object.keys(commonMutationProperties)],
  properties: commonMutationProperties,
};

const transferPrepareSchema = {
  type: 'object', additionalProperties: false,
  required: [...Object.keys(commonMutationProperties), 'approval_id', 'target_instance_id', 'target_identity_jkt',
    'target_public_jwk', 'source_generation', 'expected_binding_revision', 'expected_revision'],
  properties: {
    ...commonMutationProperties,
    approval_id: { type: 'string', pattern: uuid },
    target_instance_id: { type: 'string', pattern: uuid },
    target_identity_jkt: { type: 'string', pattern: digest },
    target_public_jwk: jwkSchema,
    source_generation: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' },
    expected_binding_revision: { type: 'string', pattern: '^(0|[1-9][0-9]{0,18})$' },
    expected_revision: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' },
  },
};

const transferCommitSchema = {
  type: 'object', additionalProperties: false,
  required: [...Object.keys(commonMutationProperties), 'approval_id', 'prepare_operation_id', 'transfer_ticket'],
  properties: {
    ...commonMutationProperties,
    approval_id: { type: 'string', pattern: uuid },
    prepare_operation_id: { type: 'string', pattern: uuid },
    transfer_ticket: { type: 'string', minLength: 100, maxLength: 16384 },
  },
};

const disasterTransferPrepareSchema = {
  type: 'object', additionalProperties: false,
  required: [...Object.keys(commonMutationProperties), 'approval_id', 'request_id', 'account_reference',
    'source_activation_id', 'source_instance_id', 'source_identity_jkt', 'target_instance_id', 'target_identity_jkt',
    'source_generation', 'expected_binding_revision', 'expected_revision'],
  properties: {
    ...commonMutationProperties,
    approval_id: { type: 'string', pattern: uuid },
    request_id: { type: 'string', pattern: uuid },
    account_reference: { type: 'string', minLength: 1, maxLength: 200 },
    source_activation_id: { type: 'string', pattern: uuid },
    source_instance_id: { type: 'string', pattern: uuid },
    source_identity_jkt: { type: 'string', pattern: digest },
    target_instance_id: { type: 'string', pattern: uuid },
    target_identity_jkt: { type: 'string', pattern: digest },
    source_generation: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' },
    expected_binding_revision: { type: 'string', pattern: '^(0|[1-9][0-9]{0,18})$' },
    expected_revision: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' },
  },
};

const disasterTransferCommitSchema = {
  type: 'object', additionalProperties: false,
  required: [...Object.keys(commonMutationProperties), 'approval_id', 'prepare_operation_id', 'disaster_ticket'],
  properties: {
    ...commonMutationProperties,
    approval_id: { type: 'string', pattern: uuid },
    prepare_operation_id: { type: 'string', pattern: uuid },
    disaster_ticket: { type: 'string', minLength: 100, maxLength: 16384 },
  },
};

const timeAnchorSchema = {
  type: 'object', additionalProperties: false,
  required: ['client_nonce'],
  properties: { client_nonce: { type: 'string', pattern: nonce } },
};

const timeResetSchema = {
  type: 'object', additionalProperties: false,
  required: [...Object.keys(commonMutationProperties), 'activation_id', 'approval_id', 'expected_generation', 'expected_revision',
    'expected_entitlement_revision', 'expected_time_epoch', 'old_watermark_digest'],
  properties: {
    ...commonMutationProperties,
    activation_id: { type: 'string', pattern: uuid },
    approval_id: { type: 'string', pattern: uuid },
    expected_generation: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' },
    expected_revision: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' },
    expected_entitlement_revision: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' },
    expected_time_epoch: { type: 'string', pattern: '^(0|[1-9][0-9]{0,18})$' },
    old_watermark_digest: { type: 'string', pattern: digest },
  },
};

const challengeSchema = {
  type: 'object', additionalProperties: false,
  required: ['operation', 'operation_id', 'intent_digest', 'instance_id', 'public_jwk', 'client_nonce'],
  properties: {
    operation: { type: 'string', enum: ['activation', 'renewal', 'recovery', 'query', 'continue', 'transfer_prepare', 'transfer_commit', 'disaster_transfer_prepare', 'disaster_transfer_commit', 'time_reset'] },
    operation_id: { type: 'string', pattern: uuid },
    intent_digest: { type: 'string', pattern: digest },
    instance_id: { type: 'string', pattern: uuid },
    public_jwk: jwkSchema,
    client_nonce: { type: 'string', pattern: nonce },
  },
};

function requestSignatureInput(request: FastifyRequest) {
  return {
    method: request.method,
    url: request.raw.url ?? '',
    headers: request.headers as Record<string, string | string[] | undefined>,
    rawHeaders: request.raw.rawHeaders,
    body: request.rawBody ?? Buffer.alloc(0),
  };
}

function normalizeOrigin(input: string | null): string | null {
  if (input === null) return null;
  let parsed: URL;
  try { parsed = new URL(input); } catch { throw new LicenseApiError(400, 'INVALID_ORIGIN'); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash || input !== parsed.origin) {
    throw new LicenseApiError(400, 'INVALID_ORIGIN');
  }
  return parsed.origin;
}

function operationResponse(result: MutationResult, reply: FastifyReply) {
  if (result.kind === 'retryable') {
    throw new LicenseApiError(409, result.code);
  }
  const statusCode = result.state === 'rejected' ? 409 : 200;
  if (result.responseType === 'license') return reply.code(statusCode).send({ license: result.token });
  if (result.responseType === 'status') return reply.code(statusCode).send({ status_receipt: result.token });
  if (result.responseType === 'time_reset') return reply.code(statusCode).send({ time_reset_receipt: result.token });
  return reply.code(statusCode).send({ operation_receipt: result.token });
}

function transferResponse(result: MutationResult, reply: FastifyReply) {
  if (result.kind === 'retryable') return reply.code(409).send({ error: { code: result.code } });
  if (result.state === 'committed' && result.outcomeCode === 'TRANSFER_PREPARED') {
    return reply.code(200).send({ transfer_ticket: result.token });
  }
  if (result.state === 'committed' && result.outcomeCode === 'TRANSFER_COMMITTED') {
    return reply.code(200).send({ transfer_receipt: result.token });
  }
  return operationResponse(result, reply);
}

function disasterTransferResponse(result: MutationResult, reply: FastifyReply) {
  if (result.kind === 'retryable') return reply.code(409).send({ error: { code: result.code } });
  if (result.state === 'committed' && result.responseType === 'disaster_ticket') {
    return reply.code(200).send({ disaster_transfer_ticket: result.token });
  }
  if (result.state === 'committed' && result.responseType === 'disaster_active') {
    return reply.code(200).send({ transfer_receipt: result.token });
  }
  if (result.state === 'committed' && result.responseType === 'disaster_binding') {
    return reply.code(200).send({ binding_receipt: result.token });
  }
  return operationResponse(result, reply);
}

export function createApp({ config, db, now: providedNow, challengeNow: providedChallengeNow }: CreateAppOptions): FastifyInstance {
  const readNow = providedNow ?? (() => databaseNow(db));
  const readChallengeNow = providedChallengeNow ?? readNow;
  const app = Fastify({
    logger: false,
    trustProxy: false,
    bodyLimit: 32 * 1024,
    https: { key: config.tlsPrivateKey, cert: config.tlsCertificate },
    ajv: { customOptions: { allErrors: false, coerceTypes: false, removeAdditional: false, useDefaults: false } },
  });
  app.decorateRequest('rawBody', null);
  app.removeContentTypeParser('application/json');
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (request, body, done) => {
    try {
      const bytes = Buffer.from(body as Buffer);
      (request as typeof request & { rawBody?: Buffer }).rawBody = bytes;
      done(null, parseStrictJson(bytes));
    } catch {
      done(new LicenseApiError(400, 'INVALID_JSON'));
    }
  });
  app.addHook('onSend', (_request, reply, payload, done) => {
    reply.header('cache-control', 'no-store, no-cache, max-age=0');
    reply.header('pragma', 'no-cache');
    reply.header('x-content-type-options', 'nosniff');
    done(null, payload);
  });
  app.setErrorHandler((error, _request, reply) => {
    const known = error instanceof LicenseApiError;
    const fastifyError = error as { statusCode?: number };
    const receivedStatus = fastifyError.statusCode ?? 500;
    const status = known ? error.statusCode : receivedStatus >= 400 && receivedStatus < 500 ? receivedStatus : 500;
    const code = known ? error.code : status === 400 ? 'INVALID_REQUEST' : status === 413 ? 'REQUEST_TOO_LARGE' : 'INTERNAL_ERROR';
    reply.code(status).send({ error: { code } });
  });
  app.register(helmet, { contentSecurityPolicy: false });
  app.register(rateLimit, {
    global: true,
    max: 120,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({ error: { code: 'RATE_LIMITED' } }),
  });

  const anchorRateBuckets = new Map<string, { count: number; resetAt: number }>();
  app.post('/v1/time-anchor', {
    bodyLimit: 512,
    schema: { body: timeAnchorSchema },
    onRequest: async (request) => {
      const monotonicNow = performance.now();
      for (const [key, bucket] of anchorRateBuckets) {
        if (bucket.resetAt <= monotonicNow) anchorRateBuckets.delete(key);
      }
      let bucket = anchorRateBuckets.get(request.ip);
      if (!bucket || bucket.resetAt <= monotonicNow) {
        bucket = { count: 0, resetAt: monotonicNow + 60_000 };
        anchorRateBuckets.set(request.ip, bucket);
      }
      if (bucket.count >= 12) throw new LicenseApiError(429, 'RATE_LIMITED');
      bucket.count += 1;
    },
  }, async (request, reply) => {
    const body = request.body as { client_nonce: string };
    if (!validateNonce(body.client_nonce)) throw new LicenseApiError(400, 'INVALID_TIME_ANCHOR_REQUEST');
    const observedCenterTime = await readNow();
    assertCenterTimeSourceHealthy(observedCenterTime);
    const token = await db.transaction().execute(async (trx) => {
      const trustedNowOverride = providedNow ? observedCenterTime : undefined;
      const authority = await lockSigningAuthorityForSigning(trx, config, trustedNowOverride);
      assertCenterTimeSourceHealthy(authority.now);
      return signTimeAnchor(authority.signer, body.client_nonce, authority.now);
    });
    return reply.code(200).send({ time_anchor: token });
  });

  app.post('/v1/challenges', { schema: { body: challengeSchema } }, async (request, reply) => {
    const body = request.body as {
      operation: 'activation' | 'renewal' | 'recovery' | 'query' | 'continue' | 'transfer_prepare' | 'transfer_commit' | 'disaster_transfer_prepare' | 'disaster_transfer_commit' | 'time_reset';
      operation_id: string; intent_digest: string; instance_id: string; public_jwk: unknown; client_nonce: string;
    };
    const now = await readNow();
    const signature = await authenticateChallengeRequest(requestSignatureInput(request), body, config, now);
    const challengeNow = await readChallengeNow();
    const token = await issueChallenge(db, config, body, signature, challengeNow);
    return reply.code(201).send({ challenge: token });
  });

  app.post('/v1/activations', { schema: { body: activationSchema } }, async (request, reply) => {
    const body = request.body as ActivationInput;
    const origin = normalizeOrigin(body.origin);
    const now = await readNow();
    const auth = await authenticateOperationRequest(db, requestSignatureInput(request), body, config, now, 'activation');
    const expectedIntent = activationIntentDigest({
      licenseId: body.license_id,
      activationCode: body.activation_code,
      instanceId: body.instance_id,
      databaseId: body.database_id,
      identityJkt: body.identity_jkt,
      origin,
    });
    if (expectedIntent !== body.intent_digest) throw new LicenseApiError(409, 'OPERATION_INTENT_CONFLICT');
    return operationResponse(await processActivation(db, config, auth, { ...body, origin }), reply);
  });

  app.post('/v1/leases/renew', { schema: { body: { oneOf: [renewalSchema, recoverySchema] } } }, async (request, reply) => {
    const body = request.body as RenewalInput;
    const kind = body.recovery_of_operation_id ? 'recovery' : 'renewal';
    const now = await readNow();
    const auth = await authenticateOperationRequest(db, requestSignatureInput(request), body, config, now, kind);
    const expectedIntent = renewalIntentDigest({
      kind,
      licenseId: body.license_id,
      databaseId: body.database_id,
      instanceId: body.instance_id,
      identityJkt: body.identity_jkt,
      expectedGeneration: body.expected_generation,
      knownRevision: body.known_revision,
      ...(body.recovery_of_operation_id ? { recoveryOfOperationId: body.recovery_of_operation_id } : {}),
    });
    if (expectedIntent !== body.intent_digest) throw new LicenseApiError(409, 'OPERATION_INTENT_CONFLICT');
    return operationResponse(await processRenewal(db, config, auth, body), reply);
  });

  app.post('/v1/operations/query', { schema: { body: querySchema } }, async (request, reply) => {
    const body = request.body as OperationQueryInput;
    const now = await readNow();
    const auth = await authenticateOperationRequest(db, requestSignatureInput(request), body, config, now, 'query');
    const token = await queryOperation(db, config, auth, body);
    if (typeof token !== 'string') throw new LicenseApiError(409, token.retryable);
    return reply.send({ operation_receipt: token });
  });

  app.post('/v1/operations/continue', {
    schema: { body: { oneOf: [continueActivationSchema, continueRenewalSchema, continueRecoverySchema] } },
  }, async (request, reply) => {
    const body = request.body as ActivationInput & RenewalInput & { kind: 'activation' | 'renewal' | 'recovery' };
    const kind = body.kind;
    const now = await readNow();
    const auth = await authenticateOperationRequest(db, requestSignatureInput(request), body, config, now, 'continue');
    if (kind === 'activation') {
      const activation = body as ActivationInput;
      const origin = normalizeOrigin(activation.origin);
      const expectedIntent = activationIntentDigest({
        licenseId: activation.license_id,
        activationCode: activation.activation_code,
        instanceId: activation.instance_id,
        databaseId: activation.database_id,
        identityJkt: activation.identity_jkt,
        origin,
      });
      if (expectedIntent !== activation.intent_digest) throw new LicenseApiError(409, 'OPERATION_INTENT_CONFLICT');
      const token = await continueOperation(db, config, auth, kind, { ...activation, origin });
      return reply.send({ operation_receipt: token });
    }
    const renewal = body as RenewalInput;
    const expectedKind = renewal.recovery_of_operation_id ? 'recovery' : 'renewal';
    if (kind !== expectedKind) throw new LicenseApiError(400, 'INVALID_OPERATION_KIND');
    const expectedIntent = renewalIntentDigest({
      kind: expectedKind,
      licenseId: renewal.license_id,
      databaseId: renewal.database_id,
      instanceId: renewal.instance_id,
      identityJkt: renewal.identity_jkt,
      expectedGeneration: renewal.expected_generation,
      knownRevision: renewal.known_revision,
      ...(renewal.recovery_of_operation_id ? { recoveryOfOperationId: renewal.recovery_of_operation_id } : {}),
    });
    if (expectedIntent !== renewal.intent_digest) throw new LicenseApiError(409, 'OPERATION_INTENT_CONFLICT');
    const token = await continueOperation(db, config, auth, expectedKind, renewal);
    return reply.send({ operation_receipt: token });
  });

  app.post('/v1/transfers/prepare', { schema: { body: transferPrepareSchema } }, async (request, reply) => {
    const body = request.body as TransferPrepareInput;
    const auth = await authenticateOperationRequest(db, requestSignatureInput(request), body, config, await readNow(), 'transfer_prepare');
    const expectedIntent = transferPrepareIntentDigest({
      licenseId: body.license_id,
      databaseId: body.database_id,
      instanceId: body.instance_id,
      sourceIdentityJkt: body.identity_jkt,
      targetInstanceId: body.target_instance_id,
      targetIdentityJkt: body.target_identity_jkt,
      approvalId: body.approval_id,
      sourceGeneration: body.source_generation,
      expectedBindingRevision: body.expected_binding_revision,
      expectedRevision: body.expected_revision,
    });
    if (expectedIntent !== body.intent_digest) throw new LicenseApiError(409, 'OPERATION_INTENT_CONFLICT');
    return transferResponse(await processTransferPrepare(db, config, auth, body), reply);
  });

  app.post('/v1/transfers/commit', { schema: { body: transferCommitSchema } }, async (request, reply) => {
    const body = request.body as TransferCommitInput;
    const auth = await authenticateOperationRequest(db, requestSignatureInput(request), body, config, await readNow(), 'transfer_commit');
    const expectedIntent = transferCommitIntentDigest({
      licenseId: body.license_id,
      databaseId: body.database_id,
      instanceId: body.instance_id,
      targetIdentityJkt: body.identity_jkt,
      approvalId: body.approval_id,
      prepareOperationId: body.prepare_operation_id,
      ticketDigest: sha256Base64url(body.transfer_ticket),
    });
    if (expectedIntent !== body.intent_digest) throw new LicenseApiError(409, 'OPERATION_INTENT_CONFLICT');
    return transferResponse(await processTransferCommit(db, config, auth, body, readNow), reply);
  });

  app.post('/v1/disaster-transfers/prepare', { schema: { body: disasterTransferPrepareSchema } }, async (request, reply) => {
    const body = request.body as DisasterTransferPrepareInput;
    const auth = await authenticateOperationRequest(db, requestSignatureInput(request), body, config, await readNow(), 'disaster_transfer_prepare');
    const expectedIntent = disasterTransferPrepareIntentDigest({
      licenseId: body.license_id,
      accountReference: body.account_reference,
      databaseId: body.database_id,
      approvalId: body.approval_id,
      requestId: body.request_id,
      sourceActivationId: body.source_activation_id,
      sourceInstanceId: body.source_instance_id,
      sourceIdentityJkt: body.source_identity_jkt,
      targetInstanceId: body.target_instance_id,
      targetIdentityJkt: body.target_identity_jkt,
      sourceGeneration: body.source_generation,
      expectedBindingRevision: body.expected_binding_revision,
      expectedRevision: body.expected_revision,
    });
    if (expectedIntent !== body.intent_digest) throw new LicenseApiError(409, 'OPERATION_INTENT_CONFLICT');
    return disasterTransferResponse(await processDisasterTransferPrepare(db, config, auth, body), reply);
  });

  app.post('/v1/disaster-transfers/commit', { schema: { body: disasterTransferCommitSchema } }, async (request, reply) => {
    const body = request.body as DisasterTransferCommitInput;
    const auth = await authenticateOperationRequest(db, requestSignatureInput(request), body, config, await readNow(), 'disaster_transfer_commit');
    const expectedIntent = disasterTransferCommitIntentDigest({
      licenseId: body.license_id,
      databaseId: body.database_id,
      targetInstanceId: body.instance_id,
      targetIdentityJkt: body.identity_jkt,
      approvalId: body.approval_id,
      prepareOperationId: body.prepare_operation_id,
      disasterTicketDigest: sha256Base64url(body.disaster_ticket),
    });
    if (expectedIntent !== body.intent_digest) throw new LicenseApiError(409, 'OPERATION_INTENT_CONFLICT');
    return disasterTransferResponse(await processDisasterTransferCommit(db, config, auth, body, readNow), reply);
  });

  app.post('/v1/time-resets/commit', { schema: { body: timeResetSchema } }, async (request, reply) => {
    const body = request.body as TimeResetInput;
    const auth = await authenticateOperationRequest(db, requestSignatureInput(request), body, config, await readNow(), 'time_reset');
    const expectedIntent = timeResetIntentDigest({
      operationId: body.operation_id,
      approvalId: body.approval_id,
      licenseId: body.license_id,
      databaseId: body.database_id,
      instanceId: body.instance_id,
      identityJkt: body.identity_jkt,
      activationId: body.activation_id,
      activationGeneration: body.expected_generation,
      expectedRevision: body.expected_revision,
      entitlementRevision: body.expected_entitlement_revision,
      expectedTimeEpoch: body.expected_time_epoch,
      oldWatermarkDigest: body.old_watermark_digest,
    });
    if (expectedIntent !== body.intent_digest) throw new LicenseApiError(409, 'OPERATION_INTENT_CONFLICT');
    return operationResponse(await processTimeReset(db, config, auth, body), reply);
  });

  return app;
}
