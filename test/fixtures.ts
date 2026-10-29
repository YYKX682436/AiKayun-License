import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { sql, type Kysely } from 'kysely';
import { signTypedJwt } from '../src/crypto/jwt.js';
import type { RuntimeConfig } from '../src/config.js';
import type { SigningContext } from '../src/crypto/signing-types.js';
import type { Database } from '../src/db/types.js';
import type { TestIdentity } from './support/runtime.js';

export async function getDbNow(db: Kysely<Database>): Promise<Date> {
  const result = await sql<{ now: Date }>`SELECT clock_timestamp() AS now`.execute(db);
  return result.rows[0]!.now;
}

export async function createLicense(db: Kysely<Database>, input: {
  id?: string;
  plan?: 'monthly' | 'yearly';
  end?: Date;
  anchorDay?: number;
} = {}) {
  const now = await getDbNow(db);
  const id = input.id ?? randomUUID();
  const anchorDay = input.anchorDay ?? now.getUTCDate();
  const end = input.end ?? new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
  await db.insertInto('licenses').values({
    id,
    account_id: `test-${randomUUID()}`,
    plan: input.plan ?? 'monthly',
    billing_anchor_utc: now,
    anchor_day: anchorDay,
    confirmed_subscription_end: end,
    status: 'active',
    current_generation: '0',
    entitlement_revision: '1',
    revision: '1',
    created_at: now,
    updated_at: now,
  }).execute();
  return { id, now, end, anchorDay };
}

export async function createActivationCode(db: Kysely<Database>, licenseId: string) {
  const code = randomBytes(32).toString('base64url');
  const now = await getDbNow(db);
  const tokenHash = createHash('sha256').update(code).digest('base64url');
  await db.insertInto('activation_codes').values({
    id: randomUUID(), license_id: licenseId, token_hash: tokenHash,
    expires_at: new Date(now.getTime() + 24 * 60 * 60 * 1000), consumed_at: null, revoked_at: null, created_at: now,
  }).execute();
  return { code, tokenHash };
}

export async function createExpiredActivationFixture(
  db: Kysely<Database>,
  config: RuntimeConfig & SigningContext,
  identity: TestIdentity,
) {
  const license = await createLicense(db);
  const instanceId = randomUUID();
  const databaseId = randomUUID();
  const operationId = randomUUID();
  const now = await getDbNow(db);
  const iat = Math.floor(now.getTime() / 1000) - 8 * 24 * 60 * 60;
  const exp = Math.floor(now.getTime() / 1000) - 24 * 60 * 60;
  const requestNonce = randomBytes(32).toString('base64url');
  const requestDigest = randomBytes(32).toString('base64url');
  const token = await signTypedJwt(config, 'aikayun-license+jwt', {
    v: 1,
    iss: config.issuer,
    aud: 'aikayun-commerce',
    sub: license.id,
    jti: randomUUID(),
    iat,
    nbf: iat,
    exp,
    instance_id: instanceId,
    database_id: databaseId,
    identity_jkt: identity.jkt,
    activation_generation: '1',
    entitlement_revision: '1',
    plan: 'monthly',
    subscription_end: Math.floor(license.end.getTime() / 1000),
    renew_after: Math.min(iat + 6 * 60 * 60, exp),
    grants: ['create_order', 'create_top_up'],
    request_nonce: requestNonce,
    request_digest: requestDigest,
  });
  await db.updateTable('licenses').set({ current_generation: '1', revision: '2' }).where('id', '=', license.id).execute();
  const activatedAt = new Date(iat * 1000);
  await db.insertInto('license_activations').values({
    id: randomUUID(), license_id: license.id, generation: '1', instance_id: instanceId,
    database_id: databaseId, identity_jwk_public: identity.publicJwk,
    identity_jkt: identity.jkt, state: 'active', activated_at: activatedAt,
    retired_at: null, last_seen_at: now, origin_display: 'https://shop.example.test',
  }).execute();
  await db.insertInto('license_operations').values({
    operation_id: operationId, actor_jkt: identity.jkt, intent_digest: randomBytes(32).toString('base64url'),
    kind: 'activation', license_id: license.id, database_id: databaseId, state: 'committed',
    outcome_code: 'ACTIVATED', response_type: 'license', result_generation: '1', result_revision: '1',
    response_jws: token, result_digest: createHash('sha256').update(token).digest('base64url'),
    created_at: activatedAt, finalized_at: activatedAt,
  }).execute();
  await db.insertInto('license_operation_attempts').values({
    attempt_id: randomUUID(), operation_id: operationId, attempt_no: 1,
    intent_digest: (await db.selectFrom('license_operations').select('intent_digest').where('operation_id', '=', operationId).executeTakeFirstOrThrow()).intent_digest,
    body_digest: requestDigest,
    client_nonce_hash: createHash('sha256').update(randomBytes(32)).digest('base64url'),
    server_nonce_hash: createHash('sha256').update(requestNonce).digest('base64url'),
    identity_jkt: identity.jkt, signature_created_at: activatedAt, received_at: activatedAt,
    outcome: 'accepted', error_code: null,
  }).execute();
  return { ...license, instanceId, databaseId, operationId, token, exp, iat };
}
