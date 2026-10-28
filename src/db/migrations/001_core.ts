import { sql, type Kysely } from 'kysely';
import type { Database } from '../types.js';

export async function up(db: Kysely<Database>): Promise<void> {
  await sql`
    CREATE TABLE IF NOT EXISTS licenses (
      id uuid PRIMARY KEY,
      account_id text NOT NULL,
      plan text NOT NULL CHECK (plan IN ('monthly', 'yearly')),
      billing_anchor_utc timestamptz NOT NULL,
      anchor_day smallint NOT NULL CHECK (anchor_day BETWEEN 1 AND 31),
      confirmed_subscription_end timestamptz NOT NULL,
      status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
      current_generation bigint NOT NULL DEFAULT 0 CHECK (current_generation >= 0),
      entitlement_revision bigint NOT NULL DEFAULT 1 CHECK (entitlement_revision > 0),
      revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
      created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
      updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
    );

    CREATE TABLE IF NOT EXISTS license_activations (
      id uuid PRIMARY KEY,
      license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
      generation bigint NOT NULL CHECK (generation > 0),
      instance_id uuid NOT NULL,
      database_id uuid NOT NULL,
      identity_jwk_public jsonb NOT NULL,
      identity_jkt text NOT NULL,
      state text NOT NULL CHECK (state IN ('active', 'retired')),
      activated_at timestamptz NOT NULL,
      retired_at timestamptz,
      last_seen_at timestamptz NOT NULL,
      origin_display text,
      UNIQUE (license_id, generation),
      CHECK ((state = 'active' AND retired_at IS NULL) OR (state = 'retired' AND retired_at IS NOT NULL))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS license_activations_one_active_license
      ON license_activations(license_id) WHERE state = 'active';
    CREATE UNIQUE INDEX IF NOT EXISTS license_activations_one_active_instance
      ON license_activations(instance_id) WHERE state = 'active';
    CREATE INDEX IF NOT EXISTS license_activations_identity_jkt
      ON license_activations(identity_jkt);

    CREATE TABLE IF NOT EXISTS activation_codes (
      id uuid PRIMARY KEY,
      license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
      token_hash text NOT NULL UNIQUE,
      expires_at timestamptz NOT NULL,
      consumed_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT clock_timestamp()
    );
    CREATE INDEX IF NOT EXISTS activation_codes_license_expiry
      ON activation_codes(license_id, expires_at);

    CREATE TABLE IF NOT EXISTS request_nonces (
      nonce_hash text PRIMARY KEY,
      operation text NOT NULL,
      operation_id uuid NOT NULL,
      intent_digest text NOT NULL,
      instance_id uuid NOT NULL,
      identity_jkt text NOT NULL,
      client_nonce_hash text NOT NULL UNIQUE,
      challenge_jws_digest text NOT NULL,
      created_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      consumed_at timestamptz,
      CHECK (expires_at > created_at)
    );
    CREATE INDEX IF NOT EXISTS request_nonces_expiry ON request_nonces(expires_at);

    CREATE TABLE IF NOT EXISTS license_operations (
      operation_id uuid PRIMARY KEY,
      actor_jkt text NOT NULL,
      intent_digest text NOT NULL,
      kind text NOT NULL CHECK (kind IN ('activation', 'renewal', 'recovery')),
      license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
      database_id uuid NOT NULL,
      state text NOT NULL CHECK (state IN ('committed', 'rejected', 'cancelled')),
      outcome_code text NOT NULL,
      response_type text NOT NULL CHECK (response_type IN ('license', 'status', 'operation')),
      result_generation bigint,
      result_revision bigint,
      response_jws text NOT NULL CHECK (octet_length(response_jws) <= 16384),
      result_digest text NOT NULL,
      created_at timestamptz NOT NULL,
      finalized_at timestamptz NOT NULL,
      CHECK (finalized_at >= created_at),
      CHECK (result_generation IS NULL OR result_generation > 0),
      CHECK (result_revision IS NULL OR result_revision > 0)
    );
    CREATE INDEX IF NOT EXISTS license_operations_license_created
      ON license_operations(license_id, created_at);

    CREATE TABLE IF NOT EXISTS license_operation_attempts (
      attempt_id uuid PRIMARY KEY,
      operation_id uuid NOT NULL,
      attempt_no integer NOT NULL CHECK (attempt_no > 0),
      intent_digest text NOT NULL,
      body_digest text NOT NULL,
      client_nonce_hash text NOT NULL,
      server_nonce_hash text,
      identity_jkt text NOT NULL,
      signature_created_at timestamptz NOT NULL,
      received_at timestamptz NOT NULL,
      outcome text NOT NULL CHECK (outcome IN (
        'accepted', 'retryable_reject', 'terminal_reject',
        'committed_replay', 'terminal_replay', 'cancelled_replay'
      )),
      error_code text,
      UNIQUE (operation_id, attempt_no),
      UNIQUE (server_nonce_hash)
    );
    CREATE INDEX IF NOT EXISTS license_operation_attempts_received
      ON license_operation_attempts(received_at);

    CREATE TABLE IF NOT EXISTS entitlement_events (
      id uuid PRIMARY KEY,
      license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
      external_event_id text NOT NULL UNIQUE,
      previous_end timestamptz NOT NULL,
      new_end timestamptz NOT NULL,
      kind text NOT NULL CHECK (kind IN ('monthly_renewal', 'yearly_renewal', 'restore', 'manual_adjustment')),
      actor text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
      CHECK (new_end > previous_end)
    );

    CREATE TABLE IF NOT EXISTS license_audit_events (
      id uuid PRIMARY KEY,
      license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
      operation_id uuid,
      kind text NOT NULL,
      actor text NOT NULL,
      safe_details jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT clock_timestamp()
    );
    CREATE INDEX IF NOT EXISTS license_audit_events_license_time
      ON license_audit_events(license_id, created_at);

    CREATE OR REPLACE FUNCTION reject_immutable_row_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'immutable table % rejects %', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '55000';
    END;
    $$;

    DROP TRIGGER IF EXISTS license_operations_immutable ON license_operations;
    CREATE TRIGGER license_operations_immutable BEFORE UPDATE OR DELETE ON license_operations
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    DROP TRIGGER IF EXISTS license_operation_attempts_append_only ON license_operation_attempts;
    CREATE TRIGGER license_operation_attempts_append_only BEFORE UPDATE OR DELETE ON license_operation_attempts
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    DROP TRIGGER IF EXISTS entitlement_events_append_only ON entitlement_events;
    CREATE TRIGGER entitlement_events_append_only BEFORE UPDATE OR DELETE ON entitlement_events
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    DROP TRIGGER IF EXISTS license_audit_events_append_only ON license_audit_events;
    CREATE TRIGGER license_audit_events_append_only BEFORE UPDATE OR DELETE ON license_audit_events
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();

    CREATE OR REPLACE FUNCTION protect_consumable_secret_row() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'protected table % rejects DELETE', TG_TABLE_NAME USING ERRCODE = '55000';
      END IF;
      IF TG_TABLE_NAME = 'activation_codes' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.license_id IS DISTINCT FROM OLD.license_id OR
          NEW.token_hash IS DISTINCT FROM OLD.token_hash OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
          NEW.created_at IS DISTINCT FROM OLD.created_at OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
          RAISE EXCEPTION 'activation code may only transition once to consumed' USING ERRCODE = '55000';
        END IF;
      ELSIF TG_TABLE_NAME = 'request_nonces' THEN
        IF NEW.nonce_hash IS DISTINCT FROM OLD.nonce_hash OR NEW.operation IS DISTINCT FROM OLD.operation OR
          NEW.operation_id IS DISTINCT FROM OLD.operation_id OR NEW.intent_digest IS DISTINCT FROM OLD.intent_digest OR
          NEW.instance_id IS DISTINCT FROM OLD.instance_id OR NEW.identity_jkt IS DISTINCT FROM OLD.identity_jkt OR
          NEW.client_nonce_hash IS DISTINCT FROM OLD.client_nonce_hash OR NEW.challenge_jws_digest IS DISTINCT FROM OLD.challenge_jws_digest OR
          NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
          OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
          RAISE EXCEPTION 'request nonce may only transition once to consumed' USING ERRCODE = '55000';
        END IF;
      END IF;
      RETURN NEW;
    END;
    $$;
    DROP TRIGGER IF EXISTS activation_codes_protected ON activation_codes;
    CREATE TRIGGER activation_codes_protected BEFORE UPDATE OR DELETE ON activation_codes
      FOR EACH ROW EXECUTE FUNCTION protect_consumable_secret_row();
    DROP TRIGGER IF EXISTS request_nonces_protected ON request_nonces;
    CREATE TRIGGER request_nonces_protected BEFORE UPDATE OR DELETE ON request_nonces
      FOR EACH ROW EXECUTE FUNCTION protect_consumable_secret_row();
  `.execute(db);
}

export async function down(): Promise<void> {
  throw new Error('Irreversible production data migration; restore from a reviewed database backup instead.');
}
