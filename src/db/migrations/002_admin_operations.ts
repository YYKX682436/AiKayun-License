import { sql, type Kysely } from 'kysely';
import type { Database } from '../types.js';

export async function up(db: Kysely<Database>): Promise<void> {
  await sql`
    ALTER TABLE activation_codes
      ADD COLUMN IF NOT EXISTS revoked_at timestamptz;
    DO $$ BEGIN
      ALTER TABLE activation_codes ADD CONSTRAINT activation_codes_terminal_state_exclusive
        CHECK (consumed_at IS NULL OR revoked_at IS NULL);
    EXCEPTION WHEN duplicate_object THEN NULL;
    END $$;
    CREATE UNIQUE INDEX IF NOT EXISTS activation_codes_one_unresolved_per_license
      ON activation_codes(license_id) WHERE consumed_at IS NULL AND revoked_at IS NULL;

    CREATE OR REPLACE FUNCTION protect_consumable_secret_row() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN
        IF TG_TABLE_NAME = 'request_nonces' AND
          EXISTS (
            SELECT 1 FROM public.request_nonce_cleanup_authorizations cleanup_auth
            WHERE cleanup_auth.backend_pid = pg_backend_pid() AND cleanup_auth.nonce_hash = OLD.nonce_hash
          ) AND
          OLD.expires_at <= clock_timestamp() - interval '24 hours' THEN
          RETURN OLD;
        END IF;
        RAISE EXCEPTION 'protected table % rejects DELETE', TG_TABLE_NAME USING ERRCODE = '55000';
      END IF;
      IF TG_TABLE_NAME = 'activation_codes' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.license_id IS DISTINCT FROM OLD.license_id OR
          NEW.token_hash IS DISTINCT FROM OLD.token_hash OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
          NEW.created_at IS DISTINCT FROM OLD.created_at OR OLD.consumed_at IS NOT NULL OR OLD.revoked_at IS NOT NULL OR
          ((NEW.consumed_at IS NULL) = (NEW.revoked_at IS NULL)) THEN
          RAISE EXCEPTION 'activation code may only transition once to consumed or revoked' USING ERRCODE = '55000';
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

    CREATE TABLE IF NOT EXISTS license_admin_operations (
      operation_id uuid PRIMARY KEY,
      request_digest text NOT NULL CHECK (request_digest ~ '^[A-Za-z0-9_-]{43}$'),
      action text NOT NULL CHECK (action IN ('license_create', 'activation_code_issue', 'license_renew', 'license_revoke', 'license_restore')),
      license_id uuid NOT NULL,
      expected_revision bigint NOT NULL CHECK (expected_revision >= 0),
      actor_os_uid integer NOT NULL CHECK (actor_os_uid >= 0),
      actor_os_username text NOT NULL CHECK (length(actor_os_username) BETWEEN 1 AND 128),
      actor_database_role text NOT NULL CHECK (length(actor_database_role) BETWEEN 1 AND 128),
      reason text NOT NULL CHECK (length(reason) BETWEEN 5 AND 1000),
      state text NOT NULL CHECK (state IN ('succeeded', 'rejected')),
      outcome_code text NOT NULL CHECK (length(outcome_code) BETWEEN 1 AND 96),
      result jsonb NOT NULL,
      result_revision bigint CHECK (result_revision IS NULL OR result_revision > 0),
      created_at timestamptz NOT NULL,
      finalized_at timestamptz NOT NULL,
      CHECK (finalized_at >= created_at)
    );
    CREATE INDEX IF NOT EXISTS license_admin_operations_license_created
      ON license_admin_operations(license_id, created_at);

    CREATE TABLE IF NOT EXISTS license_admin_audit_events (
      event_id uuid PRIMARY KEY,
      operation_id uuid NOT NULL REFERENCES license_admin_operations(operation_id) ON DELETE RESTRICT,
      license_id uuid NOT NULL,
      action text NOT NULL CHECK (action IN ('license_create', 'activation_code_issue', 'license_renew', 'license_revoke', 'license_restore')),
      request_digest text NOT NULL CHECK (request_digest ~ '^[A-Za-z0-9_-]{43}$'),
      actor_os_uid integer NOT NULL CHECK (actor_os_uid >= 0),
      actor_os_username text NOT NULL CHECK (length(actor_os_username) BETWEEN 1 AND 128),
      actor_database_role text NOT NULL CHECK (length(actor_database_role) BETWEEN 1 AND 128),
      expected_revision bigint NOT NULL CHECK (expected_revision >= 0),
      reason text NOT NULL CHECK (length(reason) BETWEEN 5 AND 1000),
      state text NOT NULL CHECK (state IN ('succeeded', 'rejected')),
      outcome_code text NOT NULL CHECK (length(outcome_code) BETWEEN 1 AND 96),
      result jsonb NOT NULL,
      created_at timestamptz NOT NULL,
      UNIQUE (operation_id)
    );
    CREATE INDEX IF NOT EXISTS license_admin_audit_events_license_time
      ON license_admin_audit_events(license_id, created_at);

    DROP TRIGGER IF EXISTS license_admin_operations_no_truncate ON license_admin_operations;
    CREATE TRIGGER license_admin_operations_no_truncate BEFORE TRUNCATE ON license_admin_operations
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();
    DROP TRIGGER IF EXISTS license_admin_audit_events_no_truncate ON license_admin_audit_events;
    CREATE TRIGGER license_admin_audit_events_no_truncate BEFORE TRUNCATE ON license_admin_audit_events
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();

    DROP TRIGGER IF EXISTS license_admin_operations_append_only ON license_admin_operations;
    CREATE TRIGGER license_admin_operations_append_only BEFORE UPDATE OR DELETE ON license_admin_operations
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    DROP TRIGGER IF EXISTS license_admin_audit_events_append_only ON license_admin_audit_events;
    CREATE TRIGGER license_admin_audit_events_append_only BEFORE UPDATE OR DELETE ON license_admin_audit_events
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
  `.execute(db);
}

export async function down(): Promise<void> {
  throw new Error('Irreversible administrative audit migration; restore from a reviewed database backup instead.');
}
