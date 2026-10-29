import { sql, type Kysely } from 'kysely';
import type { Database } from '../types.js';

export async function up(db: Kysely<Database>): Promise<void> {
  await sql`
    ALTER TABLE license_activations
      ADD COLUMN time_epoch bigint NOT NULL DEFAULT 0 CHECK (time_epoch >= 0);

    CREATE OR REPLACE FUNCTION protect_activation_time_epoch() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.time_epoch < OLD.time_epoch OR NEW.time_epoch > OLD.time_epoch + 1 THEN
        RAISE EXCEPTION 'activation time_epoch must increase monotonically by one' USING ERRCODE = '55000';
      END IF;
      IF NEW.time_epoch <> OLD.time_epoch AND OLD.state <> 'active' THEN
        RAISE EXCEPTION 'retired activation time_epoch cannot change' USING ERRCODE = '55000';
      END IF;
      RETURN NEW;
    END;
    $$;
    CREATE TRIGGER license_activations_time_epoch_protected
      BEFORE UPDATE OF time_epoch ON license_activations
      FOR EACH ROW EXECUTE FUNCTION protect_activation_time_epoch();

    ALTER TABLE license_operations DROP CONSTRAINT IF EXISTS license_operations_kind_check;
    ALTER TABLE license_operations ADD CONSTRAINT license_operations_kind_check
      CHECK (kind IN ('activation', 'renewal', 'recovery', 'transfer_prepare', 'transfer_commit',
        'disaster_transfer_prepare', 'disaster_transfer_commit', 'time_reset'));
    ALTER TABLE license_operations DROP CONSTRAINT IF EXISTS license_operations_response_type_check;
    ALTER TABLE license_operations ADD CONSTRAINT license_operations_response_type_check
      CHECK (response_type IN ('license', 'status', 'operation', 'disaster_ticket', 'disaster_active', 'disaster_binding', 'time_reset'));

    ALTER TABLE license_admin_operations DROP CONSTRAINT IF EXISTS license_admin_operations_action_check;
    ALTER TABLE license_admin_operations ADD CONSTRAINT license_admin_operations_action_check
      CHECK (action IN ('license_create', 'activation_code_issue', 'license_renew', 'license_revoke', 'license_restore',
        'transfer_approve', 'transfer_revoke', 'disaster_transfer_approve', 'disaster_transfer_revoke',
        'time_reset_approve', 'time_reset_revoke'));
    ALTER TABLE license_admin_audit_events DROP CONSTRAINT IF EXISTS license_admin_audit_events_action_check;
    ALTER TABLE license_admin_audit_events ADD CONSTRAINT license_admin_audit_events_action_check
      CHECK (action IN ('license_create', 'activation_code_issue', 'license_renew', 'license_revoke', 'license_restore',
        'transfer_approve', 'transfer_revoke', 'disaster_transfer_approve', 'disaster_transfer_revoke',
        'time_reset_approve', 'time_reset_revoke'));

    CREATE TABLE license_time_reset_approvals (
      approval_id uuid PRIMARY KEY REFERENCES license_admin_operations(operation_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
      request_digest text NOT NULL CHECK (request_digest ~ '^[A-Za-z0-9_-]{43}$'),
      license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
      activation_id uuid NOT NULL REFERENCES license_activations(id) ON DELETE RESTRICT,
      database_id uuid NOT NULL,
      instance_id uuid NOT NULL,
      identity_jkt text NOT NULL CHECK (identity_jkt ~ '^[A-Za-z0-9_-]{43}$'),
      activation_generation bigint NOT NULL CHECK (activation_generation > 0),
      expected_revision bigint NOT NULL CHECK (expected_revision > 0),
      entitlement_revision bigint NOT NULL CHECK (entitlement_revision > 0),
      expected_time_epoch bigint NOT NULL CHECK (expected_time_epoch >= 0),
      new_time_epoch bigint NOT NULL,
      reset_operation_id uuid NOT NULL UNIQUE,
      intent_digest text NOT NULL CHECK (intent_digest ~ '^[A-Za-z0-9_-]{43}$'),
      old_watermark_digest text NOT NULL CHECK (old_watermark_digest ~ '^[A-Za-z0-9_-]{43}$'),
      actor_os_uid integer NOT NULL CHECK (actor_os_uid >= 0),
      actor_os_username text NOT NULL CHECK (length(actor_os_username) BETWEEN 1 AND 128),
      actor_database_role text NOT NULL CHECK (length(actor_database_role) BETWEEN 1 AND 128),
      reason text NOT NULL CHECK (length(reason) BETWEEN 5 AND 1000),
      approved_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      CHECK (new_time_epoch = expected_time_epoch + 1),
      CHECK (expires_at > approved_at)
    );
    CREATE INDEX license_time_reset_approvals_license_epoch
      ON license_time_reset_approvals(license_id, activation_generation, expected_time_epoch, expires_at);

    CREATE TABLE license_time_reset_revocations (
      revocation_operation_id uuid PRIMARY KEY REFERENCES license_admin_operations(operation_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
      approval_id uuid NOT NULL UNIQUE REFERENCES license_time_reset_approvals(approval_id) ON DELETE RESTRICT,
      license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
      request_digest text NOT NULL CHECK (request_digest ~ '^[A-Za-z0-9_-]{43}$'),
      expected_revision bigint NOT NULL CHECK (expected_revision > 0),
      actor_os_uid integer NOT NULL CHECK (actor_os_uid >= 0),
      actor_os_username text NOT NULL CHECK (length(actor_os_username) BETWEEN 1 AND 128),
      actor_database_role text NOT NULL CHECK (length(actor_database_role) BETWEEN 1 AND 128),
      reason text NOT NULL CHECK (length(reason) BETWEEN 5 AND 1000),
      revoked_at timestamptz NOT NULL
    );
    CREATE INDEX license_time_reset_revocations_license ON license_time_reset_revocations(license_id, revoked_at);

    CREATE TABLE license_time_reset_events (
      event_id uuid PRIMARY KEY,
      license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
      approval_id uuid NOT NULL REFERENCES license_time_reset_approvals(approval_id) ON DELETE RESTRICT,
      operation_id uuid NOT NULL,
      kind text NOT NULL CHECK (kind IN ('approved', 'approval_revoked', 'committed')),
      actor text NOT NULL,
      safe_details jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL
    );
    CREATE INDEX license_time_reset_events_license_time ON license_time_reset_events(license_id, created_at);

    CREATE TRIGGER license_time_reset_approvals_immutable BEFORE UPDATE OR DELETE ON license_time_reset_approvals
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    CREATE TRIGGER license_time_reset_revocations_immutable BEFORE UPDATE OR DELETE ON license_time_reset_revocations
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    CREATE TRIGGER license_time_reset_events_immutable BEFORE UPDATE OR DELETE ON license_time_reset_events
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    CREATE TRIGGER license_time_reset_approvals_no_truncate BEFORE TRUNCATE ON license_time_reset_approvals
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();
    CREATE TRIGGER license_time_reset_revocations_no_truncate BEFORE TRUNCATE ON license_time_reset_revocations
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();
    CREATE TRIGGER license_time_reset_events_no_truncate BEFORE TRUNCATE ON license_time_reset_events
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();
  `.execute(db);
}

export async function down(): Promise<void> {
  throw new Error('Time-reset approvals and epoch history are irreversible; restore from a reviewed database backup instead.');
}
