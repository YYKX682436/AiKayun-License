import { sql, type Kysely } from 'kysely';
import type { Database } from '../types.js';

export async function up(db: Kysely<Database>): Promise<void> {
  await sql`
    ALTER TABLE license_operations DROP CONSTRAINT IF EXISTS license_operations_kind_check;
    ALTER TABLE license_operations ADD CONSTRAINT license_operations_kind_check
      CHECK (kind IN ('activation', 'renewal', 'recovery', 'transfer_prepare', 'transfer_commit'));

    ALTER TABLE license_admin_operations DROP CONSTRAINT IF EXISTS license_admin_operations_action_check;
    ALTER TABLE license_admin_operations ADD CONSTRAINT license_admin_operations_action_check
      CHECK (action IN ('license_create', 'activation_code_issue', 'license_renew', 'license_revoke', 'license_restore', 'transfer_approve'));
    ALTER TABLE license_admin_audit_events DROP CONSTRAINT IF EXISTS license_admin_audit_events_action_check;
    ALTER TABLE license_admin_audit_events ADD CONSTRAINT license_admin_audit_events_action_check
      CHECK (action IN ('license_create', 'activation_code_issue', 'license_renew', 'license_revoke', 'license_restore', 'transfer_approve'));

    CREATE TABLE license_transfer_approvals (
      approval_id uuid PRIMARY KEY REFERENCES license_admin_operations(operation_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
      request_digest text NOT NULL CHECK (request_digest ~ '^[A-Za-z0-9_-]{43}$'),
      license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
      database_id uuid NOT NULL,
      source_instance_id uuid NOT NULL,
      source_identity_jkt text NOT NULL CHECK (source_identity_jkt ~ '^[A-Za-z0-9_-]{43}$'),
      target_instance_id uuid NOT NULL,
      target_identity_jkt text NOT NULL CHECK (target_identity_jkt ~ '^[A-Za-z0-9_-]{43}$'),
      source_generation bigint NOT NULL CHECK (source_generation > 0),
      expected_binding_revision bigint NOT NULL CHECK (expected_binding_revision >= 0),
      expected_revision bigint NOT NULL CHECK (expected_revision > 0),
      actor_os_uid integer NOT NULL CHECK (actor_os_uid >= 0),
      actor_os_username text NOT NULL CHECK (length(actor_os_username) BETWEEN 1 AND 128),
      actor_database_role text NOT NULL CHECK (length(actor_database_role) BETWEEN 1 AND 128),
      reason text NOT NULL CHECK (length(reason) BETWEEN 5 AND 1000),
      approved_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      CHECK (source_instance_id = target_instance_id),
      CHECK (source_identity_jkt <> target_identity_jkt),
      CHECK (expires_at > approved_at)
    );
    CREATE INDEX license_transfer_approvals_license_expiry
      ON license_transfer_approvals(license_id, expires_at);

    CREATE TABLE license_transfer_plans (
      plan_id uuid PRIMARY KEY,
      license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
      approval_id uuid NOT NULL REFERENCES license_transfer_approvals(approval_id) ON DELETE RESTRICT,
      prepare_operation_id uuid NOT NULL UNIQUE REFERENCES license_operations(operation_id) ON DELETE RESTRICT,
      prepare_intent_digest text NOT NULL CHECK (prepare_intent_digest ~ '^[A-Za-z0-9_-]{43}$'),
      source_activation_id uuid NOT NULL REFERENCES license_activations(id) ON DELETE RESTRICT,
      database_id uuid NOT NULL,
      source_instance_id uuid NOT NULL,
      source_identity_jkt text NOT NULL CHECK (source_identity_jkt ~ '^[A-Za-z0-9_-]{43}$'),
      target_instance_id uuid NOT NULL,
      target_identity_jkt text NOT NULL CHECK (target_identity_jkt ~ '^[A-Za-z0-9_-]{43}$'),
      target_identity_jwk_public jsonb NOT NULL,
      source_generation bigint NOT NULL CHECK (source_generation > 0),
      expected_binding_revision bigint NOT NULL CHECK (expected_binding_revision >= 0),
      expected_revision bigint NOT NULL CHECK (expected_revision > 0),
      entitlement_revision bigint NOT NULL CHECK (entitlement_revision > 0),
      ticket_jws text NOT NULL CHECK (octet_length(ticket_jws) <= 16384),
      ticket_digest text NOT NULL CHECK (ticket_digest ~ '^[A-Za-z0-9_-]{43}$'),
      state text NOT NULL CHECK (state IN ('prepared', 'committed', 'expired', 'invalidated')),
      expires_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL,
      committed_at timestamptz,
      commit_operation_id uuid UNIQUE,
      committed_generation bigint CHECK (committed_generation IS NULL OR committed_generation > 0),
      transfer_receipt_jws text CHECK (transfer_receipt_jws IS NULL OR octet_length(transfer_receipt_jws) <= 16384),
      CHECK (source_instance_id = target_instance_id),
      CHECK (source_identity_jkt <> target_identity_jkt),
      CHECK ((state = 'committed' AND committed_at IS NOT NULL AND commit_operation_id IS NOT NULL AND
        committed_generation IS NOT NULL AND transfer_receipt_jws IS NOT NULL) OR
        (state <> 'committed' AND committed_at IS NULL AND commit_operation_id IS NULL AND
        committed_generation IS NULL AND transfer_receipt_jws IS NULL))
    );
    CREATE UNIQUE INDEX license_transfer_plans_one_prepared_per_license
      ON license_transfer_plans(license_id) WHERE state = 'prepared';
    CREATE INDEX license_transfer_plans_expiry ON license_transfer_plans(state, expires_at);

    CREATE TABLE license_transfer_events (
      event_id uuid PRIMARY KEY,
      license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
      approval_id uuid NOT NULL REFERENCES license_transfer_approvals(approval_id) ON DELETE RESTRICT,
      prepare_operation_id uuid,
      commit_operation_id uuid,
      plan_id uuid REFERENCES license_transfer_plans(plan_id) ON DELETE RESTRICT,
      kind text NOT NULL CHECK (kind IN ('approved', 'prepared', 'expired', 'invalidated', 'committed', 'rejected')),
      actor text NOT NULL,
      safe_details jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL
    );
    CREATE INDEX license_transfer_events_license_time ON license_transfer_events(license_id, created_at);

    CREATE OR REPLACE FUNCTION protect_license_transfer_plan() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'license transfer plans reject DELETE' USING ERRCODE = '55000';
      END IF;
      IF ROW(NEW.plan_id, NEW.license_id, NEW.approval_id, NEW.prepare_operation_id, NEW.prepare_intent_digest,
          NEW.source_activation_id, NEW.database_id, NEW.source_instance_id, NEW.source_identity_jkt,
          NEW.target_instance_id, NEW.target_identity_jkt, NEW.target_identity_jwk_public, NEW.source_generation,
          NEW.expected_binding_revision, NEW.expected_revision, NEW.entitlement_revision, NEW.ticket_jws,
          NEW.ticket_digest, NEW.expires_at, NEW.created_at)
          IS DISTINCT FROM
         ROW(OLD.plan_id, OLD.license_id, OLD.approval_id, OLD.prepare_operation_id, OLD.prepare_intent_digest,
          OLD.source_activation_id, OLD.database_id, OLD.source_instance_id, OLD.source_identity_jkt,
          OLD.target_instance_id, OLD.target_identity_jkt, OLD.target_identity_jwk_public, OLD.source_generation,
          OLD.expected_binding_revision, OLD.expected_revision, OLD.entitlement_revision, OLD.ticket_jws,
          OLD.ticket_digest, OLD.expires_at, OLD.created_at) THEN
        RAISE EXCEPTION 'license transfer plan binding is immutable' USING ERRCODE = '55000';
      END IF;
      IF OLD.state <> 'prepared' OR NEW.state NOT IN ('committed', 'expired', 'invalidated') THEN
        RAISE EXCEPTION 'license transfer plan state transition is invalid' USING ERRCODE = '55000';
      END IF;
      IF NEW.state = 'committed' THEN
        IF NEW.committed_at IS NULL OR NEW.commit_operation_id IS NULL OR NEW.committed_generation IS NULL OR NEW.transfer_receipt_jws IS NULL THEN
          RAISE EXCEPTION 'committed transfer requires complete result facts' USING ERRCODE = '23514';
        END IF;
      ELSIF ROW(NEW.committed_at, NEW.commit_operation_id, NEW.committed_generation, NEW.transfer_receipt_jws)
          IS DISTINCT FROM ROW(OLD.committed_at, OLD.commit_operation_id, OLD.committed_generation, OLD.transfer_receipt_jws) THEN
        RAISE EXCEPTION 'uncommitted transfer cannot acquire commit facts' USING ERRCODE = '55000';
      END IF;
      RETURN NEW;
    END;
    $$;

    CREATE TRIGGER license_transfer_approvals_immutable BEFORE UPDATE OR DELETE ON license_transfer_approvals
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    CREATE TRIGGER license_transfer_plans_protected BEFORE UPDATE OR DELETE ON license_transfer_plans
      FOR EACH ROW EXECUTE FUNCTION protect_license_transfer_plan();
    CREATE TRIGGER license_transfer_events_immutable BEFORE UPDATE OR DELETE ON license_transfer_events
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    CREATE TRIGGER license_transfer_approvals_no_truncate BEFORE TRUNCATE ON license_transfer_approvals
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();
    CREATE TRIGGER license_transfer_plans_no_truncate BEFORE TRUNCATE ON license_transfer_plans
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();
    CREATE TRIGGER license_transfer_events_no_truncate BEFORE TRUNCATE ON license_transfer_events
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();
  `.execute(db);
}

export async function down(): Promise<void> {
  throw new Error('Irreversible normal-transfer and approval migration; restore from a reviewed database backup instead.');
}
