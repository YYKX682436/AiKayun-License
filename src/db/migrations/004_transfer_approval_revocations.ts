import { sql, type Kysely } from 'kysely';
import type { Database } from '../types.js';

export async function up(db: Kysely<Database>): Promise<void> {
  await sql`
    ALTER TABLE license_admin_operations DROP CONSTRAINT IF EXISTS license_admin_operations_action_check;
    ALTER TABLE license_admin_operations ADD CONSTRAINT license_admin_operations_action_check
      CHECK (action IN ('license_create', 'activation_code_issue', 'license_renew', 'license_revoke', 'license_restore', 'transfer_approve', 'transfer_revoke'));
    ALTER TABLE license_admin_audit_events DROP CONSTRAINT IF EXISTS license_admin_audit_events_action_check;
    ALTER TABLE license_admin_audit_events ADD CONSTRAINT license_admin_audit_events_action_check
      CHECK (action IN ('license_create', 'activation_code_issue', 'license_renew', 'license_revoke', 'license_restore', 'transfer_approve', 'transfer_revoke'));
    ALTER TABLE license_transfer_events DROP CONSTRAINT IF EXISTS license_transfer_events_kind_check;
    ALTER TABLE license_transfer_events ADD CONSTRAINT license_transfer_events_kind_check
      CHECK (kind IN ('approved', 'approval_revoked', 'prepared', 'expired', 'invalidated', 'committed', 'rejected'));

    CREATE TABLE license_transfer_revocations (
      revocation_operation_id uuid PRIMARY KEY REFERENCES license_admin_operations(operation_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
      approval_id uuid NOT NULL UNIQUE REFERENCES license_transfer_approvals(approval_id) ON DELETE RESTRICT,
      license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
      request_digest text NOT NULL CHECK (request_digest ~ '^[A-Za-z0-9_-]{43}$'),
      expected_revision bigint NOT NULL CHECK (expected_revision > 0),
      actor_os_uid integer NOT NULL CHECK (actor_os_uid >= 0),
      actor_os_username text NOT NULL CHECK (length(actor_os_username) BETWEEN 1 AND 128),
      actor_database_role text NOT NULL CHECK (length(actor_database_role) BETWEEN 1 AND 128),
      reason text NOT NULL CHECK (length(reason) BETWEEN 5 AND 1000),
      revoked_at timestamptz NOT NULL
    );
    CREATE INDEX license_transfer_revocations_license ON license_transfer_revocations(license_id, revoked_at);
    CREATE TRIGGER license_transfer_revocations_immutable BEFORE UPDATE OR DELETE ON license_transfer_revocations
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    CREATE TRIGGER license_transfer_revocations_no_truncate BEFORE TRUNCATE ON license_transfer_revocations
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();
  `.execute(db);
}

export async function down(): Promise<void> {
  throw new Error('Irreversible transfer approval revocation migration; restore from a reviewed database backup instead.');
}
