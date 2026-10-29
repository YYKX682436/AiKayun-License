import { sql, type Kysely } from 'kysely';
import type { Database } from '../types.js';

export async function up(db: Kysely<Database>): Promise<void> {
  await sql`
    CREATE TABLE license_signer_operations (
      operation_id uuid PRIMARY KEY,
      request_digest text NOT NULL CHECK (request_digest ~ '^[A-Za-z0-9_-]{43}$'),
      action text NOT NULL CHECK (action IN ('initialize', 'trust_bundle_accept', 'key_rotate')),
      expected_signer_revision bigint NOT NULL CHECK (expected_signer_revision >= 0),
      previous_signing_kid text CHECK (previous_signing_kid IS NULL OR previous_signing_kid ~ '^[A-Za-z0-9_-]{43}$'),
      target_signing_kid text CHECK (target_signing_kid IS NULL OR target_signing_kid ~ '^[A-Za-z0-9_-]{43}$'),
      bundle_version text CHECK (bundle_version IS NULL OR bundle_version ~ '^[1-9][0-9]{0,18}$'),
      artifact_sha256 text CHECK (artifact_sha256 IS NULL OR artifact_sha256 ~ '^[A-Za-z0-9_-]{43}$'),
      proof_sha256 text CHECK (proof_sha256 IS NULL OR proof_sha256 ~ '^[A-Za-z0-9_-]{43}$'),
      rollout_gate text NOT NULL CHECK (rollout_gate IN ('isolated-development-confirmed')),
      reason text NOT NULL CHECK (length(reason) BETWEEN 5 AND 1000),
      actor_os_uid integer NOT NULL CHECK (actor_os_uid >= 0),
      actor_os_username text NOT NULL CHECK (length(actor_os_username) BETWEEN 1 AND 128),
      actor_database_role text NOT NULL CHECK (length(actor_database_role) BETWEEN 1 AND 128),
      state text NOT NULL CHECK (state IN ('succeeded', 'rejected')),
      outcome_code text NOT NULL CHECK (length(outcome_code) BETWEEN 1 AND 96),
      result jsonb NOT NULL,
      created_at timestamptz NOT NULL,
      finalized_at timestamptz NOT NULL,
      CHECK (finalized_at >= created_at),
      CHECK (state = 'rejected' OR
        (action = 'initialize' AND previous_signing_kid IS NULL AND target_signing_kid IS NOT NULL AND bundle_version IS NOT NULL AND artifact_sha256 IS NOT NULL) OR
        (action = 'trust_bundle_accept' AND target_signing_kid IS NULL AND bundle_version IS NOT NULL AND artifact_sha256 IS NOT NULL) OR
        (action = 'key_rotate' AND previous_signing_kid IS NOT NULL AND target_signing_kid IS NOT NULL AND bundle_version IS NOT NULL AND artifact_sha256 IS NOT NULL AND proof_sha256 IS NOT NULL)),
      CHECK (state = 'rejected' OR action <> 'key_rotate' OR previous_signing_kid <> target_signing_kid)
    );
    CREATE INDEX license_signer_operations_created ON license_signer_operations(created_at);

    CREATE TABLE license_signer_audit_events (
      event_id uuid PRIMARY KEY,
      operation_id uuid NOT NULL UNIQUE REFERENCES license_signer_operations(operation_id) ON DELETE RESTRICT,
      request_digest text NOT NULL CHECK (request_digest ~ '^[A-Za-z0-9_-]{43}$'),
      action text NOT NULL CHECK (action IN ('initialize', 'trust_bundle_accept', 'key_rotate')),
      expected_signer_revision bigint NOT NULL CHECK (expected_signer_revision >= 0),
      previous_signing_kid text,
      target_signing_kid text,
      bundle_version text CHECK (bundle_version IS NULL OR bundle_version ~ '^[1-9][0-9]{0,18}$'),
      artifact_sha256 text CHECK (artifact_sha256 IS NULL OR artifact_sha256 ~ '^[A-Za-z0-9_-]{43}$'),
      proof_sha256 text,
      rollout_gate text NOT NULL CHECK (rollout_gate = 'isolated-development-confirmed'),
      reason text NOT NULL CHECK (length(reason) BETWEEN 5 AND 1000),
      actor_os_uid integer NOT NULL CHECK (actor_os_uid >= 0),
      actor_os_username text NOT NULL CHECK (length(actor_os_username) BETWEEN 1 AND 128),
      actor_database_role text NOT NULL CHECK (length(actor_database_role) BETWEEN 1 AND 128),
      state text NOT NULL CHECK (state IN ('succeeded', 'rejected')),
      outcome_code text NOT NULL CHECK (length(outcome_code) BETWEEN 1 AND 96),
      result jsonb NOT NULL,
      created_at timestamptz NOT NULL
    );
    CREATE INDEX license_signer_audit_events_time ON license_signer_audit_events(created_at);

    CREATE TABLE license_signer_trust_bundles (
      bundle_version text PRIMARY KEY CHECK (bundle_version ~ '^[1-9][0-9]{0,18}$'),
      artifact_sha256 text NOT NULL UNIQUE CHECK (artifact_sha256 ~ '^[A-Za-z0-9_-]{43}$'),
      root_kid text NOT NULL CHECK (root_kid ~ '^[A-Za-z0-9_-]{43}$'),
      bundle_jws text NOT NULL CHECK (octet_length(bundle_jws) BETWEEN 1 AND 16384),
      revoked_kids jsonb NOT NULL CHECK (jsonb_typeof(revoked_kids) = 'array'),
      retired_kids jsonb NOT NULL CHECK (jsonb_typeof(retired_kids) = 'array'),
      accepted_by_operation_id uuid NOT NULL UNIQUE REFERENCES license_signer_operations(operation_id) ON DELETE RESTRICT,
      accepted_at timestamptz NOT NULL,
      UNIQUE(bundle_version, artifact_sha256)
    );

    CREATE TABLE license_signer_authority (
      singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
      active_signing_kid text CHECK (active_signing_kid IS NULL OR active_signing_kid ~ '^[A-Za-z0-9_-]{43}$'),
      signer_revision bigint NOT NULL DEFAULT 0 CHECK (signer_revision >= 0),
      bundle_version text CHECK (bundle_version IS NULL OR bundle_version ~ '^[1-9][0-9]{0,18}$'),
      artifact_sha256 text CHECK (artifact_sha256 IS NULL OR artifact_sha256 ~ '^[A-Za-z0-9_-]{43}$'),
      previous_signing_kid text CHECK (previous_signing_kid IS NULL OR previous_signing_kid ~ '^[A-Za-z0-9_-]{43}$'),
      changed_at timestamptz NOT NULL,
      CHECK ((bundle_version IS NULL) = (artifact_sha256 IS NULL)),
      CHECK ((active_signing_kid IS NULL AND signer_revision = 0 AND bundle_version IS NULL) OR
        (active_signing_kid IS NOT NULL AND signer_revision > 0 AND bundle_version IS NOT NULL)),
      FOREIGN KEY (bundle_version, artifact_sha256) REFERENCES license_signer_trust_bundles(bundle_version, artifact_sha256) ON DELETE RESTRICT
    );
    INSERT INTO license_signer_authority(singleton, active_signing_kid, signer_revision, bundle_version, artifact_sha256, previous_signing_kid, changed_at)
      VALUES (true, NULL, 0, NULL, NULL, NULL, clock_timestamp());

    CREATE OR REPLACE FUNCTION protect_license_signer_authority() RETURNS trigger
    LANGUAGE plpgsql AS $$
    DECLARE
      signer_operation_id uuid;
    BEGIN
      IF TG_OP = 'DELETE' OR NEW.singleton IS DISTINCT FROM OLD.singleton OR
        NEW.signer_revision < OLD.signer_revision OR NEW.signer_revision > OLD.signer_revision + 1 THEN
        RAISE EXCEPTION 'signer authority transition is invalid' USING ERRCODE = '55000';
      END IF;
      IF NEW.active_signing_kid IS DISTINCT FROM OLD.active_signing_kid THEN
        IF NEW.signer_revision <> OLD.signer_revision + 1 OR NEW.active_signing_kid IS NULL OR
          NEW.previous_signing_kid IS DISTINCT FROM OLD.active_signing_kid THEN
          RAISE EXCEPTION 'active signer changes require a single forward revision' USING ERRCODE = '55000';
        END IF;
        SELECT operation_id INTO signer_operation_id
          FROM license_signer_operations
          WHERE state = 'succeeded'
            AND action = CASE WHEN OLD.active_signing_kid IS NULL THEN 'initialize' ELSE 'key_rotate' END
            AND expected_signer_revision = OLD.signer_revision
            AND previous_signing_kid IS NOT DISTINCT FROM OLD.active_signing_kid
            AND target_signing_kid = NEW.active_signing_kid
            AND bundle_version = NEW.bundle_version
            AND artifact_sha256 = NEW.artifact_sha256
            AND result->>'signer_revision' = NEW.signer_revision::text
          LIMIT 1;
        IF signer_operation_id IS NULL THEN
          RAISE EXCEPTION 'active signer changes require a matching successful signer operation' USING ERRCODE = '55000';
        END IF;
        IF EXISTS (
          SELECT 1 FROM license_signer_operations
          WHERE state = 'succeeded' AND action IN ('initialize', 'key_rotate')
            AND target_signing_kid = NEW.active_signing_kid AND operation_id <> signer_operation_id
        ) THEN
          RAISE EXCEPTION 'a previously used signer identity cannot become active again' USING ERRCODE = '55000';
        END IF;
      ELSIF NEW.signer_revision <> OLD.signer_revision THEN
        RAISE EXCEPTION 'signer revision only changes with active signer identity' USING ERRCODE = '55000';
      END IF;
      IF NEW.bundle_version IS DISTINCT FROM OLD.bundle_version THEN
        IF OLD.bundle_version IS NOT NULL AND NEW.bundle_version IS NOT NULL AND NEW.bundle_version::numeric <= OLD.bundle_version::numeric THEN
          RAISE EXCEPTION 'accepted signer bundle version must increase monotonically' USING ERRCODE = '55000';
        END IF;
        IF NEW.active_signing_kid IS NOT DISTINCT FROM OLD.active_signing_kid AND NOT EXISTS (
          SELECT 1 FROM license_signer_operations
          WHERE state = 'succeeded' AND action = 'trust_bundle_accept'
            AND expected_signer_revision = OLD.signer_revision
            AND target_signing_kid IS NULL
            AND bundle_version = NEW.bundle_version AND artifact_sha256 = NEW.artifact_sha256
        ) THEN
          RAISE EXCEPTION 'trust bundle changes require a matching successful acceptance operation' USING ERRCODE = '55000';
        END IF;
      ELSIF NEW.artifact_sha256 IS DISTINCT FROM OLD.artifact_sha256 THEN
        RAISE EXCEPTION 'same signer bundle version cannot change artifact digest' USING ERRCODE = '55000';
      END IF;
      IF NEW.previous_signing_kid IS DISTINCT FROM OLD.previous_signing_kid AND
        NEW.active_signing_kid IS NOT DISTINCT FROM OLD.active_signing_kid THEN
        RAISE EXCEPTION 'previous signer identity changes only with active signer' USING ERRCODE = '55000';
      END IF;
      RETURN NEW;
    END;
    $$;
    CREATE TRIGGER license_signer_authority_protected BEFORE UPDATE OR DELETE ON license_signer_authority
      FOR EACH ROW EXECUTE FUNCTION protect_license_signer_authority();

    CREATE TRIGGER license_signer_operations_append_only BEFORE UPDATE OR DELETE ON license_signer_operations
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    CREATE TRIGGER license_signer_audit_events_append_only BEFORE UPDATE OR DELETE ON license_signer_audit_events
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    CREATE TRIGGER license_signer_trust_bundles_append_only BEFORE UPDATE OR DELETE ON license_signer_trust_bundles
      FOR EACH ROW EXECUTE FUNCTION reject_immutable_row_change();
    CREATE TRIGGER license_signer_authority_no_truncate BEFORE TRUNCATE ON license_signer_authority
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();
    CREATE TRIGGER license_signer_operations_no_truncate BEFORE TRUNCATE ON license_signer_operations
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();
    CREATE TRIGGER license_signer_audit_events_no_truncate BEFORE TRUNCATE ON license_signer_audit_events
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();
    CREATE TRIGGER license_signer_trust_bundles_no_truncate BEFORE TRUNCATE ON license_signer_trust_bundles
      FOR EACH STATEMENT EXECUTE FUNCTION reject_core_table_truncate();
  `.execute(db);
}

export async function down(): Promise<void> {
  throw new Error('Signing identity history is irreversible; restore from a reviewed database backup instead.');
}
