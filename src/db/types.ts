import type { ColumnType, Generated, Selectable } from 'kysely';

type Timestamp = ColumnType<Date, Date | string, Date | string>;
type Bigint = ColumnType<string, number | string, number | string>;
type DefaultedBigint = ColumnType<string, number | string | undefined, number | string>;
type NullableTimestamp = ColumnType<Date | null, Date | string | null | undefined, Date | string | null>;
type Json = ColumnType<Record<string, unknown>, Record<string, unknown>, Record<string, unknown>>;

export interface LicensesTable {
  id: string;
  account_id: string;
  plan: 'monthly' | 'yearly';
  billing_anchor_utc: Timestamp;
  anchor_day: number;
  confirmed_subscription_end: Timestamp;
  status: 'active' | 'revoked';
  current_generation: DefaultedBigint;
  entitlement_revision: Bigint;
  revision: Bigint;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export interface LicenseActivationsTable {
  id: string;
  license_id: string;
  generation: Bigint;
  instance_id: string;
  database_id: string;
  identity_jwk_public: Json;
  identity_jkt: string;
  state: 'active' | 'retired';
  activated_at: Timestamp;
  retired_at: Timestamp | null;
  last_seen_at: Timestamp;
  origin_display: string | null;
}

export interface ActivationCodesTable {
  id: string;
  license_id: string;
  token_hash: string;
  expires_at: Timestamp;
  consumed_at: NullableTimestamp;
  revoked_at: NullableTimestamp;
  created_at: Timestamp;
}

export interface RequestNoncesTable {
  nonce_hash: string;
  operation: string;
  operation_id: string;
  intent_digest: string;
  instance_id: string;
  identity_jkt: string;
  client_nonce_hash: string;
  challenge_jws_digest: string;
  created_at: Timestamp;
  expires_at: Timestamp;
  consumed_at: Timestamp | null;
}

export interface LicenseOperationsTable {
  operation_id: string;
  actor_jkt: string;
  intent_digest: string;
  kind: 'activation' | 'renewal' | 'recovery';
  license_id: string;
  database_id: string;
  state: 'committed' | 'rejected' | 'cancelled';
  outcome_code: string;
  response_type: 'license' | 'status' | 'operation';
  result_generation: Bigint | null;
  result_revision: Bigint | null;
  response_jws: string;
  result_digest: string;
  created_at: Timestamp;
  finalized_at: Timestamp;
}

export interface LicenseOperationAttemptsTable {
  attempt_id: Generated<string>;
  operation_id: string;
  attempt_no: number;
  intent_digest: string;
  body_digest: string;
  client_nonce_hash: string;
  server_nonce_hash: string | null;
  identity_jkt: string;
  signature_created_at: Timestamp;
  received_at: Timestamp;
  outcome: 'accepted' | 'retryable_reject' | 'terminal_reject' | 'committed_replay' | 'terminal_replay' | 'cancelled_replay';
  error_code: string | null;
}

export interface EntitlementEventsTable {
  id: Generated<string>;
  license_id: string;
  external_event_id: string;
  previous_end: Timestamp;
  new_end: Timestamp;
  result_revision: Bigint;
  kind: 'monthly_renewal' | 'yearly_renewal' | 'restore' | 'manual_adjustment';
  actor: string;
  created_at: Timestamp;
}

export interface LicenseAuditEventsTable {
  id: Generated<string>;
  license_id: string;
  operation_id: string | null;
  kind: string;
  actor: string;
  safe_details: Json;
  created_at: Timestamp;
}

export interface LicenseAdminOperationsTable {
  operation_id: string;
  request_digest: string;
  action: 'license_create' | 'activation_code_issue' | 'license_renew' | 'license_revoke' | 'license_restore';
  license_id: string;
  expected_revision: Bigint;
  actor_os_uid: number;
  actor_os_username: string;
  actor_database_role: string;
  reason: string;
  state: 'succeeded' | 'rejected';
  outcome_code: string;
  result: Json;
  result_revision: Bigint | null;
  created_at: Timestamp;
  finalized_at: Timestamp;
}

export interface LicenseAdminAuditEventsTable {
  event_id: string;
  operation_id: string;
  license_id: string;
  action: LicenseAdminOperationsTable['action'];
  request_digest: string;
  actor_os_uid: number;
  actor_os_username: string;
  actor_database_role: string;
  expected_revision: Bigint;
  reason: string;
  state: LicenseAdminOperationsTable['state'];
  outcome_code: string;
  result: Json;
  created_at: Timestamp;
}

export interface Database {
  licenses: LicensesTable;
  license_activations: LicenseActivationsTable;
  activation_codes: ActivationCodesTable;
  request_nonces: RequestNoncesTable;
  license_operations: LicenseOperationsTable;
  license_operation_attempts: LicenseOperationAttemptsTable;
  entitlement_events: EntitlementEventsTable;
  license_audit_events: LicenseAuditEventsTable;
  license_admin_operations: LicenseAdminOperationsTable;
  license_admin_audit_events: LicenseAdminAuditEventsTable;
}

export type LicenseRow = Selectable<LicensesTable>;
export type ActivationRow = Selectable<LicenseActivationsTable>;
export type ActivationCodeRow = Selectable<ActivationCodesTable>;
export type RequestNonceRow = Selectable<RequestNoncesTable>;
export type OperationRow = Selectable<LicenseOperationsTable>;
export type LicenseAdminOperationRow = Selectable<LicenseAdminOperationsTable>;
export type LicenseAdminAuditEventRow = Selectable<LicenseAdminAuditEventsTable>;
