import { sql, type Kysely } from 'kysely';
import { randomUUID } from 'node:crypto';
import type { Database } from '../db/types.js';
import { LicenseApiError } from '../errors.js';
import { addCalendarPeriod } from '../entitlements/calendar.js';
import { databaseNow } from './common.js';
import type { LicenseRow } from '../db/types.js';
import type { Transaction } from 'kysely';

export interface AppliedEntitlementEvent {
  eventId: string;
  licenseId: string;
  previousEnd: Date;
  newEnd: Date;
  revision: string;
  replayed: boolean;
}

export type EntitlementTransaction = Transaction<Database>;

export async function lockEntitlementEvent(trx: EntitlementTransaction, externalEventId: string): Promise<void> {
  await sql`SELECT pg_advisory_xact_lock(hashtextextended(${'entitlement-event:' + externalEventId}, 0))`.execute(trx);
}

/** Applies a confirmed renewal after the caller has locked the entitlement event key and license row. */
export async function applyConfirmedRenewalToLockedLicense(
  trx: EntitlementTransaction,
  license: LicenseRow,
  input: {
    externalEventId: string;
    actor: string;
    now: Date;
    operationId?: string;
    auditDetails?: Record<string, unknown>;
  },
): Promise<AppliedEntitlementEvent> {
  const existing = await trx.selectFrom('entitlement_events').selectAll()
    .where('external_event_id', '=', input.externalEventId).executeTakeFirst();
  if (existing) {
    if (existing.license_id !== license.id) throw new LicenseApiError(409, 'ENTITLEMENT_EVENT_CONFLICT');
    return {
      eventId: existing.id,
      licenseId: existing.license_id,
      previousEnd: existing.previous_end,
      newEnd: existing.new_end,
      revision: existing.result_revision.toString(),
      replayed: true,
    };
  }
  const activePeriod = license.confirmed_subscription_end.getTime() > input.now.getTime();
  const start = activePeriod ? license.confirmed_subscription_end : input.now;
  const anchorDay = activePeriod ? license.anchor_day : input.now.getUTCDate();
  const newEnd = addCalendarPeriod(start, license.plan, anchorDay);
  const eventId = randomUUID();
  const eventKind = license.plan === 'monthly' ? 'monthly_renewal' : 'yearly_renewal';
  const updatedRevision = (BigInt(license.entitlement_revision) + 1n).toString();
  await trx.updateTable('licenses').set({
    billing_anchor_utc: start,
    anchor_day: anchorDay,
    confirmed_subscription_end: newEnd,
    entitlement_revision: updatedRevision,
    revision: (BigInt(license.revision) + 1n).toString(),
    updated_at: input.now,
  }).where('id', '=', license.id).execute();
  await trx.insertInto('entitlement_events').values({
    id: eventId,
    license_id: license.id,
    external_event_id: input.externalEventId,
    previous_end: license.confirmed_subscription_end,
    new_end: newEnd,
    result_revision: updatedRevision,
    kind: eventKind,
    actor: input.actor,
    created_at: input.now,
  }).execute();
  await trx.insertInto('license_audit_events').values({
    id: randomUUID(),
    license_id: license.id,
    operation_id: input.operationId ?? null,
    kind: 'confirmed_renewal',
    actor: input.actor,
    safe_details: {
      event_id: eventId,
      previous_end: license.confirmed_subscription_end.toISOString(),
      new_end: newEnd.toISOString(),
      ...(input.auditDetails ?? {}),
    },
    created_at: input.now,
  }).execute();
  return { eventId, licenseId: license.id, previousEnd: license.confirmed_subscription_end, newEnd, revision: updatedRevision, replayed: false };
}

export async function applyConfirmedRenewal(
  db: Kysely<Database>,
  input: { licenseId: string; externalEventId: string; actor: string },
): Promise<AppliedEntitlementEvent> {
  if (input.externalEventId.length < 1 || input.externalEventId.length > 200 || input.actor.length < 1 || input.actor.length > 128) {
    throw new LicenseApiError(400, 'INVALID_ENTITLEMENT_EVENT');
  }
  return db.transaction().execute(async (trx) => {
    await lockEntitlementEvent(trx, input.externalEventId);
    const license = await trx.selectFrom('licenses').selectAll().where('id', '=', input.licenseId).forUpdate().executeTakeFirst();
    if (!license) throw new LicenseApiError(404, 'LICENSE_NOT_FOUND');
    const now = await databaseNow(trx);
    return applyConfirmedRenewalToLockedLicense(trx, license, {
      externalEventId: input.externalEventId,
      actor: input.actor,
      now,
    });
  });
}
