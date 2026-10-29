import { sql, type Kysely } from 'kysely';
import type { Database } from '../../src/db/types.js';

async function waitUntil(db: Kysely<Database>, query: () => Promise<number>, expected: number, description: string): Promise<void> {
  const deadline = Date.now() + 10_000;
  let latest = 0;
  while (Date.now() < deadline) {
    latest = await query();
    if (latest >= expected) return;
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
  throw new Error(`Timed out waiting for ${description}; observed ${latest}, expected ${expected}`);
}

export async function waitForLicenseRowWaiters(db: Kysely<Database>, count: number): Promise<void> {
  await waitUntil(db, async () => {
    const result = await sql<{ count: string }>`
      SELECT count(*)::text AS count
      FROM pg_stat_activity
      WHERE application_name = 'aikayun-license-center'
        AND wait_event_type = 'Lock'
        AND state = 'active'
        AND query ILIKE '%FOR UPDATE%'
        AND pid <> pg_backend_pid()
    `.execute(db);
    return Number(result.rows[0]!.count);
  }, count, 'PostgreSQL row-lock waiters');
}

export async function waitForLicenseRowWaiterPids(db: Kysely<Database>, count: number): Promise<number[]> {
  let pids: number[] = [];
  await waitUntil(db, async () => {
    const result = await sql<{ pid: number }>`
      SELECT pid
      FROM pg_stat_activity
      WHERE application_name = 'aikayun-license-center'
        AND wait_event_type = 'Lock'
        AND state = 'active'
        AND query ILIKE '%FOR UPDATE%'
        AND pid <> pg_backend_pid()
      ORDER BY pid
    `.execute(db);
    pids = result.rows.map(({ pid }) => pid);
    return pids.length;
  }, count, 'PostgreSQL row-lock waiter process IDs');
  return pids;
}

export async function terminatePostgresBackend(db: Kysely<Database>, pid: number): Promise<void> {
  await sql`SELECT pg_terminate_backend(${pid})`.execute(db);
}

export async function waitForAdvisoryLockWaiters(db: Kysely<Database>, count: number): Promise<void> {
  await waitUntil(db, async () => {
    const result = await sql<{ count: string }>`
      SELECT count(*)::text AS count
      FROM pg_locks l
      JOIN pg_stat_activity a USING (pid)
      WHERE a.application_name = 'aikayun-license-center'
        AND l.locktype = 'advisory'
        AND NOT l.granted
        AND a.pid <> pg_backend_pid()
    `.execute(db);
    return Number(result.rows[0]!.count);
  }, count, 'PostgreSQL advisory-lock waiters');
}

export async function waitForAdvisoryLockWaiterPids(db: Kysely<Database>, count: number): Promise<number[]> {
  let pids: number[] = [];
  await waitUntil(db, async () => {
    const result = await sql<{ pid: number }>`
      SELECT a.pid
      FROM pg_locks l
      JOIN pg_stat_activity a USING (pid)
      WHERE a.application_name = 'aikayun-license-center'
        AND l.locktype = 'advisory'
        AND NOT l.granted
        AND a.pid <> pg_backend_pid()
      ORDER BY a.pid
    `.execute(db);
    pids = result.rows.map(({ pid }) => pid);
    return pids.length;
  }, count, 'PostgreSQL advisory-lock waiter process IDs');
  return pids;
}

export async function waitForNoLockWaiters(db: Kysely<Database>): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const result = await sql<{ count: string }>`
      SELECT count(*)::text AS count
      FROM pg_stat_activity
      WHERE application_name = 'aikayun-license-center'
        AND wait_event_type = 'Lock'
        AND pid <> pg_backend_pid()
    `.execute(db);
    if (Number(result.rows[0]!.count) === 0) return;
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
  const diagnostic = await sql<{ details: string | null }>`
    SELECT json_agg(json_build_object(
      'pid', pid, 'state', state, 'wait_event_type', wait_event_type, 'wait_event', wait_event,
      'query', left(query, 160)
    ))::text AS details
    FROM pg_stat_activity
    WHERE application_name = 'aikayun-license-center'
      AND wait_event_type = 'Lock'
      AND pid <> pg_backend_pid()
  `.execute(db);
  throw new Error(`PostgreSQL still reports a license-center lock waiter: ${diagnostic.rows[0]!.details ?? 'no details'}`);
}
