import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { userInfo } from 'node:os';
import { resolve } from 'node:path';
import { sql } from 'kysely';
import { createDatabase } from '../db/database.js';
import type { Kysely } from 'kysely';
import type { Database } from '../db/types.js';

export class AdminAccessError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = 'AdminAccessError';
  }
}

export interface AdminActor {
  osUid: number;
  osUsername: string;
  databaseRole: string;
}

export interface AdminSession {
  db: Kysely<Database>;
  actor: AdminActor;
  close(): Promise<void>;
}

interface AdminPolicy {
  environment: 'isolated-development';
  allowedOsUids: number[];
  databaseRole: string;
  databaseUrlFile: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parsePolicy(value: unknown): AdminPolicy {
  if (!isRecord(value) || value['environment'] !== 'isolated-development' ||
    !Array.isArray(value['allowed_os_uids']) || value['allowed_os_uids'].length === 0 ||
    typeof value['database_role'] !== 'string' || !/^[A-Za-z_][A-Za-z0-9_$-]{0,127}$/.test(value['database_role']) ||
    typeof value['database_url_file'] !== 'string' || value['database_url_file'].trim().length === 0) {
    throw new AdminAccessError('ADMIN_POLICY_INVALID');
  }
  const allowedOsUids = value['allowed_os_uids'];
  if (allowedOsUids.some((uid) => !Number.isSafeInteger(uid) || (uid as number) < 0)) {
    throw new AdminAccessError('ADMIN_POLICY_INVALID');
  }
  const unknownKeys = Object.keys(value).filter((key) => !['environment', 'allowed_os_uids', 'database_role', 'database_url_file'].includes(key));
  if (unknownKeys.length > 0) throw new AdminAccessError('ADMIN_POLICY_INVALID');
  return {
    environment: 'isolated-development',
    allowedOsUids: [...new Set(allowedOsUids as number[])],
    databaseRole: value['database_role'],
    databaseUrlFile: value['database_url_file'],
  };
}

async function readPrivateFile(path: string, code: string): Promise<string> {
  let handle;
  try {
    const noFollow = process.platform === 'win32' ? 0 : constants.O_NOFOLLOW;
    handle = await open(path, constants.O_RDONLY | noFollow);
  } catch {
    throw new AdminAccessError(code);
  }
  try {
    const fileStat = await handle.stat();
    if (!fileStat.isFile() || (process.platform !== 'win32' && (fileStat.mode & 0o077) !== 0)) {
      throw new AdminAccessError(code);
    }
    const contents = await handle.readFile({ encoding: 'utf8' });
    if (contents.length > 16 * 1024) throw new AdminAccessError(code);
    return contents;
  } catch (error) {
    if (error instanceof AdminAccessError) throw error;
    throw new AdminAccessError(code);
  } finally {
    await handle.close().catch(() => undefined);
  }
}

function currentOsActor(allowedUids: number[]): { uid: number; username: string } {
  const getuid = process.getuid;
  const geteuid = process.geteuid;
  if (!getuid || !geteuid) throw new AdminAccessError('ADMIN_OS_IDENTITY_UNAVAILABLE');
  const uid = geteuid();
  if (getuid() !== uid || !allowedUids.includes(uid)) throw new AdminAccessError('ADMIN_OS_IDENTITY_DENIED');
  let username: string;
  try {
    const current = userInfo();
    if (current.uid !== uid) throw new Error('uid mismatch');
    username = current.username;
  } catch {
    throw new AdminAccessError('ADMIN_OS_IDENTITY_UNAVAILABLE');
  }
  if (username.length < 1 || username.length > 128 || /[\u0000-\u001f\u007f]/.test(username)) {
    throw new AdminAccessError('ADMIN_OS_IDENTITY_UNAVAILABLE');
  }
  return { uid, username };
}

function validateLoopbackDatabaseUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new AdminAccessError('ADMIN_DATABASE_URL_INVALID');
  }
  if (!['postgres:', 'postgresql:'].includes(parsed.protocol) ||
    !['localhost', '127.0.0.1', '::1', '[::1]'].includes(parsed.hostname.toLowerCase())) {
    throw new AdminAccessError('ADMIN_DATABASE_MUST_BE_LOOPBACK');
  }
  return parsed.toString();
}

export async function openAdminSession(policyFile = process.env['LICENSE_ADMIN_POLICY_FILE']): Promise<AdminSession> {
  if (process.env['NODE_ENV'] === 'production') throw new AdminAccessError('ADMIN_CLI_DISABLED_IN_PRODUCTION');
  if (!policyFile) throw new AdminAccessError('ADMIN_POLICY_FILE_REQUIRED');
  const policyPath = resolve(policyFile);
  const policyText = await readPrivateFile(policyPath, 'ADMIN_POLICY_FILE_INVALID');
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(policyText);
  } catch {
    throw new AdminAccessError('ADMIN_POLICY_INVALID');
  }
  const policy = parsePolicy(parsedJson);
  const osActor = currentOsActor(policy.allowedOsUids);
  const databaseUrlText = (await readPrivateFile(resolve(policy.databaseUrlFile), 'ADMIN_DATABASE_CREDENTIAL_FILE_INVALID')).trim();
  if (databaseUrlText.length === 0) throw new AdminAccessError('ADMIN_DATABASE_CREDENTIAL_FILE_INVALID');
  const databaseUrl = validateLoopbackDatabaseUrl(databaseUrlText);
  const db = createDatabase(databaseUrl, 4);
  try {
    const result = await sql<{ session_user: string; current_user: string }>`
      SELECT session_user::text AS session_user, current_user::text AS current_user
    `.execute(db);
    const row = result.rows[0];
    if (!row || row.session_user !== policy.databaseRole || row.current_user !== policy.databaseRole) {
      throw new AdminAccessError('ADMIN_DATABASE_ROLE_MISMATCH');
    }
    return {
      db,
      actor: { osUid: osActor.uid, osUsername: osActor.username, databaseRole: row.session_user },
      close: () => db.destroy(),
    };
  } catch (error) {
    await db.destroy().catch(() => undefined);
    if (error instanceof AdminAccessError) throw error;
    throw new AdminAccessError('ADMIN_DATABASE_AUTH_FAILED');
  }
}
