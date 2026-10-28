import { Kysely, PostgresDialect } from 'kysely';
import { Migrator, FileMigrationProvider } from 'kysely/migration';
import { Pool } from 'pg';
import { readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Database } from './types.js';

export function createDatabase(connectionString: string, max = 10): Kysely<Database> {
  const pool = new Pool({ connectionString, max, application_name: 'aikayun-license-center' });
  // An idle socket can fail after an unknown COMMIT outcome; pg removes it from
  // the pool and emits `error`. The request path handles the transaction error.
  pool.on('connect', (client) => client.on('error', () => undefined));
  pool.on('error', () => undefined);
  return new Kysely<Database>({
    dialect: new PostgresDialect({
      pool,
    }),
  });
}

export async function migrateToLatest(db: Kysely<Database>): Promise<void> {
  const folder = join(dirname(fileURLToPath(import.meta.url)), 'migrations');
  const migrator = new Migrator({
    db,
    provider: new FileMigrationProvider({ fs: { readdir }, path: { join }, migrationFolder: folder }),
  });
  const result = await migrator.migrateToLatest();
  if (result.error) throw result.error;
}
