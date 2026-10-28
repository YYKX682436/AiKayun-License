import type { Kysely } from 'kysely';
import { loadConfig } from './config.js';
import { createDatabase, migrateToLatest } from './db/database.js';
import { createApp } from './app.js';
import type { Database } from './db/types.js';

let db: Kysely<Database> | undefined;
try {
  const config = await loadConfig();
  db = createDatabase(config.databaseUrl);
  await migrateToLatest(db);
  const app = createApp({ config, db });
  await app.listen({ host: config.listenHost, port: config.port });
} catch {
  await db?.destroy().catch(() => undefined);
  process.stderr.write('License center startup failed; details are intentionally redacted.\n');
  process.exitCode = 1;
}
