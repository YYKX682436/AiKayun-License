import { createDatabase, migrateToLatest } from './database.js';

const databaseUrl = process.env['LICENSE_DATABASE_URL'];
if (!databaseUrl || !['postgres:', 'postgresql:'].includes(new URL(databaseUrl).protocol)) {
  throw new Error('A PostgreSQL LICENSE_DATABASE_URL is required to run migrations');
}
const db = createDatabase(databaseUrl);
try {
  await migrateToLatest(db);
} finally {
  await db.destroy();
}
