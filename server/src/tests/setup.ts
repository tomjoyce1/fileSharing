import { drizzle } from "drizzle-orm/libsql";
import { createClient } from "@libsql/client";
import { migrate } from "drizzle-orm/libsql/migrator";
import { join } from "path";

const client = createClient({
  url: ":memory:",
});

export const testDb = drizzle(client);

export async function setupTestDb() {
  await migrate(testDb, {
    migrationsFolder: join(process.cwd(), "server/drizzle"),
  });
}

// Clean up database after tests
export async function teardownTestDb() {
  client.close();
}
