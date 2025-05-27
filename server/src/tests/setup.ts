import { drizzle } from "drizzle-orm/libsql";
import { createClient } from "@libsql/client";
import { migrate } from "drizzle-orm/libsql/migrator";
import { join } from "path";
import { Burger } from "burger-api";
import {
  generateKeyBundle,
  serializeKeyBundlePublic,
} from "~/utils/crypto/KeyHelper";
import { usersTable } from "~/db/schema";
import { rmSync, existsSync } from "node:fs";
import { eq } from "drizzle-orm";

let client: any;
export let testDb: any;

let burger: Burger;
let serverPort: number;

export async function setupTestDb() {
  // Create a new client for each test run
  client = createClient({
    url: ":memory:",
  });

  // Create a new test database instance
  testDb = drizzle(client);

  await migrate(testDb, {
    migrationsFolder: join(process.cwd(), "drizzle"),
  });
}

export async function startTestServer() {
  // Find available port
  serverPort = 3001;

  // Create Burger instance
  burger = new Burger({
    apiDir: "src/api",
    title: "Test API",
    version: "1.0.0",
    apiPrefix: "api",
    description: "Test API server",
    debug: false,
  });

  // Start server
  await new Promise<void>((resolve) => {
    burger.serve(serverPort, () => {
      resolve();
    });
  });
}

export function getTestServerUrl(): string {
  return `http://localhost:${serverPort}`;
}

export async function createTestUser(username: string = "testuser") {
  const keyBundle = generateKeyBundle();
  const publicBundle = serializeKeyBundlePublic(keyBundle.public);

  // Insert user into test database
  await testDb.insert(usersTable).values({
    username,
    public_key_bundle: Buffer.from(JSON.stringify(publicBundle)),
  });

  // Get the created user from database
  const user = await testDb
    .select()
    .from(usersTable)
    .where(eq(usersTable.username, username))
    .then((rows: any[]) => rows[0]);

  return {
    user,
    keyBundle,
    publicBundle,
  };
}

export function cleanupEncryptedDrive() {
  const encryptedDriveDir = join(process.cwd(), "encrypted-drive");
  if (existsSync(encryptedDriveDir)) {
    rmSync(encryptedDriveDir, { recursive: true, force: true });
  }
}

// Clean up database after tests
export async function teardownTestDb() {
  if (client) {
    client.close();
  }
}
