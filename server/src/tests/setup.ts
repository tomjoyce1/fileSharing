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

// Global singleton server instance
let globalBurger: Burger | null = null;
let globalServerPort = 3001;
let isGlobalServerRunning = false;
let serverStartPromise: Promise<void> | null = null;

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

export async function ensureTestServerRunning() {
  // if server is already running, return immediately
  if (isGlobalServerRunning && globalBurger) {
    return;
  }

  // if server is in the process of starting, wait for it
  if (serverStartPromise) {
    return serverStartPromise;
  }

  // start the server
  serverStartPromise = startGlobalServer();
  return serverStartPromise;
}

async function startGlobalServer() {
  if (isGlobalServerRunning) return;

  // Create Burger instance
  globalBurger = new Burger({
    apiDir: "src/api",
    title: "Test API",
    version: "1.0.0",
    apiPrefix: "api",
    description: "Test API server",
    debug: false,
  });

  // start server
  await new Promise<void>((resolve, reject) => {
    globalBurger!.serve(globalServerPort, () => {
      isGlobalServerRunning = true;
      console.log(`Test server started on port ${globalServerPort}`);
      resolve();
    });
  });
}

// Legacy function for backward compatibility
export async function startTestServer() {
  return ensureTestServerRunning();
}

export function getTestServerUrl(): string {
  return `http://localhost:${globalServerPort}`;
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
