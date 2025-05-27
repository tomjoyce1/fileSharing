import { expect, test, describe, beforeAll, afterAll, mock } from "bun:test";
import {
  generateKeyBundle,
  serializeKeyBundlePublic,
} from "~/utils/crypto/KeyHelper";
import { POST } from "~/api/auth/register/route";
import { setupTestDb, teardownTestDb, testDb } from "./setup";
import { usersTable } from "~/db/schema";
import { eq } from "drizzle-orm";

describe("Register API", () => {
  beforeAll(async () => {
    await setupTestDb();

    // Mock the database module to use our test database
    mock.module("~/db", () => ({
      db: testDb,
    }));
  });

  afterAll(async () => {
    await teardownTestDb();
  });

  test("register user works", async () => {
    const username = "testuser";
    const keyBundle = generateKeyBundle();
    const serializedPublicBundle = serializeKeyBundlePublic(keyBundle.public);

    const mockRequest = {
      validated: {
        body: {
          username,
          key_bundle: serializedPublicBundle,
        },
      },
    };

    const response = await POST(mockRequest as any);
    const responseData = (await response.json()) as any;

    expect(response.status).toBe(201);
    expect(responseData.message).toBe("User registered");

    // ensure user actually in DB
    const insertedUser = await testDb
      .select()
      .from(usersTable)
      .where(eq(usersTable.username, username));

    expect(insertedUser).toHaveLength(1);
    expect(insertedUser[0]?.username).toBe(username);
    expect(insertedUser[0]?.public_key_bundle).toEqual(
      Buffer.from(JSON.stringify(serializedPublicBundle))
    );
  });

  test("register user with duplicate username fails", async () => {
    const username = "duplicateuser";
    const keyBundle = generateKeyBundle();
    const serializedPublicBundle = serializeKeyBundlePublic(keyBundle.public);

    // add user to db
    await testDb.insert(usersTable).values({
      username,
      public_key_bundle: Buffer.from(JSON.stringify(serializedPublicBundle)),
    });

    // try to register the same username again
    const mockRequest = {
      validated: {
        body: {
          username,
          key_bundle: serializedPublicBundle,
        },
      },
    };

    const response = await POST(mockRequest as any);
    const responseData = (await response.json()) as any;

    expect(response.status).toBe(400);
    expect(responseData.message).toBe("Username already taken");
  });
});
