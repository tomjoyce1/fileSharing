import { expect, test, describe } from "bun:test";
import {
  generateKeyBundle,
  serializeKeyBundlePublic,
} from "~/utils/crypto/KeyHelper";
import { POST } from "~/api/keyhandler/register/route";
import { getTestHarness, testDb } from "./setup";
import { usersTable } from "~/db/schema";
import { eq } from "drizzle-orm";

describe("Register API", () => {
  const harness = getTestHarness();

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

    // Ensure user actually in DB
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

    // Create user first
    await harness.createUser(username);

    // Try to register the same username again
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

    expect(response.status).toBe(400);
    expect(responseData.message).toBe("Username already taken");
  });
});
