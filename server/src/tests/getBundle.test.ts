import { expect, test, describe, beforeAll, beforeEach, mock } from "bun:test";
import {
  generateKeyBundle,
  serializeKeyBundlePublic,
} from "~/utils/crypto/KeyHelper";
import {
  setupTestDb,
  testDb,
  createTestUser,
  ensureTestServerRunning,
  getTestServerUrl,
} from "./setup";
import { makeAuthenticatedPOST } from "./fileTestUtils";
import { usersTable } from "~/db/schema";
import { eq } from "drizzle-orm";

let mockDbModule: any;

describe("Get Bundle API", () => {
  let testUser: any;
  let testUserKeyBundle: any;
  let serverUrl: string;

  beforeAll(async () => {
    await setupTestDb();
    await ensureTestServerRunning();
    serverUrl = getTestServerUrl();

    // set up the database mock after testDb is initialized
    mockDbModule = mock.module("~/db", () => ({
      db: testDb,
    }));
  });

  beforeEach(async () => {
    // Clear users table before each test
    await testDb.delete(usersTable);

    // Create a fresh test user for each test
    const testUserData = await createTestUser("testuser");
    testUser = testUserData.user;
    testUserKeyBundle = testUserData.keyBundle;
  });

  test("successfully retrieve user's key bundle", async () => {
    const requestBody = { username: testUser.username };

    const response = await makeAuthenticatedPOST(
      "/api/keyhandler/getbundle",
      requestBody,
      testUser,
      testUserKeyBundle,
      serverUrl
    );

    expect(response.status).toBe(200);

    const responseData = (await response.json()) as any;
    expect(responseData.key_bundle).toBeDefined();

    const expectedBundle = serializeKeyBundlePublic(testUserKeyBundle.public);
    expect(responseData.key_bundle).toEqual(expectedBundle);
  });

  test("retrieve same user's bundle twice returns identical results", async () => {
    const requestBody = { username: testUser.username };

    const response1 = await makeAuthenticatedPOST(
      "/api/keyhandler/getbundle",
      requestBody,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response1.status).toBe(200);
    const responseData1 = (await response1.json()) as any;

    const response2 = await makeAuthenticatedPOST(
      "/api/keyhandler/getbundle",
      requestBody,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response2.status).toBe(200);
    const responseData2 = (await response2.json()) as any;

    expect(responseData1.key_bundle).toEqual(responseData2.key_bundle);
  });

  test("retrieve bundle for invalid/nonexistent user", async () => {
    const requestBody = { username: "nonexistentuser" };

    const response = await makeAuthenticatedPOST(
      "/api/keyhandler/getbundle",
      requestBody,
      testUser,
      testUserKeyBundle,
      serverUrl
    );

    expect(response.status).toBe(400);
    const responseData = (await response.json()) as any;
    expect(responseData.message).toBe("Invalid username");
  });

  test("retrieve bundle for different user", async () => {
    // make other user
    const otherUserData = await createTestUser("otheruser");
    const otherUser = otherUserData.user;
    const otherUserKeyBundle = otherUserData.keyBundle;

    // request other users bundles
    const requestBody = { username: otherUser.username };
    const response = await makeAuthenticatedPOST(
      "/api/keyhandler/getbundle",
      requestBody,
      testUser,
      testUserKeyBundle,
      serverUrl
    );

    expect(response.status).toBe(200);
    const responseData = (await response.json()) as any;

    // should get the other user's bundle
    const expectedBundle = serializeKeyBundlePublic(otherUserKeyBundle.public);
    expect(responseData.key_bundle).toEqual(expectedBundle);

    // should be different from first user's bundle
    const firstUserBundle = serializeKeyBundlePublic(testUserKeyBundle.public);
    expect(responseData.key_bundle).not.toEqual(firstUserBundle);
  });

  test("request with malformed username fails validation", async () => {
    const requestBody = { username: "ab" };

    const response = await makeAuthenticatedPOST(
      "/api/keyhandler/getbundle",
      requestBody,
      testUser,
      testUserKeyBundle,
      serverUrl
    );

    expect(response.status).toBe(400);
  });

  test("request with empty body fails", async () => {
    const response = await makeAuthenticatedPOST(
      "/api/keyhandler/getbundle",
      {},
      testUser,
      testUserKeyBundle,
      serverUrl
    );

    expect(response.status).toBe(400);
  });
});
