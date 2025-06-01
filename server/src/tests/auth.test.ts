import { expect, test, describe } from "bun:test";
import { getTestHarness } from "./setup";
import {
  createCanonicalRequestString,
  createSignatures,
} from "~/utils/crypto/NetworkingHelper";

describe("Authentication API", () => {
  const harness = getTestHarness();
  function createValidSignatures(canonicalString: string, user: any) {
    const signatures = createSignatures(
      canonicalString,
      user.keyBundle.private
    );
    return `${signatures.preQuantum}||${signatures.postQuantum}`;
  }

  async function makeRawRequest(
    endpoint: string,
    body: Record<string, unknown>,
    headers: Record<string, string>
  ): Promise<Response> {
    return await fetch(`${harness.serverUrl}${endpoint}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
      body: JSON.stringify(body),
    });
  }

  test("replay attack protection - expired timestamp", async () => {
    await harness.createUser("testuser");
    const user = harness.getUser("testuser");

    const requestBody = { username: "testuser" };
    const endpoint = "/api/keyhandler/getbundle";

    // Create a timestamp that's older than the replay window (60 seconds)
    const oldTimestamp = new Date(Date.now() - 2 * 60 * 1000).toISOString();

    const canonicalString = createCanonicalRequestString(
      "testuser",
      oldTimestamp,
      "POST",
      endpoint,
      JSON.stringify(requestBody)
    );

    const validSignature = createValidSignatures(canonicalString, user);

    const response = await makeRawRequest(endpoint, requestBody, {
      "X-Username": "testuser",
      "X-Timestamp": oldTimestamp,
      "X-Signature": validSignature,
    });

    harness.expectUnauthorized(response);
  });

  test("lying about username - signature mismatch", async () => {
    await harness.createUser("testuser");
    await harness.createUser("otheruser");

    const testUser = harness.getUser("testuser");
    const requestBody = { username: "testuser" };
    const endpoint = "/api/keyhandler/getbundle";
    const timestamp = new Date().toISOString();

    // Create signature with testuser's keys but claim to be otheruser
    const canonicalString = createCanonicalRequestString(
      "otheruser", // Lying about username in signature
      timestamp,
      "POST",
      endpoint,
      JSON.stringify(requestBody)
    );

    const signatureWithWrongUsername = createValidSignatures(
      canonicalString,
      testUser
    );

    const response = await makeRawRequest(endpoint, requestBody, {
      "X-Username": "otheruser", // Claiming to be otheruser
      "X-Timestamp": timestamp,
      "X-Signature": signatureWithWrongUsername,
    });

    harness.expectUnauthorized(response);
  });

  test("missing X-Username header", async () => {
    await harness.createUser("testuser");
    const user = harness.getUser("testuser");

    const requestBody = { username: "testuser" };
    const endpoint = "/api/keyhandler/getbundle";
    const timestamp = new Date().toISOString();

    const canonicalString = createCanonicalRequestString(
      "testuser",
      timestamp,
      "POST",
      endpoint,
      JSON.stringify(requestBody)
    );

    const validSignature = createValidSignatures(canonicalString, user);

    const response = await makeRawRequest(endpoint, requestBody, {
      // Missing X-Username header
      "X-Timestamp": timestamp,
      "X-Signature": validSignature,
    });

    harness.expectUnauthorized(response);
  });

  test("missing X-Timestamp header", async () => {
    await harness.createUser("testuser");
    const user = harness.getUser("testuser");

    const requestBody = { username: "testuser" };
    const endpoint = "/api/keyhandler/getbundle";
    const timestamp = new Date().toISOString();

    const canonicalString = createCanonicalRequestString(
      "testuser",
      timestamp,
      "POST",
      endpoint,
      JSON.stringify(requestBody)
    );

    const validSignature = createValidSignatures(canonicalString, user);

    const response = await makeRawRequest(endpoint, requestBody, {
      "X-Username": "testuser",
      // Missing X-Timestamp header
      "X-Signature": validSignature,
    });

    harness.expectUnauthorized(response);
  });

  test("missing X-Signature header", async () => {
    await harness.createUser("testuser");

    const requestBody = { username: "testuser" };
    const endpoint = "/api/keyhandler/getbundle";
    const timestamp = new Date().toISOString();

    const response = await makeRawRequest(endpoint, requestBody, {
      "X-Username": "testuser",
      "X-Timestamp": timestamp,
      // Missing X-Signature header
    });

    harness.expectUnauthorized(response);
  });

  test("unknown username", async () => {
    // Don't create any users

    const requestBody = { username: "nonexistentuser" };
    const endpoint = "/api/keyhandler/getbundle";
    const timestamp = new Date().toISOString();

    const canonicalString = createCanonicalRequestString(
      "nonexistentuser",
      timestamp,
      "POST",
      endpoint,
      JSON.stringify(requestBody)
    );

    // Create a fake signature (won't matter since user doesn't exist)
    const fakeSignature = "fake_pre_quantum_sig||fake_post_quantum_sig";

    const response = await makeRawRequest(endpoint, requestBody, {
      "X-Username": "nonexistentuser",
      "X-Timestamp": timestamp,
      "X-Signature": fakeSignature,
    });

    harness.expectUnauthorized(response);
  });

  test("invalid signature format", async () => {
    await harness.createUser("testuser");

    const requestBody = { username: "testuser" };
    const endpoint = "/api/keyhandler/getbundle";
    const timestamp = new Date().toISOString();

    const response = await makeRawRequest(endpoint, requestBody, {
      "X-Username": "testuser",
      "X-Timestamp": timestamp,
      "X-Signature": "invalid_signature_format", // Missing || delimiter
    });

    harness.expectUnauthorized(response);
  });

  test("completely invalid signature", async () => {
    await harness.createUser("testuser");

    const requestBody = { username: "testuser" };
    const endpoint = "/api/keyhandler/getbundle";
    const timestamp = new Date().toISOString();

    const response = await makeRawRequest(endpoint, requestBody, {
      "X-Username": "testuser",
      "X-Timestamp": timestamp,
      "X-Signature": "lol xd hi",
    });

    harness.expectUnauthorized(response);
  });

  test("valid authentication should work", async () => {
    await harness.createUser("testuser");
    const response = await harness.getUserKeyBundle("testuser", "testuser");
    harness.expectSuccessfulResponse(response);
  });
});
