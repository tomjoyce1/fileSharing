import {
  expect,
  test,
  describe,
  beforeAll,
  afterAll,
  beforeEach,
  afterEach,
  mock,
} from "bun:test";
import {
  setupTestDb,
  teardownTestDb,
  testDb,
  startTestServer,
  getTestServerUrl,
  createTestUser,
  cleanupEncryptedDrive,
} from "./setup";
import { filesTable } from "~/db/schema";
import { createHash, sign as nodeSign } from "node:crypto";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { createSignedPOST } from "~/utils/crypto/NetworkingHelper";

let mockDbModule: any;

describe("File Upload API", () => {
  let testUser: any;
  let testKeyBundle: any;
  let serverUrl: string;

  beforeAll(async () => {
    await setupTestDb();
    await startTestServer();
    serverUrl = getTestServerUrl();

    // Set up the database mock after testDb is initialized
    mockDbModule = mock.module("~/db", () => ({
      db: testDb,
    }));

    // Create test user
    const testUserData = await createTestUser("testuser");
    testUser = testUserData.user;
    testKeyBundle = testUserData.keyBundle;
  });

  afterAll(async () => {
    await teardownTestDb();
  });

  beforeEach(async () => {
    await testDb.delete(filesTable);
  });

  afterEach(() => {
    cleanupEncryptedDrive();
  });

  function createTestMetadata(overrides: Partial<any> = {}) {
    return {
      original_filename: "test-document.pdf",
      file_size_bytes: 1024,
      file_type: "pdf",
      hash_of_encrypted_content: "sha256hash123",
      ...overrides,
    };
  }

  function createFileContent(content = "encrypted file content") {
    return Buffer.from(content).toString("base64");
  }

  function createFileSignatures(
    metadata_payload: string,
    useBadSignature = false
  ) {
    const metadataBuffer = Buffer.from(metadata_payload, "base64");
    const metadataHash = createHash("sha256")
      .update(metadataBuffer)
      .digest("hex");

    const dataToSign = `${testUser.user_id}|${metadataHash}`;

    const preQuantumSignature = nodeSign(
      null,
      Buffer.from(dataToSign),
      testKeyBundle.private.preQuantum.identitySigning.privateKey
    ).toString("base64");

    const postQuantumSignature = Buffer.from(
      ml_dsa87.sign(
        testKeyBundle.private.postQuantum.identitySigning.privateKey,
        Buffer.from(dataToSign)
      )
    ).toString("base64");

    return {
      pre_quantum_signature: useBadSignature ? "invalid" : preQuantumSignature,
      post_quantum_signature: postQuantumSignature,
    };
  }

  function createUploadRequestBody(
    fileContent: string,
    metadata: any,
    nonce = "nonce123",
    useBadSignature = false
  ) {
    const metadataPayload = Buffer.from(JSON.stringify(metadata)).toString(
      "base64"
    );
    const metadataNonce = Buffer.from(nonce).toString("base64");
    const signatures = createFileSignatures(metadataPayload, useBadSignature);

    return {
      file_content: fileContent,
      metadata_payload: metadataPayload,
      metadata_payload_nonce: metadataNonce,
      ...signatures,
    };
  }

  async function makeAuthenticatedRequest(
    requestBody: any,
    username = testUser.username
  ) {
    return await createSignedPOST(
      "/api/fs/upload",
      requestBody,
      username,
      testKeyBundle.private,
      serverUrl
    );
  }

  async function makeUnauthenticatedRequest(
    requestBody: any,
    headerOverrides: Record<string, string> = {}
  ) {
    const defaultHeaders = {
      "Content-Type": "application/json",
      "X-Username": testUser.username,
      "X-Timestamp": new Date().toISOString(),
      "X-Signature": "fake||signature",
    };

    return await fetch(`${serverUrl}/api/fs/upload`, {
      method: "POST",
      headers: { ...defaultHeaders, ...headerOverrides },
      body: JSON.stringify(requestBody),
    });
  }

  async function makeRequestWithCustomTimestamp(
    requestBody: any,
    timestamp: string
  ) {
    const canonicalRequestString = `${
      testUser.username
    }|${timestamp}|POST|/api/fs/upload|${JSON.stringify(requestBody)}`;

    const requestPreSig = nodeSign(
      null,
      Buffer.from(canonicalRequestString),
      testKeyBundle.private.preQuantum.identitySigning.privateKey
    ).toString("base64");

    const requestPostSig = Buffer.from(
      ml_dsa87.sign(
        testKeyBundle.private.postQuantum.identitySigning.privateKey,
        Buffer.from(canonicalRequestString)
      )
    ).toString("base64");

    const requestSignature = `${requestPreSig}||${requestPostSig}`;

    return await fetch(`${serverUrl}/api/fs/upload`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Username": testUser.username,
        "X-Timestamp": timestamp,
        "X-Signature": requestSignature,
      },
      body: JSON.stringify(requestBody),
    });
  }

  async function expectSuccessfulUpload(response: Response) {
    const responseData = (await response.json()) as any;
    expect(response.status).toBe(201);
    expect(responseData.message).toBe("File uploaded successfully");

    // Verify database record
    const files = await testDb.select().from(filesTable);
    expect(files).toHaveLength(1);

    const file = files[0];
    if (!file) throw new Error("File record not found");
    expect(file.owner_user_id).toBe(testUser.user_id);
    expect(file.storage_path).toContain("encrypted-drive");
    expect(file.storage_path).toContain(".enc");
    expect(file.metadata_payload.length).toBeGreaterThan(0);

    return file;
  }

  async function expectUnauthorized(response: Response) {
    const responseData = (await response.json()) as any;
    expect(response.status).toBe(401);
    expect(responseData.message).toBe("Unauthorized");

    // Verify no database record was created
    const files = await testDb.select().from(filesTable);
    expect(files).toHaveLength(0);
  }

  async function expectBadRequest(response: Response) {
    const responseData = (await response.json()) as any;
    expect(response.status).toBe(400);
    expect(responseData.errors).toBeDefined();

    // Verify no file was created
    const files = await testDb.select().from(filesTable);
    expect(files).toHaveLength(0);
  }

  // Tests
  test("successful file upload", async () => {
    const fileContent = createFileContent();
    const metadata = createTestMetadata();
    const requestBody = createUploadRequestBody(fileContent, metadata);

    const response = await makeAuthenticatedRequest(requestBody);
    await expectSuccessfulUpload(response);
  });

  test("missing request body validation", async () => {
    const response = await makeUnauthenticatedRequest({});
    const responseData = (await response.json()) as any;
    expect(response.status).toBe(400);
  });

  test("authentication failure - missing username header", async () => {
    const fileContent = createFileContent("test");
    const metadata = createTestMetadata();
    const requestBody = createUploadRequestBody(fileContent, metadata, "nonce");

    const response = await makeUnauthenticatedRequest(requestBody, {
      "X-Username": "",
    });

    await expectUnauthorized(response);
  });

  test("authentication failure - user not found", async () => {
    const fileContent = createFileContent("test");
    const metadata = createTestMetadata();
    const requestBody = createUploadRequestBody(fileContent, metadata, "nonce");

    const response = await makeUnauthenticatedRequest(requestBody, {
      "X-Username": "nonexistentuser",
    });

    await expectUnauthorized(response);
  });

  test("authentication failure - invalid request signature", async () => {
    const fileContent = createFileContent("test");
    const metadata = createTestMetadata();
    const requestBody = createUploadRequestBody(fileContent, metadata, "nonce");

    const response = await makeUnauthenticatedRequest(requestBody, {
      "X-Signature": "invalid||signature",
    });

    await expectUnauthorized(response);
  });

  test("file signature verification failure", async () => {
    const fileContent = createFileContent("test");
    const metadata = createTestMetadata();
    const requestBody = createUploadRequestBody(
      fileContent,
      metadata,
      "nonce",
      true
    );

    const response = await makeAuthenticatedRequest(requestBody);
    await expectUnauthorized(response);
  });

  test("replay attack protection - expired timestamp", async () => {
    const fileContent = createFileContent("test");
    const metadata = createTestMetadata();
    const requestBody = createUploadRequestBody(fileContent, metadata, "nonce");

    // Create request with old timestamp (2 minutes ago)
    const oldTimestamp = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    const response = await makeRequestWithCustomTimestamp(
      requestBody,
      oldTimestamp
    );

    await expectUnauthorized(response);
  });

  test("invalid base64 encoding", async () => {
    const requestBody = createUploadRequestBody(
      "invalid-base64!@#",
      createTestMetadata(),
      "valid-base64=="
    );
    // override with invalid base64
    requestBody.metadata_payload = "invalid-base64!@#";

    const response = await makeAuthenticatedRequest(requestBody);
    expect(response.status).toBe(401);
  });

  test("large file upload", async () => {
    // create a large file content (1MB of data)
    const largeContent = Buffer.alloc(1024 * 1024, "a");
    const fileContent = largeContent.toString("base64");

    const metadata = createTestMetadata({
      file_size_bytes: largeContent.length,
      original_filename: "large-file.pdf",
    });

    const requestBody = createUploadRequestBody(
      fileContent,
      metadata,
      "largenonce"
    );
    const response = await makeAuthenticatedRequest(requestBody);
    await expectSuccessfulUpload(response);
  });

  test("metadata with special characters", async () => {
    const fileContent = createFileContent("test content");

    const metadata = createTestMetadata({
      original_filename: "файл с русскими символами.pdf",
      description: "File with émojis 🚀 and spëcial chârs",
      hash_of_encrypted_content: "special-chars-hash",
    });

    const requestBody = createUploadRequestBody(
      fileContent,
      metadata,
      "specialnonce"
    );
    const response = await makeAuthenticatedRequest(requestBody);
    await expectSuccessfulUpload(response);
  });

  test("empty file upload", async () => {
    const fileContent = createFileContent("");
    const metadata = createTestMetadata({
      file_size_bytes: 0,
      original_filename: "empty.txt",
    });

    const requestBody = createUploadRequestBody(
      fileContent,
      metadata,
      "emptynonce"
    );
    const response = await makeAuthenticatedRequest(requestBody);
    await expectBadRequest(response);
  });
});
