import {
  expect,
  test,
  describe,
  beforeAll,
  beforeEach,
  afterEach,
  mock,
} from "bun:test";
import {
  setupTestDb,
  testDb,
  ensureTestServerRunning,
  getTestServerUrl,
  createTestUser,
  cleanupEncryptedDrive,
} from "./setup";
import { filesTable } from "~/db/schema";
import { sign as nodeSign } from "node:crypto";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import {
  createEncryptedFileContent,
  createUploadRequestBody,
  makeAuthenticatedPOST,
  createLargeFileContent,
  decryptDownloadedContent,
} from "./fileTestUtils";

let mockDbModule: any;

describe("File Upload API", () => {
  let testUser: any;
  let testUserKeyBundle: any;
  let serverUrl: string;

  beforeAll(async () => {
    await setupTestDb();
    await ensureTestServerRunning();
    serverUrl = getTestServerUrl();

    // Set up the database mock after testDb is initialized
    mockDbModule = mock.module("~/db", () => ({
      db: testDb,
    }));

    // Create test user
    const testUserData = await createTestUser("testuser");
    testUser = testUserData.user;
    testUserKeyBundle = testUserData.keyBundle;
  });

  beforeEach(async () => {
    await testDb.delete(filesTable);
  });

  afterEach(() => {
    cleanupEncryptedDrive();
  });

  async function makeAuthenticatedUploadRequest(
    requestBody: any,
    username = testUser.username
  ) {
    return await makeAuthenticatedPOST(
      "/api/fs/upload",
      requestBody,
      testUser,
      testUserKeyBundle,
      serverUrl,
      username
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
      testUserKeyBundle.private.preQuantum.identitySigning.privateKey
    ).toString("base64");

    const requestPostSig = Buffer.from(
      ml_dsa87.sign(
        testUserKeyBundle.private.postQuantum.identitySigning.privateKey,
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

    // verify database record
    const files = await testDb.select().from(filesTable);
    expect(files).toHaveLength(1);

    const file = files[0];
    if (!file) throw new Error("File record not found");
    expect(file.owner_user_id).toBe(testUser.user_id);
    expect(file.storage_path).toContain("encrypted-drive");
    expect(file.storage_path).toContain(".enc");
    expect(file.metadata.length).toBeGreaterThan(0);

    return file;
  }

  async function expectUnauthorized(response: Response) {
    const responseData = (await response.json()) as any;
    expect(response.status).toBe(401);
    expect(responseData.message).toBe("Unauthorized d");

    // verify no database record was created
    const files = await testDb.select().from(filesTable);
    expect(files).toHaveLength(0);
  }

  async function expectBadRequest(response: Response) {
    const responseData = (await response.json()) as any;
    expect(response.status).toBe(400);
    expect(responseData.errors).toBeDefined();

    // verify no file was created
    const files = await testDb.select().from(filesTable);
    expect(files).toHaveLength(0);
  }

  test("successful file upload with encryption", async () => {
    const originalContent = "test file content";
    const encrypted = createEncryptedFileContent(originalContent);
    const requestBody = createUploadRequestBody(
      encrypted.encrypted_file_content,
      encrypted.encrypted_metadata,
      testUser,
      testUserKeyBundle
    );

    const response = await makeAuthenticatedUploadRequest(requestBody);
    await expectSuccessfulUpload(response);

    // verify we can decrypt it back to original content
    const decryptedContent = decryptDownloadedContent(
      encrypted.encrypted_file_content,
      encrypted.client_data
    );
    expect(decryptedContent).toBe(originalContent);
  });

  test("missing request body validation", async () => {
    const response = await makeUnauthenticatedRequest({});
    expect(response.status).toBe(400);
  });

  test("authentication failure - missing username header", async () => {
    const encrypted = createEncryptedFileContent("test");
    const requestBody = createUploadRequestBody(
      encrypted.encrypted_file_content,
      encrypted.encrypted_metadata,
      testUser,
      testUserKeyBundle
    );

    const response = await makeUnauthenticatedRequest(requestBody, {
      "X-Username": "",
    });

    await expectUnauthorized(response);
  });

  test("authentication failure - user not found", async () => {
    const encrypted = createEncryptedFileContent("test");
    const requestBody = createUploadRequestBody(
      encrypted.encrypted_file_content,
      encrypted.encrypted_metadata,
      testUser,
      testUserKeyBundle
    );

    const response = await makeUnauthenticatedRequest(requestBody, {
      "X-Username": "nonexistentuser",
    });

    await expectUnauthorized(response);
  });

  test("authentication failure - invalid request signature", async () => {
    const encrypted = createEncryptedFileContent("test");
    const requestBody = createUploadRequestBody(
      encrypted.encrypted_file_content,
      encrypted.encrypted_metadata,
      testUser,
      testUserKeyBundle
    );

    const response = await makeUnauthenticatedRequest(requestBody, {
      "X-Signature": "invalid||signature",
    });

    await expectUnauthorized(response);
  });

  test("file record signature verification failure", async () => {
    const encrypted = createEncryptedFileContent("test");
    const requestBody = createUploadRequestBody(
      encrypted.encrypted_file_content,
      encrypted.encrypted_metadata,
      testUser,
      testUserKeyBundle,
      true
    );

    const response = await makeAuthenticatedUploadRequest(requestBody);
    await expectUnauthorized(response);
  });

  test("replay attack protection - expired timestamp", async () => {
    const encrypted = createEncryptedFileContent("test");
    const requestBody = createUploadRequestBody(
      encrypted.encrypted_file_content,
      encrypted.encrypted_metadata,
      testUser,
      testUserKeyBundle
    );

    // create request with old timestamp
    const oldTimestamp = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    const response = await makeRequestWithCustomTimestamp(
      requestBody,
      oldTimestamp
    );

    await expectUnauthorized(response);
  });

  test("invalid base64 encoding in file content", async () => {
    const encrypted = createEncryptedFileContent("test");
    const requestBody = createUploadRequestBody(
      encrypted.encrypted_file_content,
      encrypted.encrypted_metadata,
      testUser,
      testUserKeyBundle
    );

    // override with invalid base64
    requestBody.file_content = "invalid-base64!@#";

    const response = await makeAuthenticatedUploadRequest(requestBody);
    expect(response.status).toBe(401);
  });

  test("large file upload", async () => {
    // create a large file content (1MB of data)
    const largeContent = createLargeFileContent(1);

    const requestBody = createUploadRequestBody(
      largeContent.encrypted_file_content,
      largeContent.encrypted_metadata,
      testUser,
      testUserKeyBundle
    );
    const response = await makeAuthenticatedUploadRequest(requestBody);
    await expectSuccessfulUpload(response);
  });

  test("metadata with special characters", async () => {
    const fileContent = "test content";
    const metadata = {
      filename: "файл с русскими символами.pdf",
      file_size_bytes: fileContent.length,
      mime_type: "application/pdf",
    };

    const encrypted = createEncryptedFileContent(fileContent, metadata);
    const requestBody = createUploadRequestBody(
      encrypted.encrypted_file_content,
      encrypted.encrypted_metadata,
      testUser,
      testUserKeyBundle
    );
    const response = await makeAuthenticatedUploadRequest(requestBody);
    await expectSuccessfulUpload(response);
  });

  test("empty file upload should fail", async () => {
    const metadata = {
      file_size_bytes: 0,
      filename: "empty.txt",
    };

    const encrypted = createEncryptedFileContent("", metadata);
    const requestBody = createUploadRequestBody(
      encrypted.encrypted_file_content,
      encrypted.encrypted_metadata,
      testUser,
      testUserKeyBundle
    );
    const response = await makeAuthenticatedUploadRequest(requestBody);
    await expectBadRequest(response);
  });
});
