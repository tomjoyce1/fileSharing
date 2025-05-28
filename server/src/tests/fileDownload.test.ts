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
import { writeFileSync } from "node:fs";
import { eq } from "drizzle-orm";
import {
  createTestMetadata,
  createFileContent,
  uploadTestFile,
  downloadFile,
  verifyFileSignatures,
  makeAuthenticatedPOST,
  createLargeFileContent,
} from "./fileTestUtils";

let mockDbModule: any;

describe("File Download API", () => {
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

    // create test user
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

  // Tests
  test("successful file download - happy path", async () => {
    const originalContent = "test file content for download";
    const originalMetadata = createTestMetadata({
      filename: "download-test.txt",
      file_size_bytes: originalContent.length,
    });

    // upload a file first
    const fileContent = createFileContent(originalContent);
    const file_id = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      fileContent,
      originalMetadata
    );

    // download the file
    const response = await downloadFile(
      file_id,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response.status).toBe(200);

    // get the JSON response
    const responseData = (await response.json()) as any;
    expect(responseData.file_content).toBe(fileContent);

    // get the file record to verify metadata and signatures
    const fileRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, file_id))
      .then((rows: any[]) => rows[0]);

    expect(fileRecord).toBeDefined();

    const metadataPayload = fileRecord.metadata_payload.toString("base64");
    const preQuantumSig = fileRecord.pre_quantum_signature.toString("base64");
    const postQuantumSig = fileRecord.post_quantum_signature.toString("base64");

    const signaturesValid = verifyFileSignatures(
      testUser.user_id,
      metadataPayload,
      preQuantumSig,
      postQuantumSig,
      testUserKeyBundle.public
    );

    expect(signaturesValid).toBe(true);

    // decrypt and verify metadata
    const decryptedMetadata = JSON.parse(
      Buffer.from(metadataPayload, "base64").toString()
    );
    expect(decryptedMetadata.filename).toBe("download-test.txt");
    expect(decryptedMetadata.file_size_bytes).toBe(originalContent.length);

    // decrypt and verify file content
    const decryptedFileContent = Buffer.from(
      responseData.file_content,
      "base64"
    ).toString();
    expect(decryptedFileContent).toBe(originalContent);
  });

  test("5MB file download", async () => {
    const fileContent = createLargeFileContent(5);
    const originalMetadata = createTestMetadata({
      filename: "large-download-test-5mb.bin",
      file_size_bytes: 5 * 1024 * 1024,
    });

    // upload the big file
    const file_id = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      fileContent,
      originalMetadata
    );

    // download the file
    const response = await downloadFile(
      file_id,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response.status).toBe(200);

    // get the JSON response
    const responseData = (await response.json()) as any;
    expect(responseData.file_content).toBe(fileContent);

    // verify the content length is correct for base64 encoded 5MB
    const decodedSize = Buffer.from(responseData.file_content, "base64").length;
    expect(decodedSize).toBe(5 * 1024 * 1024);
  });

  test("detect file tampering on disk", async () => {
    const originalContent = "original content";
    const file_id = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      createFileContent(originalContent)
    );

    // get the storage path
    const fileRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, file_id))
      .then((rows: any[]) => rows[0]);
    const storagePath = fileRecord.storage_path;

    // tamper with the file on disk
    const tamperedContent = Buffer.from("tampered content");
    writeFileSync(storagePath, tamperedContent);

    // download should still work but content will be different
    const response = await downloadFile(
      file_id,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response.status).toBe(200);

    const responseData = (await response.json()) as any;
    const decryptedContent = Buffer.from(
      responseData.file_content,
      "base64"
    ).toString();
    expect(decryptedContent).toBe("tampered content");
    expect(decryptedContent).not.toBe(originalContent);

    // the signatures will now be invalid for the tampered content
    const serverMetadata = JSON.parse(
      Buffer.from(
        fileRecord.metadata_payload.toString("base64"),
        "base64"
      ).toString()
    );
    const signaturesValid = verifyFileSignatures(
      testUser.user_id,
      serverMetadata,
      fileRecord.pre_quantum_signature.toString("base64"),
      fileRecord.post_quantum_signature.toString("base64"),
      testUserKeyBundle.public
    );
    expect(signaturesValid).toBe(false);
  });

  test("detect metadata tampering in database", async () => {
    const originalContent = "content for metadata tampering test";
    const file_id = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      createFileContent(originalContent)
    );

    // get the original file record
    const originalRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, file_id))
      .then((rows: any[]) => rows[0]);

    // tamper with metadata in database
    const tamperedMetadata = {
      filename: "tampered-file.txt",
      file_size_bytes: 9999,
      hash_of_encrypted_content: "tampered_hash",
    };

    const tamperedMetadataPayload = Buffer.from(
      JSON.stringify(tamperedMetadata)
    );

    await testDb
      .update(filesTable)
      .set({
        metadata_payload: tamperedMetadataPayload,
      })
      .where(eq(filesTable.file_id, file_id));

    // download should still work
    const response = await downloadFile(
      file_id,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response.status).toBe(200);

    // but signature verification should fail
    const tamperedMetadataPayloadBase64 =
      tamperedMetadataPayload.toString("base64");
    const signaturesValid = verifyFileSignatures(
      testUser.user_id,
      tamperedMetadataPayloadBase64,
      originalRecord.pre_quantum_signature.toString("base64"),
      originalRecord.post_quantum_signature.toString("base64"),
      testUserKeyBundle.public
    );

    expect(signaturesValid).toBe(false);

    // the downloaded content should still be the original file content
    const responseData = (await response.json()) as any;
    expect(responseData.file_content).toBe(createFileContent(originalContent));

    // TODO: once we have  a way to get file metadata, we should verify metadata actually changed
  });

  test("file not found", async () => {
    const response = await downloadFile(
      99999,
      testUser,
      testUserKeyBundle,
      serverUrl
    ); // non-existent file ID
    expect(response.status).toBe(404);

    const responseData = (await response.json()) as any;
    expect(responseData.message).toBe("File not found");
  });

  test("unauthorized download attempt", async () => {
    // create another user
    const otherUserData = await createTestUser("otheruser");

    // upload a file as the first user
    const file_id = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl
    );

    // try to download as second user
    const downloadBody = { file_id };
    const response = await makeAuthenticatedPOST(
      "/api/fs/download",
      downloadBody,
      otherUserData.user,
      otherUserData.keyBundle,
      serverUrl
    );

    expect(response.status).toBe(404);
    const responseData = (await response.json()) as any;
    expect(responseData.message).toBe("File not found");
  });

  test("file deleted from disk after upload", async () => {
    const file_id = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl
    );

    // get the storage path and delete the file
    const fileRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, file_id))
      .then((rows: any[]) => rows[0]);

    // delete the file from disk (simulate disk failure/cleanup)
    const fs = require("fs");
    fs.unlinkSync(fileRecord.storage_path);

    // download should fail with 500 error
    const response = await downloadFile(
      file_id,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response.status).toBe(500);

    const responseData = (await response.json()) as any;
    expect(responseData.message).toBe("Internal Server Error");
  });
});
