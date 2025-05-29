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
  createLargeFileContent,
  uploadTestFile,
  downloadFile,
  makeAuthenticatedPOST,
  decryptDownloadedContent,
  verifyDownloadedFileSignatures,
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
  test("successful file download and content verification", async () => {
    const originalContent = "test file content for download";
    const originalMetadata = {
      filename: "download-test.txt",
      file_size_bytes: originalContent.length,
    };

    // Upload the file (uploadTestFile will handle encryption)
    const uploadResult = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      originalContent,
      originalMetadata
    );

    // Download the file
    const response = await downloadFile(
      uploadResult.file_id,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response.status).toBe(200);

    // Verify the downloaded content matches uploaded content
    const responseData = (await response.json()) as any;
    expect(responseData.file_content).toBe(
      uploadResult.test_data.encrypted_file_content
    );
    expect(responseData.pre_quantum_signature).toBeDefined();
    expect(responseData.post_quantum_signature).toBeDefined();

    const signaturesValid = verifyDownloadedFileSignatures(
      responseData.file_content,
      responseData.pre_quantum_signature,
      responseData.post_quantum_signature,
      testUser,
      testUserKeyBundle,
      uploadResult.test_data.encrypted_metadata
    );
    expect(signaturesValid).toBe(true);

    // Decrypt and verify the actual file content
    const decryptedFileContent = decryptDownloadedContent(
      responseData.file_content,
      uploadResult.test_data.client_data
    );
    expect(decryptedFileContent).toBe(originalContent);
  });
  test("large file download (5MB)", async () => {
    const sizeInMB = 5;
    const sizeInBytes = sizeInMB * 1024 * 1024;
    const largeContent = "a".repeat(sizeInBytes);

    // upload the large file
    const uploadResult = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      largeContent,
      {
        filename: "large-download-test-5mb.bin",
        file_size_bytes: sizeInBytes,
      }
    );

    // download the file
    const response = await downloadFile(
      uploadResult.file_id,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response.status).toBe(200);

    // verify the downloaded content matches
    const responseData = (await response.json()) as any;
    expect(responseData.file_content).toBe(
      uploadResult.test_data.encrypted_file_content
    );
    expect(responseData.pre_quantum_signature).toBeDefined();
    expect(responseData.post_quantum_signature).toBeDefined();

    const signaturesValid = verifyDownloadedFileSignatures(
      responseData.file_content,
      responseData.pre_quantum_signature,
      responseData.post_quantum_signature,
      testUser,
      testUserKeyBundle,
      uploadResult.test_data.encrypted_metadata
    );
    expect(signaturesValid).toBe(true);

    // verify the content length is correct for 5MB
    const decryptedContent = decryptDownloadedContent(
      responseData.file_content,
      uploadResult.test_data.client_data
    );
    expect(decryptedContent.length).toBe(5 * 1024 * 1024);
  });

  test("download detects file tampering on disk", async () => {
    const originalContent = "original content";

    const uploadResult = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      originalContent
    );

    // get the storage path
    const fileRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, uploadResult.file_id))
      .then((rows: any[]) => rows[0]);
    const storagePath = fileRecord.storage_path;

    // tamper with the file on disk
    const tamperedContent = Buffer.from("tampered content");
    writeFileSync(storagePath, tamperedContent);

    // download should still work but content will be different
    const response = await downloadFile(
      uploadResult.file_id,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response.status).toBe(200);

    const responseData = (await response.json()) as any;
    const downloadedContent = Buffer.from(
      responseData.file_content,
      "base64"
    ).toString();
    expect(downloadedContent).toBe("tampered content");
    expect(downloadedContent).not.toBe(originalContent);
  });

  test("download detects file signature mismatch when file is tampered", async () => {
    const originalContent = "original content for signature test";

    const uploadResult = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      originalContent
    );

    // tamper with the file on disk
    const fileRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, uploadResult.file_id))
      .then((rows: any[]) => rows[0]);
    const storagePath = fileRecord.storage_path;
    const tamperedContent = Buffer.from("tampered content");
    writeFileSync(storagePath, tamperedContent);

    // download the file
    const response = await downloadFile(
      uploadResult.file_id,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response.status).toBe(200);

    const responseData = (await response.json()) as any;

    // the file content will be the tampered content now
    const tamperedBase64 = tamperedContent.toString("base64");
    expect(responseData.file_content).toBe(tamperedBase64);

    // but signatures should not match because the file was tampered with
    const signaturesValid = verifyDownloadedFileSignatures(
      responseData.file_content,
      responseData.pre_quantum_signature,
      responseData.post_quantum_signature,
      testUser,
      testUserKeyBundle,
      uploadResult.test_data.encrypted_metadata
    );
    expect(signaturesValid).toBe(false);
  });

  test("file not found", async () => {
    const response = await downloadFile(
      99999, // non-existent file ID
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response.status).toBe(404);

    const responseData = (await response.json()) as any;
    expect(responseData.message).toBe("File not found");
  });

  test("unauthorized download attempt", async () => {
    // create another user
    const otherUserData = await createTestUser("otheruser");

    // upload a file as the first user
    const uploadResult = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl
    );

    // try to download as second user
    const downloadBody = { file_id: uploadResult.file_id };
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
    const uploadResult = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl
    );

    // get the storage path and delete the file
    const fileRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, uploadResult.file_id))
      .then((rows: any[]) => rows[0]);

    // delete the file from disk (simulate disk failure/cleanup)
    const fs = require("fs");
    fs.unlinkSync(fileRecord.storage_path);

    // download should fail with 500 error
    const response = await downloadFile(
      uploadResult.file_id,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    expect(response.status).toBe(500);

    const responseData = (await response.json()) as any;
    expect(responseData.message).toBe("Internal Server Error");
  });
  test("multiple files download - content isolation", async () => {
    // Upload multiple files with different content
    const content1 = "first file content";
    const content2 = "second file different content";

    const uploadResult1 = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      content1,
      { filename: "file1.txt" }
    );

    const uploadResult2 = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      content2,
      { filename: "file2.txt" }
    );

    // Download both files
    const response1 = await downloadFile(
      uploadResult1.file_id,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
    const response2 = await downloadFile(
      uploadResult2.file_id,
      testUser,
      testUserKeyBundle,
      serverUrl
    );

    expect(response1.status).toBe(200);
    expect(response2.status).toBe(200);

    const data1 = (await response1.json()) as any;
    const data2 = (await response2.json()) as any;

    // Verify each file has its correct encrypted content
    expect(data1.file_content).toBe(
      uploadResult1.test_data.encrypted_file_content
    );
    expect(data2.file_content).toBe(
      uploadResult2.test_data.encrypted_file_content
    );
    expect(data1.file_content).not.toBe(data2.file_content);

    const signatures1Valid = verifyDownloadedFileSignatures(
      data1.file_content,
      data1.pre_quantum_signature,
      data1.post_quantum_signature,
      testUser,
      testUserKeyBundle,
      uploadResult1.test_data.encrypted_metadata
    );
    const signatures2Valid = verifyDownloadedFileSignatures(
      data2.file_content,
      data2.pre_quantum_signature,
      data2.post_quantum_signature,
      testUser,
      testUserKeyBundle,
      uploadResult2.test_data.encrypted_metadata
    );
    expect(signatures1Valid).toBe(true);
    expect(signatures2Valid).toBe(true);

    // Verify decryption works correctly for each
    const decrypted1 = decryptDownloadedContent(
      data1.file_content,
      uploadResult1.test_data.client_data
    );
    const decrypted2 = decryptDownloadedContent(
      data2.file_content,
      uploadResult2.test_data.client_data
    );

    expect(decrypted1).toBe(content1);
    expect(decrypted2).toBe(content2);
    expect(decrypted1).not.toBe(decrypted2);
  });
});
