import { expect, test, describe } from "bun:test";
import { getTestHarness, testDb } from "./setup";
import { filesTable } from "~/db/schema";
import { writeFileSync } from "node:fs";
import { eq } from "drizzle-orm";

describe("File Download API", () => {
  const harness = getTestHarness();
  test("successful file download and content verification", async () => {
    await harness.createUser("testuser");

    const originalContent = "test file content for download";
    const originalMetadata = {
      filename: "download-test.txt",
      file_size_bytes: originalContent.length,
    };

    const uploadResult = await harness.uploadFile(
      "testuser",
      originalContent,
      originalMetadata
    );
    const response = await harness.downloadFile(
      "testuser",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(response);

    const responseData = (await response.json()) as any;
    expect(responseData.file_content).toBe(
      uploadResult.test_data.encrypted_file_content
    );
    expect(responseData.pre_quantum_signature).toBeDefined();
    expect(responseData.post_quantum_signature).toBeDefined();

    const user = harness.getUser("testuser");
    const signaturesValid = harness.verifyFileSignatures(
      user.dbUser.user_id,
      responseData.file_content,
      uploadResult.test_data.encrypted_metadata,
      responseData.pre_quantum_signature,
      responseData.post_quantum_signature,
      user.keyBundle.public
    );
    expect(signaturesValid).toBe(true);

    const decryptedFileContent = harness.decryptFileContent(
      responseData.file_content,
      uploadResult.test_data.client_data
    );
    expect(decryptedFileContent).toBe(originalContent);
  });
  test("large file download (5MB)", async () => {
    await harness.createUser("testuser");

    const sizeInMB = 5;
    const sizeInBytes = sizeInMB * 1024 * 1024;
    const largeContent = "a".repeat(sizeInBytes);
    const largeMetadata = {
      filename: "large-download-test-5mb.bin",
      file_size_bytes: sizeInBytes,
    };

    const uploadResult = await harness.uploadFile(
      "testuser",
      largeContent,
      largeMetadata
    );
    const response = await harness.downloadFile(
      "testuser",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(response);

    const responseData = (await response.json()) as any;
    expect(responseData.file_content).toBe(
      uploadResult.test_data.encrypted_file_content
    );
    expect(responseData.pre_quantum_signature).toBeDefined();
    expect(responseData.post_quantum_signature).toBeDefined();

    const user = harness.getUser("testuser");
    const signaturesValid = harness.verifyFileSignatures(
      user.dbUser.user_id,
      responseData.file_content,
      uploadResult.test_data.encrypted_metadata,
      responseData.pre_quantum_signature,
      responseData.post_quantum_signature,
      user.keyBundle.public
    );
    expect(signaturesValid).toBe(true);

    const decryptedContent = harness.decryptFileContent(
      responseData.file_content,
      uploadResult.test_data.client_data
    );
    expect(decryptedContent.length).toBe(5 * 1024 * 1024);
  });

  test("download detects file tampering on disk", async () => {
    await harness.createUser("testuser");

    const originalContent = "original content";
    const uploadResult = await harness.uploadFile("testuser", originalContent);

    const fileRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, uploadResult.file_id))
      .then((rows: any[]) => rows[0]);
    if (!fileRecord) throw new Error("File record missing");

    const tamperedContentOnDisk = Buffer.from("tampered content on disk");
    writeFileSync(fileRecord.storage_path, tamperedContentOnDisk);

    const response = await harness.downloadFile(
      "testuser",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(response);

    const responseData = (await response.json()) as any;
    const downloadedFileContentRaw = Buffer.from(
      responseData.file_content,
      "base64"
    );
    expect(downloadedFileContentRaw.equals(tamperedContentOnDisk)).toBe(true);

    const user = harness.getUser("testuser");
    const signaturesValid = harness.verifyFileSignatures(
      user.dbUser.user_id,
      responseData.file_content,
      uploadResult.test_data.encrypted_metadata,
      responseData.pre_quantum_signature,
      responseData.post_quantum_signature,
      user.keyBundle.public
    );
    expect(signaturesValid).toBe(false);
  });

  test("file not found", async () => {
    await harness.createUser("testuser");

    const response = await harness.downloadFile("testuser", 99999);
    expect(response.status).toBe(404);

    const responseData = (await response.json()) as any;
    expect(responseData.message).toBe("File not found");
  });

  test("unauthorized download attempt", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");

    const uploadResult = await harness.uploadFile("userA");
    const response = await harness.downloadFile("userB", uploadResult.file_id);
    expect(response.status).toBe(404);

    const responseData = (await response.json()) as any;
    expect(responseData.message).toBe("File not found");
  });

  test("file deleted from disk after upload", async () => {
    await harness.createUser("testuser");

    const uploadResult = await harness.uploadFile("testuser");

    const fileRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, uploadResult.file_id))
      .then((rows: any[]) => rows[0]);

    const fs = require("fs");
    fs.unlinkSync(fileRecord.storage_path);

    const response = await harness.downloadFile(
      "testuser",
      uploadResult.file_id
    );
    expect(response.status).toBe(500);

    const responseData = (await response.json()) as any;
    expect(responseData.message).toBe("Internal Server Error");
  });
  test("multiple files download - content isolation", async () => {
    await harness.createUser("testuser");

    const content1 = "first file content";
    const content2 = "second file different content";

    const uploadResult1 = await harness.uploadFile("testuser", content1, {
      filename: "file1.txt",
    });
    const uploadResult2 = await harness.uploadFile("testuser", content2, {
      filename: "file2.txt",
    });

    const response1 = await harness.downloadFile(
      "testuser",
      uploadResult1.file_id
    );
    const response2 = await harness.downloadFile(
      "testuser",
      uploadResult2.file_id
    );

    harness.expectSuccessfulResponse(response1);
    harness.expectSuccessfulResponse(response2);

    const data1 = (await response1.json()) as any;
    const data2 = (await response2.json()) as any;

    expect(data1.file_content).toBe(
      uploadResult1.test_data.encrypted_file_content
    );
    expect(data2.file_content).toBe(
      uploadResult2.test_data.encrypted_file_content
    );
    expect(data1.file_content).not.toBe(data2.file_content);

    const user = harness.getUser("testuser");
    const signatures1Valid = harness.verifyFileSignatures(
      user.dbUser.user_id,
      data1.file_content,
      uploadResult1.test_data.encrypted_metadata,
      data1.pre_quantum_signature,
      data1.post_quantum_signature,
      user.keyBundle.public
    );
    const signatures2Valid = harness.verifyFileSignatures(
      user.dbUser.user_id,
      data2.file_content,
      uploadResult2.test_data.encrypted_metadata,
      data2.pre_quantum_signature,
      data2.post_quantum_signature,
      user.keyBundle.public
    );
    expect(signatures1Valid).toBe(true);
    expect(signatures2Valid).toBe(true);

    const decrypted1 = harness.decryptFileContent(
      data1.file_content,
      uploadResult1.test_data.client_data
    );
    const decrypted2 = harness.decryptFileContent(
      data2.file_content,
      uploadResult2.test_data.client_data
    );

    expect(decrypted1).toBe(content1);
    expect(decrypted2).toBe(content2);
    expect(decrypted1).not.toBe(decrypted2);
  });
});
