import { expect, test, describe } from "bun:test";
import { getTestHarness } from "./setup";

describe("File Upload API", () => {
  const harness = getTestHarness();

  test("successful file upload with encryption", async () => {
    await harness.createUser("testuser");

    const originalContent = "test file content";
    const metadata = {
      name: "test.txt",
      size_bytes: originalContent.length,
    };

    const uploadResult = await harness.uploadFile(
      "testuser",
      originalContent,
      metadata
    );
    expect(uploadResult.file_id).toBeGreaterThan(0);

    // verify we can decrypt it back to original content
    const decryptedContent = harness.decryptFileContent(
      uploadResult.test_data.encrypted_file_content,
      uploadResult.test_data.client_data
    );
    expect(decryptedContent).toBe(originalContent);
  });

  test("large file upload (1MB)", async () => {
    await harness.createUser("testuser");

    const sizeInMB = 1;
    const sizeInBytes = sizeInMB * 1024 * 1024;
    const largeContent = "a".repeat(sizeInBytes);
    const metadata = {
      name: "large-test-1mb.bin",
      size_bytes: sizeInBytes,
    };

    const uploadResult = await harness.uploadFile(
      "testuser",
      largeContent,
      metadata
    );
    expect(uploadResult.file_id).toBeGreaterThan(0);

    // verify content integrity
    const decryptedContent = harness.decryptFileContent(
      uploadResult.test_data.encrypted_file_content,
      uploadResult.test_data.client_data
    );
    expect(decryptedContent.length).toBe(sizeInBytes);
    expect(decryptedContent).toBe(largeContent);
  });

  test("metadata with special characters", async () => {
    await harness.createUser("testuser");

    const fileContent = "test content with special metadata";
    const metadata = {
      name: "файл с русскими символами.pdf",
      size_bytes: fileContent.length,
    };

    const uploadResult = await harness.uploadFile(
      "testuser",
      fileContent,
      metadata
    );
    expect(uploadResult.file_id).toBeGreaterThan(0);

    // verify metadata is preserved
    const decryptedContent = harness.decryptFileContent(
      uploadResult.test_data.encrypted_file_content,
      uploadResult.test_data.client_data
    );
    expect(decryptedContent).toBe(fileContent);
  });

  test("multiple file uploads by same user", async () => {
    await harness.createUser("testuser");

    const files = [
      { content: "first file content", filename: "file1.txt" },
      { content: "second file content", filename: "file2.txt" },
      { content: "third file content", filename: "file3.txt" },
    ];

    const uploadResults = [];
    for (const file of files) {
      const metadata = {
        name: file.filename,
        size_bytes: file.content.length,
      };
      const result = await harness.uploadFile(
        "testuser",
        file.content,
        metadata
      );
      uploadResults.push(result);
    }

    // verify all files were uploaded successfully
    expect(uploadResults).toHaveLength(3);
    uploadResults.forEach((result, index) => {
      expect(result.file_id).toBeGreaterThan(0);

      const decryptedContent = harness.decryptFileContent(
        result.test_data.encrypted_file_content,
        result.test_data.client_data
      );
      const expectedContent = files[index];
      expect(expectedContent).toBeDefined();
      expect(decryptedContent).toBe(expectedContent!.content);
    });

    // verify all file IDs are unique
    const fileIds = uploadResults.map((r) => r.file_id);
    const uniqueIds = new Set(fileIds);
    expect(uniqueIds.size).toBe(fileIds.length);
  });
});
