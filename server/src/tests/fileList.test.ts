import { expect, test, describe } from "bun:test";
import { getTestHarness, TestData, TestScenarios } from "./setup";

describe("File List API", () => {
  const harness = getTestHarness();

  test("empty file list", async () => {
    await harness.createUser("testuser");

    const response = await harness.listFiles("testuser");
    harness.expectSuccessfulResponse(response);

    const responseData = (await response.json()) as any;
    expect(responseData.fileData).toEqual([]);
    expect(responseData.hasNextPage).toBe(false);
  });

  test("list single file", async () => {
    await harness.createUser("testuser");

    const metadata = {
      name: "single-file.pdf",
      size_bytes: 2048,
    };

    const fileContent = "single file content";
    const uploadResult = await harness.uploadFile(
      "testuser",
      fileContent,
      metadata
    );

    const response = await harness.listFiles("testuser");
    harness.expectSuccessfulResponse(response);

    const responseData = (await response.json()) as any;
    expect(responseData.fileData).toHaveLength(1);
    expect(responseData.hasNextPage).toBe(false);

    const file = responseData.fileData[0];
    expect(file.file_id).toBeDefined();
    expect(file.is_owner).toBe(true);
    expect(file.shared_access).toBeUndefined();

    const decryptedMetadata = harness.decryptMetadata(
      file.metadata,
      uploadResult.test_data.client_data
    );
    expect(decryptedMetadata.name).toBe("single-file.pdf");
    expect(decryptedMetadata.size_bytes).toBe(2048);
  });

  test("list multiple files with different metadata", async () => {
    await harness.createUser("testuser");

    const uploads = await TestScenarios.createUserWithMultipleFiles(
      harness,
      "testuser",
      3
    );

    const response = await harness.listFiles("testuser");
    harness.expectSuccessfulResponse(response);

    const responseData = (await response.json()) as any;
    expect(responseData.fileData).toHaveLength(3);
    expect(responseData.hasNextPage).toBe(false);

    responseData.fileData.forEach((file: any) => {
      expect(file.file_id).toBeDefined();
      expect(file.is_owner).toBe(true);
      expect(file.shared_access).toBeUndefined();
      expect(file.metadata).toBeDefined();
      expect(file.pre_quantum_signature).toBeDefined();
      expect(file.post_quantum_signature).toBeDefined();
    });

    const decryptedMetadata1 = harness.decryptMetadata(
      responseData.fileData[0].metadata,
      uploads[2]!.test_data.client_data
    );
    expect(decryptedMetadata1.name).toBe("file-2.txt");
  });

  test("metadata with special characters and unicode", async () => {
    await harness.createUser("testuser");

    const uploadResult = await harness.uploadFile(
      "testuser",
      TestData.unicodeFile.content,
      TestData.unicodeFile.metadata
    );

    const response = await harness.listFiles("testuser");
    harness.expectSuccessfulResponse(response);

    const responseData = (await response.json()) as any;
    expect(responseData.fileData).toHaveLength(1);

    const decryptedMetadata = harness.decryptMetadata(
      responseData.fileData[0].metadata,
      uploadResult.test_data.client_data
    );
    expect(decryptedMetadata.name).toBe(TestData.unicodeFile.metadata.name);
  });

  test("pagination - two pages", async () => {
    await harness.createUser("testuser");

    const uploads = await TestScenarios.createUserWithMultipleFiles(
      harness,
      "testuser",
      30
    );

    const firstPageResponse = await harness.listFiles("testuser", 1);
    harness.expectSuccessfulResponse(firstPageResponse);

    const firstPageData = (await firstPageResponse.json()) as any;
    expect(firstPageData.fileData).toHaveLength(25);
    expect(firstPageData.hasNextPage).toBe(true);

    const secondPageResponse = await harness.listFiles("testuser", 2);
    harness.expectSuccessfulResponse(secondPageResponse);

    const secondPageData = (await secondPageResponse.json()) as any;
    expect(secondPageData.fileData).toHaveLength(5);
    expect(secondPageData.hasNextPage).toBe(false);
  });

  test("pagination - page beyond available data", async () => {
    await harness.createUser("testuser");

    await TestScenarios.createUserWithMultipleFiles(harness, "testuser", 3);

    const response = await harness.listFiles("testuser", 2);
    harness.expectSuccessfulResponse(response);

    const responseData = (await response.json()) as any;
    expect(responseData.fileData).toEqual([]);
    expect(responseData.hasNextPage).toBe(false);
  });

  test("verify base64 encoding is correct", async () => {
    await harness.createUser("testuser");

    await harness.uploadFile("testuser", "test encoding", {
      name: "encoding-test.txt",
      file_size_bytes: 512,
    });

    const response = await harness.listFiles("testuser");
    harness.expectSuccessfulResponse(response);

    const responseData = (await response.json()) as any;
    const file = responseData.fileData[0];

    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    expect(base64Regex.test(file.metadata)).toBe(true);
    expect(base64Regex.test(file.pre_quantum_signature)).toBe(true);
    expect(base64Regex.test(file.post_quantum_signature)).toBe(true);

    expect(() => Buffer.from(file.metadata, "base64")).not.toThrow();
    expect(() =>
      Buffer.from(file.pre_quantum_signature, "base64")
    ).not.toThrow();
    expect(() =>
      Buffer.from(file.post_quantum_signature, "base64")
    ).not.toThrow();
  });
});
