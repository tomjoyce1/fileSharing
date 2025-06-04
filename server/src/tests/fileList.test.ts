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
    expect(file.owner_username).toBe("testuser");

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
      expect(file.owner_username).toBe("testuser");
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
    expect(responseData.fileData[0].owner_username).toBe("testuser");

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
    firstPageData.fileData.forEach((file: any) => {
      expect(file.owner_username).toBe("testuser");
    });

    const secondPageResponse = await harness.listFiles("testuser", 2);
    harness.expectSuccessfulResponse(secondPageResponse);

    const secondPageData = (await secondPageResponse.json()) as any;
    expect(secondPageData.fileData).toHaveLength(5);
    expect(secondPageData.hasNextPage).toBe(false);
    secondPageData.fileData.forEach((file: any) => {
      expect(file.owner_username).toBe("testuser");
    });
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

  test("list files after sharing - owner and recipient perspectives", async () => {
    // Create two users with a shared file using test scenario
    const shareResult = await TestScenarios.createTwoUsersWithSharedFile(
      harness
    );
    const sharedFileId = shareResult.uploadResult.file_id;

    // Owner (userA) lists files - should see file as owned
    const ownerResponse = await harness.listFiles("userA");
    harness.expectSuccessfulResponse(ownerResponse);

    const ownerData = (await ownerResponse.json()) as any;
    expect(ownerData.fileData).toHaveLength(1);
    expect(ownerData.hasNextPage).toBe(false);

    const ownerFile = ownerData.fileData[0];
    expect(ownerFile.file_id).toBe(sharedFileId);
    expect(ownerFile.is_owner).toBe(true);
    expect(ownerFile.owner_username).toBe("userA");
    expect(ownerFile.shared_access).toBeUndefined();

    // Recipient (userB) lists files - should see file as shared
    const recipientResponse = await harness.listFiles("userB");
    harness.expectSuccessfulResponse(recipientResponse);

    const recipientData = (await recipientResponse.json()) as any;
    expect(recipientData.fileData).toHaveLength(1);
    expect(recipientData.hasNextPage).toBe(false);

    const recipientFile = recipientData.fileData[0];
    expect(recipientFile.file_id).toBe(sharedFileId);
    expect(recipientFile.is_owner).toBe(false);
    expect(recipientFile.owner_username).toBe("userA");
    expect(recipientFile.shared_access).toBeDefined();
  });

  test("mixed owned and shared files in list", async () => {
    // Create a user with their own files
    await harness.createUser("charlie");

    // Charlie uploads his own file
    const charlieUpload = await harness.uploadFile(
      "charlie",
      "Charlie's file",
      {
        name: "charlie-file.txt",
        size_bytes: 1024,
      }
    );

    // Create a shared file scenario (userA shares with userB)
    const shareResult = await TestScenarios.createTwoUsersWithSharedFile(
      harness
    );

    // Share userA's file with Charlie as well
    const shareWithCharlieResponse = await harness.shareFile(
      "userA",
      "charlie",
      shareResult.uploadResult.file_id,
      shareResult.uploadResult.test_data.client_data.fek,
      shareResult.uploadResult.test_data.client_data.mek,
      shareResult.uploadResult.test_data.client_data.fileNonce,
      shareResult.uploadResult.test_data.client_data.metadataNonce
    );
    harness.expectSuccessfulResponse(shareWithCharlieResponse, 201);

    // Charlie lists files - should see both owned and shared files with correct owner_username
    const charlieResponse = await harness.listFiles("charlie");
    harness.expectSuccessfulResponse(charlieResponse);

    const charlieData = (await charlieResponse.json()) as any;
    expect(charlieData.fileData).toHaveLength(2); // Charlie's own file + shared file from userA

    // Find Charlie's own file and the shared file
    const charlieOwnedFile = charlieData.fileData.find(
      (file: any) => file.is_owner === true
    );
    const sharedFile = charlieData.fileData.find(
      (file: any) => file.is_owner === false
    );

    // Verify Charlie's own file
    expect(charlieOwnedFile).toBeDefined();
    expect(charlieOwnedFile.file_id).toBe(charlieUpload.file_id);
    expect(charlieOwnedFile.is_owner).toBe(true);
    expect(charlieOwnedFile.owner_username).toBe("charlie");
    expect(charlieOwnedFile.shared_access).toBeUndefined();

    // Verify shared file from userA
    expect(sharedFile).toBeDefined();
    expect(sharedFile.file_id).toBe(shareResult.uploadResult.file_id);
    expect(sharedFile.is_owner).toBe(false);
    expect(sharedFile.owner_username).toBe("userA");
    expect(sharedFile.shared_access).toBeDefined();

    // UserA lists files - should see only their own file
    const userAResponse = await harness.listFiles("userA");
    harness.expectSuccessfulResponse(userAResponse);

    const userAData = (await userAResponse.json()) as any;
    expect(userAData.fileData).toHaveLength(1);

    const userAFile = userAData.fileData[0];
    expect(userAFile.is_owner).toBe(true);
    expect(userAFile.owner_username).toBe("userA");
    expect(userAFile.shared_access).toBeUndefined();
  });
});
