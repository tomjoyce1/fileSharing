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
import {
  uploadTestFile,
  makeAuthenticatedPOST,
  decryptDownloadedMetadata,
} from "./fileTestUtils";

let mockDbModule: any;

describe("File List API", () => {
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

  async function listFiles(page = 1) {
    const listBody = { page };
    return await makeAuthenticatedPOST(
      "/api/fs/list",
      listBody,
      testUser,
      testUserKeyBundle,
      serverUrl
    );
  }

  function decryptMetadata(base64Metadata: string, client_data: any): any {
    return decryptDownloadedMetadata(base64Metadata, client_data);
  }

  test("empty file list", async () => {
    const response = await listFiles();
    expect(response.status).toBe(200);

    const responseData = (await response.json()) as any;
    expect(responseData.fileData).toEqual([]);
    expect(responseData.hasNextPage).toBe(false);
  });

  test("list single file", async () => {
    const metadata = {
      filename: "single-file.pdf",
      file_size_bytes: 2048,
    };

    const fileContent = "single file content";
    const uploadResult = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      fileContent,
      metadata
    );

    // list files
    const response = await listFiles();
    expect(response.status).toBe(200);

    const responseData = (await response.json()) as any;
    expect(responseData.fileData).toHaveLength(1);
    expect(responseData.hasNextPage).toBe(false);

    const file = responseData.fileData[0];
    expect(file.file_id).toBeDefined();
    expect(file.is_owner).toBe(true);
    expect(file.shared_access).toBeUndefined();

    // decrypt and verify metadata
    const decryptedMetadata = decryptMetadata(
      file.metadata,
      uploadResult.test_data.client_data
    );
    expect(decryptedMetadata.filename).toBe("single-file.pdf");
    expect(decryptedMetadata.file_size_bytes).toBe(2048);
  });

  test("list three files with different metadata", async () => {
    const file1Metadata = {
      filename: "document1.pdf",
      file_size_bytes: 1024,
    };

    const file2Metadata = {
      filename: "image.jpg",
      file_size_bytes: 5120,
    };

    const file3Metadata = {
      filename: "spreadsheet.xlsx",
      file_size_bytes: 3072,
    };

    const file1Content = "document content";
    const file2Content = "image binary data";
    const file3Content = "spreadsheet data";

    const upload1 = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      file1Content,
      file1Metadata
    );
    const upload2 = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      file2Content,
      file2Metadata
    );
    const upload3 = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      file3Content,
      file3Metadata
    );

    // list files
    const response = await listFiles();
    expect(response.status).toBe(200);

    const responseData = (await response.json()) as any;
    expect(responseData.fileData).toHaveLength(3);
    expect(responseData.hasNextPage).toBe(false);

    // verify all files are owned by the user
    responseData.fileData.forEach((file: any) => {
      expect(file.file_id).toBeDefined();
      expect(file.is_owner).toBe(true);
      expect(file.shared_access).toBeUndefined();
      expect(file.metadata).toBeDefined();
      expect(file.pre_quantum_signature).toBeDefined();
      expect(file.post_quantum_signature).toBeDefined();
    });

    // verify files are ordered by upload time (newest first)
    // the last uploaded file (spreadsheet) should be first
    const decryptedMetadata1 = decryptMetadata(
      responseData.fileData[0].metadata,
      upload3.test_data.client_data
    );
    const decryptedMetadata2 = decryptMetadata(
      responseData.fileData[1].metadata,
      upload2.test_data.client_data
    );
    const decryptedMetadata3 = decryptMetadata(
      responseData.fileData[2].metadata,
      upload1.test_data.client_data
    );

    expect(decryptedMetadata1.filename).toBe("spreadsheet.xlsx");
    expect(decryptedMetadata1.file_size_bytes).toBe(3072);

    expect(decryptedMetadata2.filename).toBe("image.jpg");
    expect(decryptedMetadata2.file_size_bytes).toBe(5120);

    expect(decryptedMetadata3.filename).toBe("document1.pdf");
    expect(decryptedMetadata3.file_size_bytes).toBe(1024);
  });

  test("metadata with special characters and unicode", async () => {
    const metadata = {
      filename: "файл с русскими символами.pdf",
      file_size_bytes: 4096,
    };

    const fileContent = "unicode content";
    const uploadResult = await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      fileContent,
      metadata
    );

    const response = await listFiles();
    expect(response.status).toBe(200);

    const responseData = (await response.json()) as any;
    expect(responseData.fileData).toHaveLength(1);

    const decryptedMetadata = decryptMetadata(
      responseData.fileData[0].metadata,
      uploadResult.test_data.client_data
    );
    expect(decryptedMetadata.filename).toBe("файл с русскими символами.pdf");
  });

  test("pagination - two pages", async () => {
    const uploadPromises = [];
    for (let i = 0; i < 30; i++) {
      const metadata = {
        filename: `file-${i.toString()}.txt`,
        file_size_bytes: 1024 + i,
      };
      const content = `content for file ${i}`;
      uploadPromises.push(
        uploadTestFile(
          testUser,
          testUserKeyBundle,
          serverUrl,
          content,
          metadata
        )
      );
    }
    const uploadResults = await Promise.all(uploadPromises);

    // test first page
    const firstPageResponse = await listFiles(1);
    expect(firstPageResponse.status).toBe(200);

    const firstPageData = (await firstPageResponse.json()) as any;
    expect(firstPageData.fileData).toHaveLength(25);
    expect(firstPageData.hasNextPage).toBe(true);

    // test second page
    const secondPageResponse = await listFiles(2);
    expect(secondPageResponse.status).toBe(200);

    const secondPageData = (await secondPageResponse.json()) as any;
    expect(secondPageData.fileData).toHaveLength(5);
    expect(secondPageData.hasNextPage).toBe(false);
  });

  test("pagination - page beyond available data", async () => {
    for (let i = 0; i < 3; i++) {
      const metadata = {
        filename: `file-${i}.txt`,
        file_size_bytes: 1024,
      };
      const content = `content ${i}`;
      await uploadTestFile(
        testUser,
        testUserKeyBundle,
        serverUrl,
        content,
        metadata
      );
    }

    // request page 2 (should be empty)
    const response = await listFiles(2);
    expect(response.status).toBe(200);

    const responseData = (await response.json()) as any;
    expect(responseData.fileData).toEqual([]);
    expect(responseData.hasNextPage).toBe(false);
  });

  test("verify base64 encoding is correct", async () => {
    const metadata = {
      filename: "encoding-test.txt",
      file_size_bytes: 512,
    };

    const fileContent = "test encoding";
    await uploadTestFile(
      testUser,
      testUserKeyBundle,
      serverUrl,
      fileContent,
      metadata
    );

    const response = await listFiles();
    expect(response.status).toBe(200);

    const responseData = (await response.json()) as any;
    const file = responseData.fileData[0];

    // verify all base64 fields are valid base64
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    expect(base64Regex.test(file.metadata)).toBe(true);
    expect(base64Regex.test(file.pre_quantum_signature)).toBe(true);
    expect(base64Regex.test(file.post_quantum_signature)).toBe(true);

    // verify we can decode without errors
    expect(() => Buffer.from(file.metadata, "base64")).not.toThrow();
    expect(() =>
      Buffer.from(file.pre_quantum_signature, "base64")
    ).not.toThrow();
    expect(() =>
      Buffer.from(file.post_quantum_signature, "base64")
    ).not.toThrow();
  });

  test("invalid page number", async () => {
    const listBody = { page: 0 };
    const response = await makeAuthenticatedPOST(
      "/api/fs/list",
      listBody,
      testUser,
      testUserKeyBundle,
      serverUrl
    );

    expect(response.status).toBe(400);
  });
});
