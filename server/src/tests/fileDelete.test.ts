import { expect, test, describe } from "bun:test";
import { getTestHarness, TestData, testDb } from "./setup";
import { filesTable, sharedAccessTable } from "~/db/schema";
import { eq } from "drizzle-orm";
import { existsSync } from "node:fs";

describe("File Delete API", () => {
  const harness = getTestHarness();

  test("successful file deletion - happy path", async () => {
    await harness.createUser("testuser");

    // upload a file
    const uploadResult = await harness.uploadFile(
      "testuser",
      TestData.simpleFile.content,
      TestData.simpleFile.metadata
    );

    // verify file exists and can be downloaded
    const downloadResponseBefore = await harness.downloadFile(
      "testuser",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(downloadResponseBefore);

    // delete the file
    const deleteResponse = await harness.deleteFile(
      "testuser",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(deleteResponse, 200);
    await harness.expectResponseMessage(
      deleteResponse,
      "File deleted successfully"
    );

    // verify file can no longer be downloaded
    const downloadResponseAfter = await harness.downloadFile(
      "testuser",
      uploadResult.file_id
    );
    harness.expectNotFound(downloadResponseAfter);
    await harness.expectResponseMessage(
      downloadResponseAfter,
      "File not found"
    );

    // verify file doesn't appear in file list
    const listResponse = await harness.listFiles("testuser");
    harness.expectSuccessfulResponse(listResponse);
    const listData = (await listResponse.json()) as any;
    expect(listData.fileData).toHaveLength(0);
  });

  test("delete shared file removes all shares and prevents access", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");
    await harness.createUser("userC");

    // upload a file as userA
    const uploadResult = await harness.uploadFile("userA");

    // share with both userB and userC
    const shareResponseB = await harness.shareFile(
      "userA",
      "userB",
      uploadResult.file_id,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek,
      uploadResult.test_data.client_data.fileNonce,
      uploadResult.test_data.client_data.metadataNonce
    );
    harness.expectSuccessfulResponse(shareResponseB, 201);

    const shareResponseC = await harness.shareFile(
      "userA",
      "userC",
      uploadResult.file_id,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek,
      uploadResult.test_data.client_data.fileNonce,
      uploadResult.test_data.client_data.metadataNonce
    );
    harness.expectSuccessfulResponse(shareResponseC, 201);

    // verify both users can see the shared file
    const listResponseB = await harness.listFiles("userB");
    harness.expectSuccessfulResponse(listResponseB);
    const listDataB = (await listResponseB.json()) as any;
    expect(listDataB.fileData).toHaveLength(1);

    const listResponseC = await harness.listFiles("userC");
    harness.expectSuccessfulResponse(listResponseC);
    const listDataC = (await listResponseC.json()) as any;
    expect(listDataC.fileData).toHaveLength(1);

    // verify shared access records exist in database
    const sharedRecordsBefore = await testDb
      .select()
      .from(sharedAccessTable)
      .where(eq(sharedAccessTable.file_id, uploadResult.file_id));
    expect(sharedRecordsBefore).toHaveLength(2);

    // delete the file as userA
    const deleteResponse = await harness.deleteFile(
      "userA",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(deleteResponse, 200);

    // verify shared access records are gone
    const sharedRecordsAfter = await testDb
      .select()
      .from(sharedAccessTable)
      .where(eq(sharedAccessTable.file_id, uploadResult.file_id));
    expect(sharedRecordsAfter).toHaveLength(0);

    // verify userB can no longer see or download the file
    const listResponseBAfter = await harness.listFiles("userB");
    harness.expectSuccessfulResponse(listResponseBAfter);
    const listDataBAfter = (await listResponseBAfter.json()) as any;
    expect(listDataBAfter.fileData).toHaveLength(0);

    const downloadResponseB = await harness.downloadFile(
      "userB",
      uploadResult.file_id
    );
    harness.expectNotFound(downloadResponseB);

    // verify userC can no longer see or download the file
    const listResponseCAfter = await harness.listFiles("userC");
    harness.expectSuccessfulResponse(listResponseCAfter);
    const listDataCAfter = (await listResponseCAfter.json()) as any;
    expect(listDataCAfter.fileData).toHaveLength(0);

    const downloadResponseC = await harness.downloadFile(
      "userC",
      uploadResult.file_id
    );
    harness.expectNotFound(downloadResponseC);
  });

  test("cannot delete file you don't own", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");

    const uploadResult = await harness.uploadFile("userA");

    // userB tries to delete userA's file
    const deleteResponse = await harness.deleteFile(
      "userB",
      uploadResult.file_id
    );
    harness.expectForbidden(deleteResponse);
    await harness.expectResponseMessage(deleteResponse, "Unauthorized");

    // verify file still exists and can be downloaded by owner
    const downloadResponse = await harness.downloadFile(
      "userA",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(downloadResponse);
  });

  test("cannot delete file that doesn't exist", async () => {
    await harness.createUser("testuser");

    const nonExistentFileId = 99999;
    const deleteResponse = await harness.deleteFile(
      "testuser",
      nonExistentFileId
    );
    harness.expectBadRequest(deleteResponse);
    await harness.expectResponseMessage(deleteResponse, "Unknown file");
  });

  test("cannot delete file twice", async () => {
    await harness.createUser("testuser");

    const uploadResult = await harness.uploadFile("testuser");

    // first deletion should succeed
    const firstDeleteResponse = await harness.deleteFile(
      "testuser",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(firstDeleteResponse, 200);
    await harness.expectResponseMessage(
      firstDeleteResponse,
      "File deleted successfully"
    );

    // second deletion should fail
    const secondDeleteResponse = await harness.deleteFile(
      "testuser",
      uploadResult.file_id
    );
    harness.expectBadRequest(secondDeleteResponse);
    await harness.expectResponseMessage(secondDeleteResponse, "Unknown file");
  });

  test("physical file is deleted from disk", async () => {
    await harness.createUser("testuser");

    const uploadResult = await harness.uploadFile("testuser");

    // get the storage path from database
    const fileRecord = await testDb
      .select({ storage_path: filesTable.storage_path })
      .from(filesTable)
      .where(eq(filesTable.file_id, uploadResult.file_id))
      .then((rows: any[]) => rows[0]);

    expect(fileRecord).toBeDefined();
    const storagePath = fileRecord.storage_path;

    // verify file exists on disk
    expect(existsSync(storagePath)).toBe(true);

    // delete the file
    const deleteResponse = await harness.deleteFile(
      "testuser",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(deleteResponse, 200);

    // verify file is deleted from disk
    expect(existsSync(storagePath)).toBe(false);
  });

  test("file record is removed from database", async () => {
    await harness.createUser("testuser");

    const uploadResult = await harness.uploadFile("testuser");

    // verify file record exists in database
    const fileRecordBefore = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, uploadResult.file_id));
    expect(fileRecordBefore).toHaveLength(1);

    // delete the file
    const deleteResponse = await harness.deleteFile(
      "testuser",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(deleteResponse, 200);

    // verify file record is removed from database
    const fileRecordAfter = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, uploadResult.file_id));
    expect(fileRecordAfter).toHaveLength(0);
  });

  test("malformed request body - missing file_id", async () => {
    await harness.createUser("testuser");
    const user = harness.getUser("testuser");

    const response = await harness.fileHelper.makeAuthenticatedRequest(
      "/api/fs/delete",
      {}, // missing file_id
      user
    );
    harness.expectBadRequest(response);
  });

  test("malformed request body - invalid file_id", async () => {
    await harness.createUser("testuser");
    const user = harness.getUser("testuser");

    const response = await harness.fileHelper.makeAuthenticatedRequest(
      "/api/fs/delete",
      { file_id: -1 }, // negative file_id
      user
    );
    harness.expectBadRequest(response);
  });

  test("malformed request body - non-integer file_id", async () => {
    await harness.createUser("testuser");
    const user = harness.getUser("testuser");

    const response = await harness.fileHelper.makeAuthenticatedRequest(
      "/api/fs/delete",
      { file_id: "not_a_number" }, // string file_id
      user
    );
    harness.expectBadRequest(response);
  });

  test("unauthorized request without authentication", async () => {
    // attempt to delete without authentication
    const response = await fetch(`${harness.serverUrl}/api/fs/delete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file_id: 123 }),
    });
    harness.expectUnauthorized(response);
  });

  test("delete after file sharing and revocation", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");

    const uploadResult = await harness.uploadFile("userA");

    // share the file
    const shareResponse = await harness.shareFile(
      "userA",
      "userB",
      uploadResult.file_id,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek,
      uploadResult.test_data.client_data.fileNonce,
      uploadResult.test_data.client_data.metadataNonce
    );
    harness.expectSuccessfulResponse(shareResponse, 201);

    // revoke the share
    const revokeResponse = await harness.revokeFile(
      "userA",
      "userB",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(revokeResponse, 200);

    // now delete the file
    const deleteResponse = await harness.deleteFile(
      "userA",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(deleteResponse, 200);

    // verify file is completely gone
    const downloadResponse = await harness.downloadFile(
      "userA",
      uploadResult.file_id
    );
    harness.expectNotFound(downloadResponse);

    const listResponse = await harness.listFiles("userA");
    harness.expectSuccessfulResponse(listResponse);
    const listData = (await listResponse.json()) as any;
    expect(listData.fileData).toHaveLength(0);
  });

  test("multiple file deletion maintains data isolation", async () => {
    await harness.createUser("testuser");

    // upload multiple files
    const upload1 = await harness.uploadFile("testuser", "file 1 content", {
      name: "file1.txt",
      size_bytes: 13,
    });
    const upload2 = await harness.uploadFile("testuser", "file 2 content", {
      name: "file2.txt",
      size_bytes: 13,
    });

    // verify both files exist
    const listResponseBefore = await harness.listFiles("testuser");
    harness.expectSuccessfulResponse(listResponseBefore);
    const listDataBefore = (await listResponseBefore.json()) as any;
    expect(listDataBefore.fileData).toHaveLength(2);

    // delete first file
    const deleteResponse1 = await harness.deleteFile(
      "testuser",
      upload1.file_id
    );
    harness.expectSuccessfulResponse(deleteResponse1, 200);

    // verify first file is gone, second file remains
    const listResponseAfter1 = await harness.listFiles("testuser");
    harness.expectSuccessfulResponse(listResponseAfter1);
    const listDataAfter1 = (await listResponseAfter1.json()) as any;
    expect(listDataAfter1.fileData).toHaveLength(1);
    expect(listDataAfter1.fileData[0].file_id).toBe(upload2.file_id);

    // verify second file can still be downloaded
    const downloadResponse2 = await harness.downloadFile(
      "testuser",
      upload2.file_id
    );
    harness.expectSuccessfulResponse(downloadResponse2);

    // delete second file
    const deleteResponse2 = await harness.deleteFile(
      "testuser",
      upload2.file_id
    );
    harness.expectSuccessfulResponse(deleteResponse2, 200);

    // verify no files remain
    const listResponseFinal = await harness.listFiles("testuser");
    harness.expectSuccessfulResponse(listResponseFinal);
    const listDataFinal = (await listResponseFinal.json()) as any;
    expect(listDataFinal.fileData).toHaveLength(0);
  });
});
