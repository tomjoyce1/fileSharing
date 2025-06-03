import { expect, test, describe } from "bun:test";
import { getTestHarness, TestData } from "./setup";

describe("File Revoke API", () => {
  const harness = getTestHarness();

  test("successful file revoke - happy path", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");

    // upload a file as userA
    const uploadResult = await harness.uploadFile(
      "userA",
      TestData.simpleFile.content,
      TestData.simpleFile.metadata
    );

    // share the file with userB
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

    // verify userB can see the shared file
    const listResponseBefore = await harness.listFiles("userB");
    harness.expectSuccessfulResponse(listResponseBefore);
    const listDataBefore = (await listResponseBefore.json()) as any;
    expect(listDataBefore.fileData).toHaveLength(1);
    expect(listDataBefore.fileData[0].file_id).toBe(uploadResult.file_id);
    expect(listDataBefore.fileData[0].is_owner).toBe(false);

    // revoke the file from userB
    const revokeResponse = await harness.revokeFile(
      "userA",
      "userB",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(revokeResponse, 200);
    await harness.expectResponseMessage(
      revokeResponse,
      "File access revoked successfully"
    );

    // verify userB can no longer see the file
    const listResponseAfter = await harness.listFiles("userB");
    harness.expectSuccessfulResponse(listResponseAfter);
    const listDataAfter = (await listResponseAfter.json()) as any;
    expect(listDataAfter.fileData).toHaveLength(0);
  });

  test("cannot revoke file that doesn't exist", async () => {
    await harness.createUser("userA");

    const nonExistentFileId = 99999;
    const revokeResponse = await harness.revokeFile(
      "userA",
      "userB",
      nonExistentFileId
    );
    harness.expectBadRequest(revokeResponse);
    await harness.expectResponseMessage(revokeResponse, "Unknown file");
  });

  test("cannot revoke file twice", async () => {
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

    // first revoke should succeed
    const firstRevokeResponse = await harness.revokeFile(
      "userA",
      "userB",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(firstRevokeResponse, 200);
    await harness.expectResponseMessage(
      firstRevokeResponse,
      "File access revoked successfully"
    );

    // second revoke should fail
    const secondRevokeResponse = await harness.revokeFile(
      "userA",
      "userB",
      uploadResult.file_id
    );
    harness.expectNotFound(secondRevokeResponse);
    await harness.expectResponseMessage(
      secondRevokeResponse,
      "File is not shared with this user"
    );
  });

  test("cannot revoke file from user that doesn't exist", async () => {
    await harness.createUser("userA");

    const uploadResult = await harness.uploadFile("userA");

    const revokeResponse = await harness.revokeFile(
      "userA",
      "nonExistentUser",
      uploadResult.file_id
    );
    harness.expectBadRequest(revokeResponse);
    await harness.expectResponseMessage(revokeResponse, "Unknown user");
  });

  test("cannot revoke file from user that file was never shared with", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");
    await harness.createUser("userC");

    const uploadResult = await harness.uploadFile("userA");

    // share with userB but not userC
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

    // try to revoke from userC (who was never shared with)
    const revokeResponse = await harness.revokeFile(
      "userA",
      "userC",
      uploadResult.file_id
    );
    harness.expectNotFound(revokeResponse);
    await harness.expectResponseMessage(
      revokeResponse,
      "File is not shared with this user"
    );
  });

  test("cannot revoke file you don't own", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");
    await harness.createUser("userC");

    const uploadResult = await harness.uploadFile("userA");

    // share with userB
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

    // userC tries to revoke userA's file shared with userB
    const revokeResponse = await harness.revokeFile(
      "userC",
      "userB",
      uploadResult.file_id
    );
    harness.expectForbidden(revokeResponse);
    await harness.expectResponseMessage(revokeResponse, "Unauthorized");
  });

  test("cannot revoke access from self", async () => {
    await harness.createUser("userA");

    const uploadResult = await harness.uploadFile("userA");

    const revokeResponse = await harness.revokeFile(
      "userA",
      "userA",
      uploadResult.file_id
    );
    harness.expectBadRequest(revokeResponse);
    await harness.expectResponseMessage(
      revokeResponse,
      "Cannot revoke access from self"
    );
  });

  test("malformed request body - missing file_id", async () => {
    await harness.createUser("userA");
    const user = harness.getUser("userA");

    const response = await harness.sharingHelper.makeAuthenticatedRequest(
      "/api/fs/revoke",
      { username: "userB" }, // missing file_id
      user
    );
    harness.expectBadRequest(response);
  });

  test("malformed request body - missing username", async () => {
    await harness.createUser("userA");
    const user = harness.getUser("userA");

    const response = await harness.sharingHelper.makeAuthenticatedRequest(
      "/api/fs/revoke",
      { file_id: 123 }, // missing username
      user
    );
    harness.expectBadRequest(response);
  });

  test("malformed request body - invalid file_id", async () => {
    await harness.createUser("userA");
    const user = harness.getUser("userA");

    const response = await harness.sharingHelper.makeAuthenticatedRequest(
      "/api/fs/revoke",
      { file_id: -1, username: "userB" }, // negative file_id
      user
    );
    harness.expectBadRequest(response);
  });

  test("malformed request body - non-integer file_id", async () => {
    await harness.createUser("userA");
    const user = harness.getUser("userA");

    const response = await harness.sharingHelper.makeAuthenticatedRequest(
      "/api/fs/revoke",
      { file_id: "not_a_number", username: "userB" }, // string file_id
      user
    );
    harness.expectBadRequest(response);
  });

  test("revoke affects only specific user, not all shares", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");
    await harness.createUser("userC");

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

    // verify both users can see the file
    const listResponseB = await harness.listFiles("userB");
    harness.expectSuccessfulResponse(listResponseB);
    const listDataB = (await listResponseB.json()) as any;
    expect(listDataB.fileData).toHaveLength(1);

    const listResponseC = await harness.listFiles("userC");
    harness.expectSuccessfulResponse(listResponseC);
    const listDataC = (await listResponseC.json()) as any;
    expect(listDataC.fileData).toHaveLength(1);

    // revoke access from userB only
    const revokeResponse = await harness.revokeFile(
      "userA",
      "userB",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(revokeResponse, 200);

    // verify userB can no longer see the file
    const listResponseBAfter = await harness.listFiles("userB");
    harness.expectSuccessfulResponse(listResponseBAfter);
    const listDataBAfter = (await listResponseBAfter.json()) as any;
    expect(listDataBAfter.fileData).toHaveLength(0);

    // verify userC can still see the file
    const listResponseCAfter = await harness.listFiles("userC");
    harness.expectSuccessfulResponse(listResponseCAfter);
    const listDataCAfter = (await listResponseCAfter.json()) as any;
    expect(listDataCAfter.fileData).toHaveLength(1);
    expect(listDataCAfter.fileData[0].file_id).toBe(uploadResult.file_id);
  });
});
