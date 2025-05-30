import { expect, test, describe } from "bun:test";
import { getTestHarness, TestData, testDb } from "./setup";
import { filesTable } from "~/db/schema";
import { writeFileSync } from "node:fs";
import { eq } from "drizzle-orm";
import { deserializeKeyBundlePublic } from "~/utils/crypto/KeyHelper";

describe("File Sharing API", () => {
  const harness = getTestHarness();

  test("successful file sharing and verification", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");

    const uploadResult = await harness.uploadFile(
      "userA",
      TestData.simpleFile.content,
      TestData.simpleFile.metadata
    );

    const shareResponse = await harness.shareFile(
      "userA",
      "userB",
      uploadResult.file_id,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    harness.expectSuccessfulResponse(shareResponse, 201);
    await harness.expectResponseMessage(
      shareResponse,
      "File shared successfully"
    );

    const keyBundleResponse = await harness.getUserKeyBundle("userA", "userB");
    harness.expectSuccessfulResponse(keyBundleResponse);
    const keyBundleData = (await keyBundleResponse.json()) as any;
    const userAPublicKeyBundle = deserializeKeyBundlePublic(
      keyBundleData.key_bundle
    );

    const downloadResponse = await harness.downloadFile(
      "userB",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(downloadResponse);

    const downloadData = (await downloadResponse.json()) as any;
    expect(downloadData.file_content).toBeDefined();
    expect(downloadData.pre_quantum_signature).toBeDefined();
    expect(downloadData.post_quantum_signature).toBeDefined();

    const userA = harness.getUser("userA");
    const signaturesValid = harness.verifyFileSignatures(
      userA.dbUser.user_id,
      downloadData.file_content,
      uploadResult.test_data.encrypted_metadata,
      downloadData.pre_quantum_signature,
      downloadData.post_quantum_signature,
      userAPublicKeyBundle
    );
    expect(signaturesValid).toBe(true);

    const decryptedContent = harness.decryptFileContent(
      downloadData.file_content,
      uploadResult.test_data.client_data
    );
    expect(decryptedContent).toBe(TestData.simpleFile.content);

    const decryptedMetadata = harness.decryptMetadata(
      uploadResult.test_data.encrypted_metadata,
      uploadResult.test_data.client_data
    );
    expect(decryptedMetadata.name).toBe(TestData.simpleFile.metadata.name);
  });

  test("file tampering detection", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");

    const originalContent = "original file content";
    const uploadResult = await harness.uploadFile("userA", originalContent);

    const shareResponse = await harness.shareFile(
      "userA",
      "userB",
      uploadResult.file_id,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    harness.expectSuccessfulResponse(shareResponse, 201);

    const fileRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, uploadResult.file_id))
      .then((rows: any[]) => rows[0]);

    if (!fileRecord) {
      throw new Error("File record not found");
    }

    const fs = require("fs");
    const originalFileContent = fs.readFileSync(fileRecord.storage_path);
    const tamperedContent = Buffer.concat([
      originalFileContent,
      Buffer.from("123"),
    ]);
    writeFileSync(fileRecord.storage_path, tamperedContent);

    const keyBundleResponse = await harness.getUserKeyBundle("userA", "userB");
    harness.expectSuccessfulResponse(keyBundleResponse);
    const keyBundleData = (await keyBundleResponse.json()) as any;
    const userAPublicKeyBundle = deserializeKeyBundlePublic(
      keyBundleData.key_bundle
    );

    const tamperedBase64 = tamperedContent.toString("base64");

    const userA = harness.getUser("userA");
    const signaturesValid = harness.verifyFileSignatures(
      userA.dbUser.user_id,
      tamperedBase64,
      uploadResult.test_data.encrypted_metadata,
      fileRecord.pre_quantum_signature.toString("base64"),
      fileRecord.post_quantum_signature.toString("base64"),
      userAPublicKeyBundle
    );
    expect(signaturesValid).toBe(false);
  });

  test("server lying about key bundle", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");

    const originalContent = "test file for key bundle verification";
    const uploadResult = await harness.uploadFile("userA", originalContent);

    const shareResponse = await harness.shareFile(
      "userA",
      "userB",
      uploadResult.file_id,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    harness.expectSuccessfulResponse(shareResponse, 201);

    const fakeKeyBundle = {
      preQuantum: {
        identitySigningPublicKey: Buffer.from("fake_pre_quantum_key"),
      },
      postQuantum: {
        identitySigningPublicKey: Buffer.from("fake_post_quantum_key"),
      },
    };

    const fileRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, uploadResult.file_id))
      .then((rows: any[]) => rows[0]);

    if (!fileRecord) {
      throw new Error("File record not found");
    }

    const userA = harness.getUser("userA");
    const signaturesValid = harness.verifyFileSignatures(
      userA.dbUser.user_id,
      uploadResult.test_data.encrypted_file_content,
      uploadResult.test_data.encrypted_metadata,
      fileRecord.pre_quantum_signature.toString("base64"),
      fileRecord.post_quantum_signature.toString("base64"),
      // @ts-expect-error: testing invalid key bundle
      fakeKeyBundle
    );
    expect(signaturesValid).toBe(false);

    const correctSignaturesValid = harness.verifyFileSignatures(
      userA.dbUser.user_id,
      uploadResult.test_data.encrypted_file_content,
      uploadResult.test_data.encrypted_metadata,
      fileRecord.pre_quantum_signature.toString("base64"),
      fileRecord.post_quantum_signature.toString("base64"),
      userA.keyBundle.public
    );
    expect(correctSignaturesValid).toBe(true);
  });

  test("cannot share file with self", async () => {
    await harness.createUser("userA");

    const uploadResult = await harness.uploadFile("userA");

    const shareResponse = await harness.shareFile(
      "userA",
      "userA",
      uploadResult.file_id,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    harness.expectBadRequest(shareResponse);
    await harness.expectResponseMessage(
      shareResponse,
      "Cannot share file with self"
    );
  });

  test("cannot share file you don't own", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");

    const uploadResult = await harness.uploadFile("userA");

    const shareResponse = await harness.shareFile(
      "userB",
      "userA",
      uploadResult.file_id,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    harness.expectForbidden(shareResponse);
    await harness.expectResponseMessage(shareResponse, "Unauthorized");
  });

  test("cannot share same file twice with same user", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");

    const uploadResult = await harness.uploadFile("userA");

    const firstShareResponse = await harness.shareFile(
      "userA",
      "userB",
      uploadResult.file_id,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    harness.expectSuccessfulResponse(firstShareResponse, 201);

    const secondShareResponse = await harness.shareFile(
      "userA",
      "userB",
      uploadResult.file_id,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    harness.expectConflict(secondShareResponse);
    await harness.expectResponseMessage(
      secondShareResponse,
      "File is already shared with this user"
    );
  });

  test("shared files appear in user's file list", async () => {
    await harness.createUser("userA");
    await harness.createUser("userB");

    const upload1 = await harness.uploadFile("userA", "file 1 content", {
      filename: "file1.txt",
    });
    await harness.uploadFile("userA", "file 2 content", {
      filename: "file2.txt",
    });

    await harness.shareFile(
      "userA",
      "userB",
      upload1.file_id,
      upload1.test_data.client_data.fek,
      upload1.test_data.client_data.mek
    );

    const listResponse = await harness.listFiles("userB");
    harness.expectSuccessfulResponse(listResponse);

    const listData = (await listResponse.json()) as any;
    expect(listData.fileData).toHaveLength(1);
    expect(listData.fileData[0].file_id).toBe(upload1.file_id);
    expect(listData.fileData[0].is_owner).toBe(false);
    expect(listData.fileData[0].shared_access).toBeDefined();
    expect(listData.fileData[0].shared_access.encrypted_fek).toBeDefined();
    expect(listData.fileData[0].shared_access.encrypted_mek).toBeDefined();
  });
});
