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
    const userB = await harness.createUser("userB");

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
      uploadResult.test_data.client_data.mek,
      uploadResult.test_data.client_data.fileNonce,
      uploadResult.test_data.client_data.metadataNonce
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
      userA.dbUser.username,
      downloadData.file_content,
      downloadData.metadata,
      downloadData.pre_quantum_signature,
      downloadData.post_quantum_signature,
      userAPublicKeyBundle
    );
    expect(signaturesValid).toBe(true);

    const derivedClientData = await harness.deriveClientDataFromSharedAccess(
      downloadData.shared_access,
      userB.keyBundle.private
    );
    expect(derivedClientData).toBeDefined();

    const decryptedContent = harness.decryptFileContent(
      downloadData.file_content,
      derivedClientData
    );
    expect(decryptedContent).toBe(TestData.simpleFile.content);

    const decryptedMetadata = harness.decryptMetadata(
      downloadData.metadata,
      derivedClientData
    );
    expect(decryptedMetadata.name).toBe(TestData.simpleFile.metadata.name);
  });

  test("file tampering detection", async () => {
    await harness.createUser("userA");
    const userB = await harness.createUser("userB");

    const originalContent = "original file content";
    const uploadResult = await harness.uploadFile("userA", originalContent);

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

    // User B downloads the file
    const downloadResponse = await harness.downloadFile(
      "userB",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(downloadResponse);
    const downloadData = (await downloadResponse.json()) as any;

    // Get User A's public key bundle
    const keyBundleResponse = await harness.getUserKeyBundle("userA", "userB");
    harness.expectSuccessfulResponse(keyBundleResponse);
    const keyBundleData = (await keyBundleResponse.json()) as any;
    const userAPublicKeyBundle = deserializeKeyBundlePublic(
      keyBundleData.key_bundle
    );

    const userA = harness.getUser("userA");

    // Verify original downloaded content (should be valid)
    const originalSignaturesValid = harness.verifyFileSignatures(
      userA.dbUser.username,
      downloadData.file_content,
      downloadData.metadata,
      downloadData.pre_quantum_signature,
      downloadData.post_quantum_signature,
      userAPublicKeyBundle
    );
    expect(originalSignaturesValid).toBe(true);

    // Tamper the downloaded file content (append to base64 string)
    const tamperedFileContentBase64 = downloadData.file_content + "TAMPERED";

    // Verify tampered content (should be invalid)
    const tamperedSignaturesValid = harness.verifyFileSignatures(
      userA.dbUser.username,
      tamperedFileContentBase64,
      downloadData.metadata, // Use metadata from download
      downloadData.pre_quantum_signature, // Use signature from download
      downloadData.post_quantum_signature, // Use signature from download
      userAPublicKeyBundle
    );
    expect(tamperedSignaturesValid).toBe(false);
  });

  test("server lying about key bundle", async () => {
    await harness.createUser("userA");
    const userB = await harness.createUser("userB");

    const originalContent = "test file for key bundle verification";
    const uploadResult = await harness.uploadFile("userA", originalContent);

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

    // User B downloads the file
    const downloadResponse = await harness.downloadFile(
      "userB",
      uploadResult.file_id
    );
    harness.expectSuccessfulResponse(downloadResponse);
    const downloadData = (await downloadResponse.json()) as any;

    const fakeKeyBundle = {
      preQuantum: {
        identitySigningPublicKey: Buffer.from("fake_pre_quantum_key"),
      },
      postQuantum: {
        identitySigningPublicKey: Buffer.from("fake_post_quantum_key"),
      },
    };

    const userA = harness.getUser("userA");

    // Verify with the fake key bundle (should be invalid)
    const signaturesValidWithFakeKey = harness.verifyFileSignatures(
      userA.dbUser.username,
      downloadData.file_content,
      downloadData.metadata,
      downloadData.pre_quantum_signature,
      downloadData.post_quantum_signature,
      // @ts-expect-error: testing invalid key bundle
      fakeKeyBundle
    );
    expect(signaturesValidWithFakeKey).toBe(false);

    // Verify with the correct key bundle (should be valid)
    const correctSignaturesValid = harness.verifyFileSignatures(
      userA.dbUser.username,
      downloadData.file_content,
      downloadData.metadata,
      downloadData.pre_quantum_signature,
      downloadData.post_quantum_signature,
      userA.keyBundle.public // User A's actual public key
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
      uploadResult.test_data.client_data.mek,
      uploadResult.test_data.client_data.fileNonce,
      uploadResult.test_data.client_data.metadataNonce
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
      uploadResult.test_data.client_data.mek,
      uploadResult.test_data.client_data.fileNonce,
      uploadResult.test_data.client_data.metadataNonce
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
      uploadResult.test_data.client_data.mek,
      uploadResult.test_data.client_data.fileNonce,
      uploadResult.test_data.client_data.metadataNonce
    );
    harness.expectSuccessfulResponse(firstShareResponse, 201);

    const secondShareResponse = await harness.shareFile(
      "userA",
      "userB",
      uploadResult.file_id,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek,
      uploadResult.test_data.client_data.fileNonce,
      uploadResult.test_data.client_data.metadataNonce
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
      upload1.test_data.client_data.mek,
      upload1.test_data.client_data.fileNonce,
      upload1.test_data.client_data.metadataNonce
    );

    const listResponse = await harness.listFiles("userB");
    harness.expectSuccessfulResponse(listResponse);

    const listData = (await listResponse.json()) as any;
    expect(listData.fileData).toHaveLength(1);
    expect(listData.fileData[0].file_id).toBe(upload1.file_id);
    expect(listData.fileData[0].is_owner).toBe(false);
    expect(listData.fileData[0].shared_access).toBeDefined();
    expect(listData.fileData[0].shared_access.encrypted_fek).toBeDefined();
    expect(
      listData.fileData[0].shared_access.encrypted_fek_nonce
    ).toBeDefined();
    expect(listData.fileData[0].shared_access.encrypted_mek).toBeDefined();
    expect(
      listData.fileData[0].shared_access.encrypted_mek_nonce
    ).toBeDefined();
    expect(listData.fileData[0].shared_access.file_content_nonce).toBeDefined();
    expect(listData.fileData[0].shared_access.metadata_nonce).toBeDefined();
    expect(
      listData.fileData[0].shared_access.ephemeral_public_key
    ).toBeDefined();
  });

  test("server cannot substitute different user's file content", async () => {
    const userA = await harness.createUser("userA");
    await harness.createUser("userB");
    await harness.createUser("userC");

    // UserA uploads and shares a file with userB
    const userAContent = "userA's secret file content";
    const userAUpload = await harness.uploadFile("userA", userAContent, {
      filename: "userA_file.txt",
    });

    const shareResponse = await harness.shareFile(
      "userA",
      "userB",
      userAUpload.file_id,
      userAUpload.test_data.client_data.fek,
      userAUpload.test_data.client_data.mek,
      userAUpload.test_data.client_data.fileNonce,
      userAUpload.test_data.client_data.metadataNonce
    );
    harness.expectSuccessfulResponse(shareResponse, 201);

    // UserC uploads a different file (this simulates malicious content the server might substitute)
    const userCContent = "userC's malicious file content";
    const userCUpload = await harness.uploadFile("userC", userCContent, {
      filename: "userC_file.txt",
    });

    // UserB downloads userA's file
    const downloadResponse = await harness.downloadFile(
      "userB",
      userAUpload.file_id
    );
    harness.expectSuccessfulResponse(downloadResponse);
    const downloadData = (await downloadResponse.json()) as any;

    // Get userA's public key bundle (what userB should use to verify)
    const keyBundleResponse = await harness.getUserKeyBundle("userA", "userB");
    harness.expectSuccessfulResponse(keyBundleResponse);
    const keyBundleData = (await keyBundleResponse.json()) as any;
    const userAPublicKeyBundle = deserializeKeyBundlePublic(
      keyBundleData.key_bundle
    );

    // First verify that the legitimate file content passes signature verification
    const legitSignaturesValid = harness.verifyFileSignatures(
      userA.dbUser.username,
      downloadData.file_content,
      downloadData.metadata,
      downloadData.pre_quantum_signature,
      downloadData.post_quantum_signature,
      userAPublicKeyBundle
    );
    expect(legitSignaturesValid).toBe(true);

    // Now simulate server attack: substitute userC's file content while keeping userA's signatures
    // This would happen if a malicious server tried to give userB different content than what userA shared
    const maliciousSignaturesValid = harness.verifyFileSignatures(
      userA.dbUser.username, // Server claims this is still from userA
      userCUpload.test_data.encrypted_file_content, // But substitutes userC's content
      downloadData.metadata, // Keep userA's metadata
      downloadData.pre_quantum_signature, // Keep userA's signatures
      downloadData.post_quantum_signature,
      userAPublicKeyBundle // UserB still has userA's key bundle
    );
    expect(maliciousSignaturesValid).toBe(false);

    // Also test substituting both content and metadata from userC
    const fullSubstitutionSignaturesValid = harness.verifyFileSignatures(
      userA.dbUser.username, // Server still claims this is from userA
      userCUpload.test_data.encrypted_file_content, // userC's content
      userCUpload.test_data.encrypted_metadata, // userC's metadata
      downloadData.pre_quantum_signature, // But userA's signatures
      downloadData.post_quantum_signature,
      userAPublicKeyBundle // UserB has userA's key bundle
    );
    expect(fullSubstitutionSignaturesValid).toBe(false);
  });
});
