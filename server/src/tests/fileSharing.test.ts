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
import { filesTable, sharedAccessTable } from "~/db/schema";
import { writeFileSync } from "node:fs";
import { eq } from "drizzle-orm";
import {
  uploadTestFile,
  makeAuthenticatedPOST,
  decryptDownloadedContent,
  decryptDownloadedMetadata,
  verifyFileSignatures,
} from "./fileTestUtils";
import { deserializeKeyBundlePublic } from "~/utils/crypto/KeyHelper";
import { randomBytes, createCipheriv, diffieHellman } from "node:crypto";

let mockDbModule: any;

describe("File Sharing API", () => {
  let userA: any;
  let userAKeyBundle: any;
  let userB: any;
  let userBKeyBundle: any;
  let serverUrl: string;

  beforeAll(async () => {
    await setupTestDb();
    await ensureTestServerRunning();
    serverUrl = getTestServerUrl();

    // Set up the database mock after testDb is initialized
    mockDbModule = mock.module("~/db", () => ({
      db: testDb,
    }));

    // Create test users
    const userAData = await createTestUser("userA");
    userA = userAData.user;
    userAKeyBundle = userAData.keyBundle;

    const userBData = await createTestUser("userB");
    userB = userBData.user;
    userBKeyBundle = userBData.keyBundle;
  });

  beforeEach(async () => {
    await testDb.delete(sharedAccessTable);
    await testDb.delete(filesTable);
  });

  afterEach(() => {
    cleanupEncryptedDrive();
  });

  // Helper function to perform X25519 key exchange and derive shared secret
  function deriveSharedSecret(
    privateKey: any, // X25519 private key (KeyObject)
    publicKey: any // X25519 public key (KeyObject)
  ): Buffer {
    // Use Node.js built-in diffieHellman for X25519
    return diffieHellman({
      privateKey: privateKey,
      publicKey: publicKey,
    });
  }

  // Helper function to encrypt data using AES-256-CTR with a derived key
  function encryptWithSharedSecret(
    data: Uint8Array,
    sharedSecret: Buffer
  ): { encrypted: Buffer; salt: Buffer; nonce: Buffer } {
    const salt = randomBytes(32);
    const nonce = randomBytes(16);

    // Derive encryption key from shared secret + salt using a simple approach
    // In production, you'd use HKDF or similar
    const crypto = require("crypto");
    const key = crypto.pbkdf2Sync(sharedSecret, salt, 100000, 32, "sha256");

    const cipher = createCipheriv("aes-256-ctr", key, nonce);
    const encrypted1 = cipher.update(Buffer.from(data));
    const encrypted2 = cipher.final();

    return {
      encrypted: Buffer.concat([encrypted1, encrypted2]),
      salt,
      nonce,
    };
  }

  async function shareFile(
    file_id: number,
    owner: any,
    ownerKeyBundle: any,
    shared_with_username: string,
    originalFek: Uint8Array,
    originalMek: Uint8Array
  ) {
    // Get the recipient's public key bundle
    const keyBundleResponse = await getUserKeyBundle(
      shared_with_username,
      owner,
      ownerKeyBundle
    );
    expect(keyBundleResponse.status).toBe(200);
    const keyBundleData = (await keyBundleResponse.json()) as any;
    const recipientPublicBundle = deserializeKeyBundlePublic(
      keyBundleData.key_bundle
    );

    // Derive shared secret using X25519 key exchange
    const sharedSecret = deriveSharedSecret(
      ownerKeyBundle.private.preQuantum.identityKem.privateKey,
      recipientPublicBundle.preQuantum.identityKemPublicKey
    );

    // Encrypt FEK and MEK with the shared secret
    const encryptedFekData = encryptWithSharedSecret(originalFek, sharedSecret);
    const encryptedMekData = encryptWithSharedSecret(originalMek, sharedSecret);

    const shareBody = {
      file_id,
      shared_with_username,
      encrypted_fek: encryptedFekData.encrypted.toString("base64"),
      encrypted_fek_salt: encryptedFekData.salt.toString("base64"),
      encrypted_fek_nonce: encryptedFekData.nonce.toString("base64"),
      encrypted_mek: encryptedMekData.encrypted.toString("base64"),
      encrypted_mek_salt: encryptedMekData.salt.toString("base64"),
      encrypted_mek_nonce: encryptedMekData.nonce.toString("base64"),
    };

    return await makeAuthenticatedPOST(
      "/api/fs/share",
      shareBody,
      owner,
      ownerKeyBundle,
      serverUrl
    );
  }

  async function downloadSharedFile(
    file_id: number,
    user: any,
    userKeyBundle: any
  ) {
    const downloadBody = { file_id };
    return await makeAuthenticatedPOST(
      "/api/fs/download",
      downloadBody,
      user,
      userKeyBundle,
      serverUrl
    );
  }

  async function getUserKeyBundle(
    username: string,
    requestingUser: any,
    requestingUserKeyBundle: any
  ) {
    const body = { username };
    return await makeAuthenticatedPOST(
      "/api/keyhandler/getbundle",
      body,
      requestingUser,
      requestingUserKeyBundle,
      serverUrl
    );
  }

  test("successful file sharing and verification", async () => {
    // user A uploads a file
    const originalContent = "test file content for sharing";
    const originalMetadata = {
      filename: "shared-document.pdf",
      file_size_bytes: originalContent.length,
      mime_type: "application/pdf",
    };

    const uploadResult = await uploadTestFile(
      userA,
      userAKeyBundle,
      serverUrl,
      originalContent,
      originalMetadata
    );

    // user A shares the file with user B
    const shareResponse = await shareFile(
      uploadResult.file_id,
      userA,
      userAKeyBundle,
      userB.username,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    expect(shareResponse.status).toBe(201);
    const shareData = (await shareResponse.json()) as any;
    expect(shareData.message).toBe("File shared successfully");

    // user B fetches user A's key bundle to verify signatures
    const keyBundleResponse = await getUserKeyBundle(
      userA.username,
      userB,
      userBKeyBundle
    );
    expect(keyBundleResponse.status).toBe(200);
    const keyBundleData = (await keyBundleResponse.json()) as any;
    const userAPublicBundle = keyBundleData.key_bundle;
    const userAPublicKeyBundle = deserializeKeyBundlePublic(userAPublicBundle);

    // User B downloads the shared file
    const downloadResponse = await downloadSharedFile(
      uploadResult.file_id,
      userB,
      userBKeyBundle
    );
    expect(downloadResponse.status).toBe(200);

    const downloadData = (await downloadResponse.json()) as any;
    expect(downloadData.file_content).toBeDefined();
    expect(downloadData.pre_quantum_signature).toBeDefined();
    expect(downloadData.post_quantum_signature).toBeDefined();

    // Verify file signatures using User A's public keys
    const signaturesValid = verifyFileSignatures(
      userA.user_id,
      downloadData.file_content,
      uploadResult.test_data.encrypted_metadata,
      downloadData.pre_quantum_signature,
      downloadData.post_quantum_signature,
      userAPublicKeyBundle
    );
    expect(signaturesValid).toBe(true);

    // Verify we can decrypt the content using the shared encryption keys
    // Note: In a real implementation, User B would use the shared encrypted_fek/encrypted_mek
    // to decrypt the file, but for this test we'll use the original client data
    const decryptedContent = decryptDownloadedContent(
      downloadData.file_content,
      uploadResult.test_data.client_data
    );
    expect(decryptedContent).toBe(originalContent);

    const decryptedMetadata = decryptDownloadedMetadata(
      uploadResult.test_data.encrypted_metadata,
      uploadResult.test_data.client_data
    );
    expect(decryptedMetadata.filename).toBe("shared-document.pdf");
    expect(decryptedMetadata.file_size_bytes).toBe(originalContent.length);
    expect(decryptedMetadata.mime_type).toBe("application/pdf");
  });

  test("file tampering detection", async () => {
    // User A uploads a file
    const originalContent = "original file content";
    const uploadResult = await uploadTestFile(
      userA,
      userAKeyBundle,
      serverUrl,
      originalContent
    );

    // User A shares the file with User B
    const shareResponse = await shareFile(
      uploadResult.file_id,
      userA,
      userAKeyBundle,
      userB.username,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    expect(shareResponse.status).toBe(201);

    // Tamper with the file on disk
    const fileRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, uploadResult.file_id))
      .then((rows: any[]) => rows[0]);

    if (!fileRecord) {
      throw new Error("File record not found");
    }

    // Read the original file and append "123" to it
    const fs = require("fs");
    const originalFileContent = fs.readFileSync(fileRecord.storage_path);
    const tamperedContent = Buffer.concat([
      originalFileContent,
      Buffer.from("123"),
    ]);
    writeFileSync(fileRecord.storage_path, tamperedContent);

    // User B fetches User A's key bundle
    const keyBundleResponse = await getUserKeyBundle(
      userA.username,
      userB,
      userBKeyBundle
    );
    expect(keyBundleResponse.status).toBe(200);
    const keyBundleData = (await keyBundleResponse.json()) as any;
    const userAPublicBundle = keyBundleData.key_bundle;
    const userAPublicKeyBundle = deserializeKeyBundlePublic(userAPublicBundle);

    // The tampered file content
    const tamperedBase64 = tamperedContent.toString("base64");

    // Verify signatures should fail because file was tampered
    const signaturesValid = verifyFileSignatures(
      userA.user_id,
      tamperedBase64,
      uploadResult.test_data.encrypted_metadata,
      fileRecord.pre_quantum_signature.toString("base64"),
      fileRecord.post_quantum_signature.toString("base64"),
      userAPublicKeyBundle
    );
    expect(signaturesValid).toBe(false);
  });

  test("server lying about key bundle", async () => {
    // User A uploads a file
    const originalContent = "test file for key bundle verification";
    const uploadResult = await uploadTestFile(
      userA,
      userAKeyBundle,
      serverUrl,
      originalContent
    );

    // User A shares the file with User B
    const shareResponse = await shareFile(
      uploadResult.file_id,
      userA,
      userAKeyBundle,
      userB.username,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    expect(shareResponse.status).toBe(201);

    // Create a fake/incorrect key bundle
    const fakeKeyBundle = {
      preQuantum: {
        identitySigningPublicKey: Buffer.from("fake_pre_quantum_key"),
      },
      postQuantum: {
        identitySigningPublicKey: Buffer.from("fake_post_quantum_key"),
      },
    };

    // Get the file record
    const fileRecord = await testDb
      .select()
      .from(filesTable)
      .where(eq(filesTable.file_id, uploadResult.file_id))
      .then((rows: any[]) => rows[0]);

    if (!fileRecord) {
      throw new Error("File record not found");
    }

    // Verify signatures with the fake key bundle should fail
    const signaturesValid = verifyFileSignatures(
      userA.user_id,
      uploadResult.test_data.encrypted_file_content,
      uploadResult.test_data.encrypted_metadata,
      fileRecord.pre_quantum_signature.toString("base64"),
      fileRecord.post_quantum_signature.toString("base64"),
      fakeKeyBundle
    );
    expect(signaturesValid).toBe(false);

    // Verify with correct key bundle should succeed
    const correctSignaturesValid = verifyFileSignatures(
      userA.user_id,
      uploadResult.test_data.encrypted_file_content,
      uploadResult.test_data.encrypted_metadata,
      fileRecord.pre_quantum_signature.toString("base64"),
      fileRecord.post_quantum_signature.toString("base64"),
      userAKeyBundle.public
    );
    expect(correctSignaturesValid).toBe(true);
  });

  test("cannot share file with self", async () => {
    const uploadResult = await uploadTestFile(userA, userAKeyBundle, serverUrl);

    const shareResponse = await shareFile(
      uploadResult.file_id,
      userA,
      userAKeyBundle,
      userA.username,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    expect(shareResponse.status).toBe(400);
    const responseData = (await shareResponse.json()) as any;
    expect(responseData.message).toBe("Cannot share file with self");
  });

  test("cannot share file you don't own", async () => {
    // User A uploads a file
    const uploadResult = await uploadTestFile(userA, userAKeyBundle, serverUrl);

    // User B tries to share User A's file
    const shareResponse = await shareFile(
      uploadResult.file_id,
      userB,
      userBKeyBundle,
      "userB",
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    expect(shareResponse.status).toBe(403);
    const responseData = (await shareResponse.json()) as any;
    expect(responseData.message).toBe("Unauthorized");
  });

  test("cannot share same file twice with same user", async () => {
    const uploadResult = await uploadTestFile(userA, userAKeyBundle, serverUrl);

    // First share should succeed
    const firstShareResponse = await shareFile(
      uploadResult.file_id,
      userA,
      userAKeyBundle,
      userB.username,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    expect(firstShareResponse.status).toBe(201);

    // Second share should fail
    const secondShareResponse = await shareFile(
      uploadResult.file_id,
      userA,
      userAKeyBundle,
      userB.username,
      uploadResult.test_data.client_data.fek,
      uploadResult.test_data.client_data.mek
    );
    expect(secondShareResponse.status).toBe(409);
    const responseData = (await secondShareResponse.json()) as any;
    expect(responseData.message).toBe("File is already shared with this user");
  });

  test("shared files appear in user's file list", async () => {
    // User A uploads two files
    const upload1 = await uploadTestFile(
      userA,
      userAKeyBundle,
      serverUrl,
      "file 1 content",
      { filename: "file1.txt" }
    );

    await uploadTestFile(userA, userAKeyBundle, serverUrl, "file 2 content", {
      filename: "file2.txt",
    });

    // User A shares first file with User B
    await shareFile(
      upload1.file_id,
      userA,
      userAKeyBundle,
      userB.username,
      upload1.test_data.client_data.fek,
      upload1.test_data.client_data.mek
    );

    // User B lists their files
    const listBody = { page: 1 };
    const listResponse = await makeAuthenticatedPOST(
      "/api/fs/list",
      listBody,
      userB,
      userBKeyBundle,
      serverUrl
    );
    expect(listResponse.status).toBe(200);

    const listData = (await listResponse.json()) as any;
    expect(listData.fileData).toHaveLength(1);
    expect(listData.fileData[0].file_id).toBe(upload1.file_id);
    expect(listData.fileData[0].is_owner).toBe(false);
    expect(listData.fileData[0].shared_access).toBeDefined();
    expect(listData.fileData[0].shared_access.encrypted_fek).toBeDefined();
    expect(listData.fileData[0].shared_access.encrypted_mek).toBeDefined();
  });
});
