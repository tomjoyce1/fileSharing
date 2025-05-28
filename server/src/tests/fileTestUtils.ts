import { expect } from "bun:test";
import { createHash, sign as nodeSign, verify } from "node:crypto";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { createSignedPOST } from "~/utils/crypto/NetworkingHelper";
import { testDb } from "./setup";
import { filesTable } from "~/db/schema";

export function createTestMetadata(overrides: Partial<any> = {}) {
  return {
    filename: "test-document.pdf",
    file_size_bytes: 1024,
    hash_of_encrypted_content: "sha256hash123",
    ...overrides,
  };
}

export function createFileContent(content = "encrypted file content") {
  return Buffer.from(content).toString("base64");
}

export function createFileSignatures(
  metadata_payload: string,
  testUser: any,
  testUserKeyBundle: any,
  useBadSignature = false
) {
  const metadataBuffer = Buffer.from(metadata_payload, "base64");
  const metadataHash = createHash("sha256")
    .update(metadataBuffer)
    .digest("hex");

  const dataToSign = `${testUser.user_id}|${metadataHash}`;

  const preQuantumSignature = nodeSign(
    null,
    Buffer.from(dataToSign),
    testUserKeyBundle.private.preQuantum.identitySigning.privateKey
  ).toString("base64");

  const postQuantumSignature = Buffer.from(
    ml_dsa87.sign(
      testUserKeyBundle.private.postQuantum.identitySigning.privateKey,
      Buffer.from(dataToSign)
    )
  ).toString("base64");

  return {
    pre_quantum_signature: useBadSignature ? "invalid" : preQuantumSignature,
    post_quantum_signature: postQuantumSignature,
  };
}

export function createUploadRequestBody(
  fileContent: string,
  metadata: any,
  testUser: any,
  testUserKeyBundle: any,
  nonce = "nonce123",
  useBadSignature = false
) {
  const metadataPayload = Buffer.from(JSON.stringify(metadata)).toString(
    "base64"
  );
  const metadataNonce = Buffer.from(nonce).toString("base64");
  const signatures = createFileSignatures(
    metadataPayload,
    testUser,
    testUserKeyBundle,
    useBadSignature
  );

  return {
    file_content: fileContent,
    metadata_payload: metadataPayload,
    metadata_payload_nonce: metadataNonce,
    ...signatures,
  };
}

export async function makeAuthenticatedPOST(
  endpoint: string,
  requestBody: any,
  testUser: any,
  testUserKeyBundle: any,
  serverUrl: string,
  username?: string
) {
  return await createSignedPOST(
    endpoint,
    requestBody,
    username || testUser.username,
    testUserKeyBundle.private,
    serverUrl
  );
}

export function verifyFileSignatures(
  user_id: number,
  metadata_payload: string,
  pre_quantum_signature: string,
  post_quantum_signature: string,
  userPublicBundle: any
): boolean {
  try {
    const metadataBuffer = Buffer.from(metadata_payload, "base64");
    const metadataHash = createHash("sha256")
      .update(metadataBuffer)
      .digest("hex");

    const dataToSign = `${user_id}|${metadataHash}`;

    const preQuantumValid = verify(
      null,
      Buffer.from(dataToSign),
      userPublicBundle.preQuantum.identitySigningPublicKey,
      Buffer.from(pre_quantum_signature, "base64")
    );

    const postQuantumValid = ml_dsa87.verify(
      userPublicBundle.postQuantum.identitySigningPublicKey,
      Buffer.from(dataToSign),
      Buffer.from(post_quantum_signature, "base64")
    );

    return preQuantumValid && postQuantumValid;
  } catch (error) {
    return false;
  }
}

export async function uploadTestFile(
  testUser: any,
  testUserKeyBundle: any,
  serverUrl: string,
  fileContent?: string,
  metadata?: any,
  nonce?: string
): Promise<number> {
  const content = fileContent || createFileContent("test file content");
  const meta = metadata || createTestMetadata();
  const uploadBody = createUploadRequestBody(
    content,
    meta,
    testUser,
    testUserKeyBundle,
    nonce
  );

  const response = await makeAuthenticatedPOST(
    "/api/fs/upload",
    uploadBody,
    testUser,
    testUserKeyBundle,
    serverUrl
  );
  expect(response.status).toBe(201);

  // get the uploaded file from database
  const files = await testDb.select().from(filesTable);
  expect(files).toHaveLength(1);
  return files[0].file_id;
}

export async function downloadFile(
  file_id: number,
  testUser: any,
  testUserKeyBundle: any,
  serverUrl: string
) {
  const downloadBody = { file_id };
  return await makeAuthenticatedPOST(
    "/api/fs/download",
    downloadBody,
    testUser,
    testUserKeyBundle,
    serverUrl
  );
}

export function createLargeFileContent(sizeInMB: number): string {
  const sizeInBytes = sizeInMB * 1024 * 1024;
  const buffer = Buffer.alloc(sizeInBytes, "a");
  return buffer.toString("base64");
}
