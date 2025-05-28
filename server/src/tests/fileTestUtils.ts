import { expect } from "bun:test";
import { sign as nodeSign, verify } from "node:crypto";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { createSignedPOST } from "~/utils/crypto/NetworkingHelper";
import {
  createFileSignature,
  encryptFile,
  decryptFileContent,
  decryptMetadata,
  type ClientFileData,
} from "~/utils/crypto/FileEncryption";

export interface TestEncryptedFileData {
  encrypted_file_content: string;
  encrypted_metadata: string;
  client_data: ClientFileData;
  original_metadata: any;
}

export function createEncryptedFileContent(
  content = "test file content",
  metadata = { filename: "test-document.pdf", file_size_bytes: 1024 }
): TestEncryptedFileData {
  const plaintext_content = new TextEncoder().encode(content);
  const encryptionResult = encryptFile(plaintext_content, metadata);
  if (encryptionResult.isErr()) {
    throw new Error(`Encryption failed: ${encryptionResult.error}`);
  }

  const { encrypted_content, encrypted_metadata, client_data } =
    encryptionResult.value;

  return {
    encrypted_file_content: Buffer.from(
      encrypted_content.encrypted_data
    ).toString("base64"),
    encrypted_metadata: Buffer.from(encrypted_metadata.encrypted_data).toString(
      "base64"
    ),
    client_data,
    original_metadata: metadata,
  };
}

export function createFileSignatures(
  file_content: string,
  metadata: string,
  testUser: any,
  testUserKeyBundle: any,
  useBadSignature = false
) {
  const dataToSign = createFileSignature(
    testUser.user_id,
    file_content,
    metadata
  );

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
  encrypted_metadata: string,
  testUser: any,
  testUserKeyBundle: any,
  useBadSignature = false
) {
  const signatures = createFileSignatures(
    fileContent,
    encrypted_metadata,
    testUser,
    testUserKeyBundle,
    useBadSignature
  );

  return {
    file_content: fileContent,
    metadata: encrypted_metadata,
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
  file_content: string,
  metadata: string,
  pre_quantum_signature: string,
  post_quantum_signature: string,
  userPublicBundle: any
): boolean {
  try {
    const dataToSign = createFileSignature(user_id, file_content, metadata);

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
  metadata?: any
): Promise<{ file_id: number; test_data: TestEncryptedFileData }> {
  const clonedMetadata = metadata
    ? JSON.parse(JSON.stringify(metadata))
    : undefined;
  const encrypted = createEncryptedFileContent(fileContent, clonedMetadata);

  const uploadBody = createUploadRequestBody(
    encrypted.encrypted_file_content,
    encrypted.encrypted_metadata,
    testUser,
    testUserKeyBundle
  );

  const response = await makeAuthenticatedPOST(
    "/api/fs/upload",
    uploadBody,
    testUser,
    testUserKeyBundle,
    serverUrl
  );
  expect(response.status).toBe(201);

  // get the file_id from the response
  const responseData = (await response.json()) as {
    file_id: number;
    message: string;
  };
  expect(responseData.file_id).toBeDefined();
  expect(typeof responseData.file_id).toBe("number");

  return { file_id: responseData.file_id, test_data: encrypted };
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

export function createLargeFileContent(
  sizeInMB: number
): TestEncryptedFileData {
  const sizeInBytes = sizeInMB * 1024 * 1024;
  const content = "a".repeat(sizeInBytes);

  return createEncryptedFileContent(content);
}

export function decryptDownloadedContent(
  encrypted_file_content: string,
  client_data: ClientFileData
): string {
  const encryptedData = {
    encrypted_data: new Uint8Array(
      Buffer.from(encrypted_file_content, "base64")
    ),
    nonce: client_data.fileNonce,
  };

  const decryptResult = decryptFileContent(encryptedData, client_data.fek);
  if (decryptResult.isErr()) {
    throw new Error(`Decryption failed: ${decryptResult.error}`);
  }

  return new TextDecoder().decode(decryptResult.value);
}

export function decryptDownloadedMetadata(
  encrypted_metadata: string,
  client_data: ClientFileData
): any {
  const encryptedData = {
    encrypted_data: new Uint8Array(Buffer.from(encrypted_metadata, "base64")),
    nonce: client_data.metadataNonce,
  };

  const decryptResult = decryptMetadata(encryptedData, client_data);
  if (decryptResult.isErr()) {
    throw new Error(`Metadata decryption failed: ${decryptResult.error}`);
  }

  return decryptResult.value;
}
