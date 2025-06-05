import {
  randomBytes,
  createHash,
  createCipheriv,
  createDecipheriv,
} from "node:crypto";
import { ok, err, Result } from "neverthrow";

// Encryption constants
const NONCE_SIZE = 16; // AES-CTR nonce size

export interface EncryptedData {
  encrypted_data: Uint8Array;
  nonce: Uint8Array;
}

export interface ClientFileData {
  fek: Uint8Array;
  fileNonce: Uint8Array;
  mek: Uint8Array;
  metadataNonce: Uint8Array;
}

// encrypts the file content using a file encryption key (FEK)
export function encryptFileContent(
  content: Uint8Array,
  fek: Uint8Array
): Result<EncryptedData, string> {
  try {
    const fileNonce = randomBytes(NONCE_SIZE);
    const cipher = createCipheriv(
      "aes-256-ctr",
      Buffer.from(fek),
      Buffer.from(fileNonce)
    );

    const encrypted1 = cipher.update(Buffer.from(content));
    const encrypted2 = cipher.final();

    const encrypted_data = new Uint8Array(
      encrypted1.length + encrypted2.length
    );
    encrypted_data.set(encrypted1);
    encrypted_data.set(encrypted2, encrypted1.length);

    // Log details of the encryption process

    return ok({
      encrypted_data,
      nonce: fileNonce,
    });
  } catch (error) {
    return err("Failed to encrypt file content");
  }
}

// decrypts the file content using a file encryption key (FEK)
function decryptFileContentWithFEK(
  encryptedData: EncryptedData,
  fek: Uint8Array
): Result<Uint8Array, string> {
  try {
    const decipher = createDecipheriv(
      "aes-256-ctr",
      Buffer.from(fek),
      Buffer.from(encryptedData.nonce)
    );

    const decrypted1 = decipher.update(
      Buffer.from(encryptedData.encrypted_data)
    );
    const decrypted2 = decipher.final();

    const decrypted = new Uint8Array(decrypted1.length + decrypted2.length);
    decrypted.set(decrypted1);
    decrypted.set(decrypted2, decrypted1.length);

    return ok(decrypted);
  } catch (error) {
    return err("Failed to decrypt file content");
  }
}

// encrypts metadata using a metadata encryption key (MEK)
function encryptMetadata(
  metadata: any,
  mek: Uint8Array
): Result<EncryptedData, string> {
  try {
    const metadataJson = JSON.stringify(metadata);
    const metadataBytes = new TextEncoder().encode(metadataJson);

    const metadataNonce = randomBytes(NONCE_SIZE);
    const cipher = createCipheriv(
      "aes-256-ctr",
      Buffer.from(mek),
      Buffer.from(metadataNonce)
    );

    const encrypted1 = cipher.update(Buffer.from(metadataBytes));
    const encrypted2 = cipher.final();

    const encrypted_data = new Uint8Array(
      encrypted1.length + encrypted2.length
    );
    encrypted_data.set(encrypted1);
    encrypted_data.set(encrypted2, encrypted1.length);

    // Log details of the encryption process

    return ok({
      encrypted_data,
      nonce: metadataNonce,
    });
  } catch (error) {
    return err("Failed to encrypt metadata");
  }
}

// decrypts metadata using a metadata encryption key (MEK)
function decryptMetadataWithMEK(
  encryptedData: EncryptedData,
  mek: Uint8Array
): Result<any, string> {
  try {
    const decipher = createDecipheriv(
      "aes-256-ctr",
      Buffer.from(mek),
      Buffer.from(encryptedData.nonce)
    );

    const decrypted1 = decipher.update(
      Buffer.from(encryptedData.encrypted_data)
    );
    const decrypted2 = decipher.final();

    const decryptedBytes = new Uint8Array(
      decrypted1.length + decrypted2.length
    );
    decryptedBytes.set(decrypted1);
    decryptedBytes.set(decrypted2, decrypted1.length);

    const decryptedJson = new TextDecoder().decode(decryptedBytes);
    const metadata = JSON.parse(decryptedJson);

    return ok(metadata);
  } catch (error) {
    return err("Failed to decrypt metadata");
  }
}

// encrypts a file's content and metadata, returning the encrypted data and client data
export function encryptFile(
  plaintext_content: Uint8Array,
  plaintext_metadata: any
): Result<
  {
    encrypted_content: EncryptedData;
    encrypted_metadata: EncryptedData;
    client_data: ClientFileData;
  },
  string
> {
  try {
    // generate fek and mek
    const mek = randomBytes(32);
    const fek = randomBytes(32);

    // encrypt content
    const encryptedContentResult = encryptFileContent(plaintext_content, fek);
    if (encryptedContentResult.isErr())
      return err(encryptedContentResult.error);

    // encrypt metadata
    const encryptedMetadataResult = encryptMetadata(plaintext_metadata, mek);
    if (encryptedMetadataResult.isErr())
      return err(encryptedMetadataResult.error);

    // save client data
    const client_data: ClientFileData = {
      fek,
      fileNonce: encryptedContentResult.value.nonce,
      mek,
      metadataNonce: encryptedMetadataResult.value.nonce,
    };

    return ok({
      encrypted_content: encryptedContentResult.value,
      encrypted_metadata: encryptedMetadataResult.value,
      client_data,
    });
  } catch (error) {
    return err("Failed to encrypt file");
  }
}

// decrypts a file's content using the file encryption key (FEK)
export function decryptFileContent(
  encrypted_content: EncryptedData,
  fek: Uint8Array
): Result<Uint8Array, string> {
  try {
    return decryptFileContentWithFEK(encrypted_content, fek);
  } catch (error) {
    return err("Failed to decrypt file content with client data");
  }
}

// decrypts metadata using the metadata encryption key (MEK) from client data
export function decryptMetadata(
  encrypted_metadata: EncryptedData,
  client_data: ClientFileData
): Result<any, string> {
  try {
    const mek = client_data.mek;
    return decryptMetadataWithMEK(encrypted_metadata, mek);
  } catch (error) {
    return err("Failed to decrypt metadata with client data");
  }
}

// creates a file signature based on the owner's username, file content, and metadata
export function createFileSignature(
  owner_username: string,
  file_content: string,
  metadata: string
): string {
  const encryptedContentHash = createHash("sha256")
    .update(Buffer.from(file_content, "base64"))
    .digest("hex");
  const encryptedMetadataHash = createHash("sha256")
    .update(Buffer.from(metadata, "base64"))
    .digest("hex");

  return `${owner_username}|${encryptedContentHash}|${encryptedMetadataHash}`;
}
