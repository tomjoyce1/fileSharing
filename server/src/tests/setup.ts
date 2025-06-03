import { drizzle } from "drizzle-orm/libsql";
import { createClient } from "@libsql/client";
import { migrate } from "drizzle-orm/libsql/migrator";
import { join } from "path";
import { Burger } from "burger-api";
import { beforeAll, beforeEach, afterEach, expect } from "bun:test";
import {
  sign as nodeSign,
  verify,
  diffieHellman,
  randomBytes,
  createCipheriv,
  KeyObject,
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  createDecipheriv,
} from "node:crypto";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import {
  generateKeyBundle,
  serializeKeyBundlePublic,
} from "~/utils/crypto/KeyHelper";
import { usersTable, filesTable, sharedAccessTable } from "~/db/schema";
import { rmSync, existsSync } from "node:fs";
import { eq } from "drizzle-orm";
import { mock } from "bun:test";
import type { KeyBundlePrivate, KeyBundlePublic } from "~/utils/schema";
import { createSignedPOST } from "~/utils/crypto/NetworkingHelper";
import {
  createFileSignature,
  encryptFile,
  decryptFileContent,
  decryptMetadata,
  type ClientFileData,
} from "~/utils/crypto/FileEncryption";
import { deserializeKeyBundlePublic } from "~/utils/crypto/KeyHelper";

// Strict type inference from database schema
type DbUser = typeof usersTable.$inferSelect;
type DbFile = typeof filesTable.$inferSelect;
type DbSharedAccess = typeof sharedAccessTable.$inferSelect;

export interface TestUserData {
  readonly dbUser: DbUser;
  readonly keyBundle: {
    readonly private: KeyBundlePrivate;
    readonly public: KeyBundlePublic;
  };
}

export interface TestFileData {
  readonly encrypted_file_content: string;
  readonly encrypted_metadata: string;
  readonly client_data: ClientFileData;
  readonly original_metadata: Record<string, unknown>;
}

export interface UploadResult {
  readonly file_id: number;
  readonly test_data: TestFileData;
}

let client: any;
export let testDb: any;
let globalBurger: Burger | null = null;
let globalServerPort = 3001;
let isGlobalServerRunning = false;
let serverStartPromise: Promise<void> | null = null;

class TestFileHelper {
  constructor(private readonly serverUrl: string) {}

  createEncryptedFile(
    content = "test file content",
    metadata: Record<string, unknown> = {
      filename: "test-document.pdf",
      file_size_bytes: 1024,
    }
  ): TestFileData {
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
      encrypted_metadata: Buffer.from(
        encrypted_metadata.encrypted_data
      ).toString("base64"),
      client_data,
      original_metadata: metadata,
    };
  }

  createFileSignatures(
    encrypted_file_content: string,
    encrypted_metadata: string,
    user: TestUserData,
    useBadSignature = false
  ): {
    readonly pre_quantum_signature: string;
    readonly post_quantum_signature: string;
  } {
    const dataToSign = createFileSignature(
      user.dbUser.username,
      encrypted_file_content,
      encrypted_metadata
    );

    const preQuantumSignature = nodeSign(
      null,
      Buffer.from(dataToSign),
      user.keyBundle.private.preQuantum.identitySigning.privateKey
    ).toString("base64");

    const postQuantumSignature = Buffer.from(
      ml_dsa87.sign(
        user.keyBundle.private.postQuantum.identitySigning.privateKey,
        Buffer.from(dataToSign)
      )
    ).toString("base64");

    return {
      pre_quantum_signature: useBadSignature ? "invalid" : preQuantumSignature,
      post_quantum_signature: postQuantumSignature,
    };
  }

  createUploadBody(
    fileData: TestFileData,
    user: TestUserData,
    useBadSignature = false
  ): Record<string, string> {
    const signatures = this.createFileSignatures(
      fileData.encrypted_file_content,
      fileData.encrypted_metadata,
      user,
      useBadSignature
    );

    return {
      file_content: fileData.encrypted_file_content,
      metadata: fileData.encrypted_metadata,
      ...signatures,
    };
  }

  async makeAuthenticatedRequest(
    endpoint: string,
    body: Record<string, unknown>,
    user: TestUserData,
    username?: string
  ): Promise<Response> {
    return await createSignedPOST(
      endpoint,
      body,
      username || user.dbUser.username,
      user.keyBundle.private,
      this.serverUrl
    );
  }

  async uploadFile(
    user: TestUserData,
    fileContent?: string,
    metadata?: Record<string, unknown>
  ): Promise<UploadResult> {
    const clonedMetadata = metadata
      ? JSON.parse(JSON.stringify(metadata))
      : undefined;
    const fileData = this.createEncryptedFile(fileContent, clonedMetadata);
    const uploadBody = this.createUploadBody(fileData, user);

    const response = await this.makeAuthenticatedRequest(
      "/api/fs/upload",
      uploadBody,
      user
    );
    expect(response.status).toBe(201);

    const responseData = (await response.json()) as {
      file_id: number;
      message: string;
    };
    expect(responseData.file_id).toBeDefined();
    expect(typeof responseData.file_id).toBe("number");

    return { file_id: responseData.file_id, test_data: fileData };
  }

  async downloadFile(file_id: number, user: TestUserData): Promise<Response> {
    const downloadBody = { file_id };
    return await this.makeAuthenticatedRequest(
      "/api/fs/download",
      downloadBody,
      user
    );
  }

  async listFiles(user: TestUserData, page = 1): Promise<Response> {
    const listBody = { page };
    return await this.makeAuthenticatedRequest("/api/fs/list", listBody, user);
  }

  async getUserKeyBundle(
    username: string,
    requestingUser: TestUserData
  ): Promise<Response> {
    const body = { username };
    return await this.makeAuthenticatedRequest(
      "/api/keyhandler/getbundle",
      body,
      requestingUser
    );
  }

  verifyFileSignatures(
    username: string,
    file_content: string,
    metadata: string,
    pre_quantum_signature: string,
    post_quantum_signature: string,
    userPublicBundle: KeyBundlePublic
  ): boolean {
    try {
      const dataToSign = createFileSignature(username, file_content, metadata);

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

  decryptFileContent(
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

  decryptMetadata(
    encrypted_metadata: string,
    client_data: ClientFileData
  ): Record<string, unknown> {
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

  createLargeFile(sizeInMB: number): TestFileData {
    const sizeInBytes = sizeInMB * 1024 * 1024;
    const content = "a".repeat(sizeInBytes);
    return this.createEncryptedFile(content);
  }
}

class TestSharingHelper extends TestFileHelper {
  private deriveSharedSecret(
    ephemeralPrivateKey: KeyObject,
    recipientPublicKey: KeyObject
  ): Buffer {
    return diffieHellman({
      privateKey: ephemeralPrivateKey,
      publicKey: recipientPublicKey,
    });
  }

  private encryptWithSharedSecret(
    data: Uint8Array,
    sharedSecret: Buffer,
    nonce: Buffer
  ): Buffer {
    const cipher = createCipheriv("aes-256-ctr", sharedSecret, nonce);
    const encrypted1 = cipher.update(Buffer.from(data));
    const encrypted2 = cipher.final();

    return Buffer.concat([encrypted1, encrypted2]);
  }

  private decryptWithSharedSecret(
    encryptedData: Buffer,
    sharedSecret: Buffer,
    nonce: Buffer
  ): Buffer {
    const cipher = createDecipheriv("aes-256-ctr", sharedSecret, nonce);
    const decrypted1 = cipher.update(encryptedData);
    const decrypted2 = cipher.final();

    return Buffer.concat([decrypted1, decrypted2]);
  }

  deriveClientDataFromSharedAccess(
    sharedAccess: {
      encrypted_fek: string;
      encrypted_fek_nonce: string;
      encrypted_mek: string;
      encrypted_mek_nonce: string;
      ephemeral_public_key: string;
      file_content_nonce: string;
      metadata_nonce: string;
    },
    recipientPrivateKeyBundle: KeyBundlePrivate
  ): ClientFileData {
    const ephemeralPublicKey = createPublicKey({
      key: Buffer.from(sharedAccess.ephemeral_public_key, "base64"),
      format: "der",
      type: "spki",
      encoding: "der",
    });

    const sharedSecret = diffieHellman({
      privateKey: recipientPrivateKeyBundle.preQuantum.identityKem.privateKey,
      publicKey: ephemeralPublicKey,
    });

    const fekNonce = Buffer.from(sharedAccess.encrypted_fek_nonce, "base64");
    const fek = this.decryptWithSharedSecret(
      Buffer.from(sharedAccess.encrypted_fek, "base64"),
      sharedSecret,
      fekNonce
    );

    const mekNonce = Buffer.from(sharedAccess.encrypted_mek_nonce, "base64");
    const mek = this.decryptWithSharedSecret(
      Buffer.from(sharedAccess.encrypted_mek, "base64"),
      sharedSecret,
      mekNonce
    );

    return {
      fek,
      mek,
      fileNonce: Buffer.from(sharedAccess.file_content_nonce, "base64"),
      metadataNonce: Buffer.from(sharedAccess.metadata_nonce, "base64"),
    };
  }

  async shareFile(
    file_id: number,
    owner: TestUserData,
    shared_with_username: string,
    originalFek: Uint8Array,
    originalMek: Uint8Array,
    fileContentNonce: Uint8Array,
    metadataNonce: Uint8Array
  ): Promise<Response> {
    const keyBundleResponse = await this.getUserKeyBundle(
      shared_with_username,
      owner
    );
    expect(keyBundleResponse.status).toBe(200);

    const keyBundleData = (await keyBundleResponse.json()) as any;
    const recipientPublicBundle = deserializeKeyBundlePublic(
      keyBundleData.key_bundle
    );

    const ephemeralKeyPair = generateKeyPairSync("x25519", {
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "der" },
    });

    const ephemeralPrivateKey = createPrivateKey({
      key: ephemeralKeyPair.privateKey,
      format: "der",
      type: "pkcs8",
      encoding: "der",
    });

    const sharedSecret = this.deriveSharedSecret(
      ephemeralPrivateKey,
      recipientPublicBundle.preQuantum.identityKemPublicKey
    );

    const fekNonce = randomBytes(16);
    const encryptedFekData = this.encryptWithSharedSecret(
      originalFek,
      sharedSecret,
      fekNonce
    );

    const mekNonce = randomBytes(16);
    const encryptedMekData = this.encryptWithSharedSecret(
      originalMek,
      sharedSecret,
      mekNonce
    );

    const shareBody = {
      file_id,
      shared_with_username,
      encrypted_fek: encryptedFekData.toString("base64"),
      encrypted_fek_nonce: fekNonce.toString("base64"),
      encrypted_mek: encryptedMekData.toString("base64"),
      encrypted_mek_nonce: mekNonce.toString("base64"),
      ephemeral_public_key: ephemeralKeyPair.publicKey.toString("base64"),
      file_content_nonce: Buffer.from(fileContentNonce).toString("base64"),
      metadata_nonce: Buffer.from(metadataNonce).toString("base64"),
    };

    return await this.makeAuthenticatedRequest(
      "/api/fs/share",
      shareBody,
      owner
    );
  }

  async revokeFile(
    file_id: number,
    fileOwner: TestUserData,
    username: string
  ): Promise<Response> {
    const revokeBody = {
      file_id,
      username,
    };

    return await this.makeAuthenticatedRequest(
      "/api/fs/revoke",
      revokeBody,
      fileOwner
    );
  }
}

class TestEnvironment {
  public readonly serverUrl = `http://localhost:${globalServerPort}`;
  private mockDbModule: any;
  private readonly users = new Map<string, TestUserData>();

  async setup(): Promise<void> {
    await this.setupDatabase();
    await this.startServer();
    this.setupMocks();
  }

  private async setupDatabase(): Promise<void> {
    client = createClient({ url: ":memory:" });
    testDb = drizzle(client);
    await migrate(testDb, { migrationsFolder: join(process.cwd(), "drizzle") });
  }

  private async startServer(): Promise<void> {
    if (isGlobalServerRunning) return;
    if (serverStartPromise) return serverStartPromise;

    serverStartPromise = this.initializeServer();
    return serverStartPromise;
  }

  private async initializeServer(): Promise<void> {
    if (isGlobalServerRunning) return;

    globalBurger = new Burger({
      apiDir: "src/api",
      title: "Test API",
      version: "1.0.0",
      apiPrefix: "api",
      description: "Test API server",
      debug: false,
    });

    await new Promise<void>((resolve) => {
      globalBurger!.serve(globalServerPort, () => {
        isGlobalServerRunning = true;
        resolve();
      });
    });
  }

  private setupMocks(): void {
    this.mockDbModule = mock.module("~/db", () => ({ db: testDb }));
  }

  async createUser(username: string): Promise<TestUserData> {
    if (this.users.has(username)) {
      return this.users.get(username)!;
    }

    const keyBundle = generateKeyBundle();
    const publicBundle = serializeKeyBundlePublic(keyBundle.public);

    await testDb.insert(usersTable).values({
      username,
      public_key_bundle: Buffer.from(JSON.stringify(publicBundle)),
    });

    const dbUser = await testDb
      .select()
      .from(usersTable)
      .where(eq(usersTable.username, username))
      .then((rows: DbUser[]) => rows[0]);

    const userData: TestUserData = { dbUser, keyBundle };
    this.users.set(username, userData);
    return userData;
  }

  getUser(username: string): TestUserData {
    const user = this.users.get(username);
    if (!user) throw new Error(`User ${username} not found`);
    return user;
  }

  async cleanupDatabase(): Promise<void> {
    await testDb.delete(sharedAccessTable);
    await testDb.delete(filesTable);
    await testDb.delete(usersTable);
    this.users.clear();
  }

  cleanupFiles(): void {
    const encryptedDriveDir = join(process.cwd(), "encrypted-drive");
    if (existsSync(encryptedDriveDir)) {
      rmSync(encryptedDriveDir, { recursive: true, force: true });
    }
  }
}

export class TestHarness {
  private readonly env = new TestEnvironment();
  private readonly _fileHelper = new TestFileHelper(this.env.serverUrl);
  private readonly _sharingHelper = new TestSharingHelper(this.env.serverUrl);

  async setupTest(): Promise<void> {
    await this.env.setup();
  }

  async beforeEachTest(): Promise<void> {
    await this.env.cleanupDatabase();
  }

  afterEachTest(): void {
    this.env.cleanupFiles();
  }

  async createUser(username: string): Promise<TestUserData> {
    return await this.env.createUser(username);
  }

  getUser(username: string): TestUserData {
    return this.env.getUser(username);
  }

  expectSuccessfulResponse(response: Response, expectedStatus = 200): void {
    expect(response.status).toBe(expectedStatus);
  }

  expectUnauthorized(response: Response): void {
    expect(response.status).toBe(401);
  }

  expectBadRequest(response: Response): void {
    expect(response.status).toBe(400);
  }

  expectForbidden(response: Response): void {
    expect(response.status).toBe(403);
  }

  expectConflict(response: Response): void {
    expect(response.status).toBe(409);
  }

  expectNotFound(response: Response): void {
    expect(response.status).toBe(404);
  }

  async expectResponseMessage(
    response: Response,
    expectedMessage: string
  ): Promise<void> {
    const data = (await response.json()) as any;
    expect(data.message).toBe(expectedMessage);
  }

  async uploadFile(
    username: string,
    content?: string,
    metadata?: Record<string, unknown>
  ): Promise<UploadResult> {
    const user = this.getUser(username);
    return await this._fileHelper.uploadFile(user, content, metadata);
  }

  async downloadFile(username: string, file_id: number): Promise<Response> {
    const user = this.getUser(username);
    return await this._fileHelper.downloadFile(file_id, user);
  }

  async listFiles(username: string, page = 1): Promise<Response> {
    const user = this.getUser(username);
    return await this._fileHelper.listFiles(user, page);
  }

  async shareFile(
    ownerUsername: string,
    recipientUsername: string,
    file_id: number,
    originalFek: Uint8Array,
    originalMek: Uint8Array,
    fileContentNonce: Uint8Array,
    metadataNonce: Uint8Array
  ): Promise<Response> {
    const owner = this.getUser(ownerUsername);
    return await this._sharingHelper.shareFile(
      file_id,
      owner,
      recipientUsername,
      originalFek,
      originalMek,
      fileContentNonce,
      metadataNonce
    );
  }

  async deriveClientDataFromSharedAccess(
    sharedAccess: {
      encrypted_fek: string;
      encrypted_fek_nonce: string;
      encrypted_mek: string;
      encrypted_mek_nonce: string;
      ephemeral_public_key: string;
      file_content_nonce: string;
      metadata_nonce: string;
    },
    recipientPrivateKeyBundle: KeyBundlePrivate
  ): Promise<ClientFileData> {
    return this._sharingHelper.deriveClientDataFromSharedAccess(
      sharedAccess,
      recipientPrivateKeyBundle
    );
  }

  async revokeFile(
    fileOwnerUsername: string,
    revokedFromUsername: string,
    file_id: number
  ): Promise<Response> {
    const fileOwner = this.getUser(fileOwnerUsername);
    return await this._sharingHelper.revokeFile(
      file_id,
      fileOwner,
      revokedFromUsername
    );
  }

  async getUserKeyBundle(
    username: string,
    requestingUsername: string
  ): Promise<Response> {
    const requestingUser = this.getUser(requestingUsername);
    return await this._fileHelper.getUserKeyBundle(username, requestingUser);
  }

  // Verification helpers
  verifyFileSignatures(
    username: string,
    file_content: string,
    metadata: string,
    pre_quantum_signature: string,
    post_quantum_signature: string,
    userPublicBundle: KeyBundlePublic
  ): boolean {
    return this._fileHelper.verifyFileSignatures(
      username,
      file_content,
      metadata,
      pre_quantum_signature,
      post_quantum_signature,
      userPublicBundle
    );
  }

  decryptFileContent(
    encrypted_file_content: string,
    client_data: ClientFileData
  ): string {
    return this._fileHelper.decryptFileContent(
      encrypted_file_content,
      client_data
    );
  }

  decryptMetadata(
    encrypted_metadata: string,
    client_data: ClientFileData
  ): Record<string, unknown> {
    return this._fileHelper.decryptMetadata(encrypted_metadata, client_data);
  }

  get fileHelper(): TestFileHelper {
    return this._fileHelper;
  }

  get sharingHelper(): TestSharingHelper {
    return this._sharingHelper;
  }

  get serverUrl(): string {
    return this.env.serverUrl;
  }
}

export function getTestHarness(): TestHarness {
  const harness = new TestHarness();

  beforeAll(async () => {
    await harness.setupTest();
  });

  beforeEach(async () => {
    await harness.beforeEachTest();
  });

  afterEach(() => {
    harness.afterEachTest();
  });

  return harness;
}

export const TestData = {
  simpleFile: {
    content: "test file content",
    metadata: {
      name: "test-document.pdf",
      size_bytes: 17,
    } as const,
  },

  largeFile: {
    content: "a".repeat(1024 * 1024), // 1MB
    metadata: {
      name: "large-file.bin",
      size_bytes: 1024 * 1024,
    } as const,
  },

  unicodeFile: {
    content: "файл с русскими символами",
    metadata: {
      name: "файл с русскими символами.pdf",
      size_bytes: 25,
    } as const,
  },

  emptyFile: {
    content: "",
    metadata: {
      name: "empty.txt",
      size_bytes: 0,
    } as const,
  },
} as const;

export const TestScenarios = {
  async createTwoUsersWithSharedFile(harness: TestHarness) {
    const userA = await harness.createUser("userA");
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

    return { userA, userB, uploadResult, shareResponse } as const;
  },

  async createUserWithMultipleFiles(
    harness: TestHarness,
    username: string,
    fileCount: number
  ): Promise<readonly UploadResult[]> {
    await harness.createUser(username);
    const uploads: UploadResult[] = [];

    for (let i = 0; i < fileCount; i++) {
      const content = `file ${i} content`;
      const metadata = {
        name: `file-${i}.txt`,
        size_bytes: content.length,
      } as const;

      const upload = await harness.uploadFile(username, content, metadata);
      uploads.push(upload);
    }

    return uploads;
  },
} as const;
