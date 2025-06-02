// src/routes/api/fs/upload.ts

import { z } from "zod";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { filesTable } from "~/db/schema";
import { verify, randomUUID } from "node:crypto";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { getAuthenticatedUserFromRequest } from "~/utils/crypto/NetworkingHelper";
import { deserializeKeyBundlePublic } from "~/utils/crypto/KeyHelper";
import { createFileSignature } from "~/utils/crypto/FileEncryption";
import { ok, err, Result } from "neverthrow";
import { existsSync, writeFileSync, mkdirSync, unlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import type { KeyBundlePublic, APIError } from "~/utils/schema";

// Raise Bun’s body parser limit to 50 MiB:
export const config = {
  bodyLimit: 50 * 1024 * 1024
};

const MAX_FILE_SIZE = 50 * 1024 * 1024;

export const schema = {
  post: {
    body: z
      .object({
        file_content: z.string().min(1, "File content is required"),
        metadata: z.string().min(1, "Metadata payload is required"),
        pre_quantum_signature: z
          .string()
          .min(1, "Pre-quantum signature is required"),
        post_quantum_signature: z
          .string()
          .min(1, "Post-quantum signature is required"),
      })
      .strict(),
  },
};

function generateUniqueStoragePath(): string {
  const baseDir = join(process.cwd(), "encrypted-drive");
  let storagePath: string;

  do {
    const uuid = randomUUID();
    storagePath = join(baseDir, `${uuid}.enc`);
  } while (existsSync(storagePath));

  return storagePath;
}

function writeFileContent(
  storage_path: string,
  file_content: string
): Result<void, APIError> {
  try {
    console.log("[SERVER] writeFileContent: validating base64");
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(file_content)) {
      console.log("[SERVER]  → invalid base64 format");
      return err({ message: "File Write Error", status: 400 });
    }

    // Decode and re‐encode to verify base64 correctness
    const decoded = Buffer.from(file_content, "base64");
    const reencoded = decoded.toString("base64");
    if (reencoded !== file_content) {
      console.log("[SERVER]  → reencoded !== original (bad base64)");
      return err({ message: "File Write Error", status: 400 });
    }

    console.log("[SERVER]  → base64 OK; writing to disk at:", storage_path);
    const dir = dirname(storage_path);
    mkdirSync(dir, { recursive: true });
    writeFileSync(storage_path, decoded);
    console.log("[SERVER]  → writeFileContent succeeded");
    return ok(undefined);
  } catch (e: any) {
    console.error("[SERVER] writeFileContent threw:", e);
    return err({ message: "Internal Server Error", status: 500 });
  }
}

function cleanupFile(storage_path: string): void {
  try {
    if (existsSync(storage_path)) {
      unlinkSync(storage_path);
      console.log("[SERVER] cleanupFile removed:", storage_path);
    }
  } catch (e) {
    console.error("[SERVER] cleanupFile failed:", e);
  }
}

function verifyFileSignatures(
  user_id: number,
  file_content: string,
  metadata: string,
  pre_quantum_signature: string,
  post_quantum_signature: string,
  userPublicBundle: KeyBundlePublic
): Result<void, APIError> {
  try {
    console.log("[SERVER] verifyFileSignatures: building dataToSign");
    const dataToSign = createFileSignature(user_id, file_content, metadata);

    console.log("[SERVER]  → verifying ED25519");
    const preQuantumValid = verify(
      null,
      Buffer.from(dataToSign),
      userPublicBundle.preQuantum.identitySigningPublicKey,
      Buffer.from(pre_quantum_signature, "base64")
    );

    console.log("[SERVER]  → verifying ML-DSA-87");
    const postQuantumValid = ml_dsa87.verify(
      userPublicBundle.postQuantum.identitySigningPublicKey,
      Buffer.from(dataToSign),
      Buffer.from(post_quantum_signature, "base64")
    );

    if (!preQuantumValid || !postQuantumValid) {
      console.log(
        "[SERVER]  → signature verification failed:",
        "preQuantumValid=", preQuantumValid,
        "postQuantumValid=", postQuantumValid
      );
      return err({ message: "Unauthorized", status: 401 });
    }

    console.log("[SERVER]  → signatures OK");
    return ok(undefined);
  } catch (e: any) {
    console.error("[SERVER] verifyFileSignatures threw:", e);
    return err({ message: "Internal Server Error", status: 500 });
  }
}

async function insertFileRecord(
  user_id: number,
  storage_path: string,
  metadata_payload: string,
  pre_quantum_signature: string,
  post_quantum_signature: string
): Promise<Result<number, APIError>> {
  try {
    console.log("[SERVER] insertFileRecord: writing to database");
    const metadataBuffer = Buffer.from(metadata_payload, "base64");

    const result = await db
      .insert(filesTable)
      .values({
        owner_user_id: user_id,
        storage_path,
        metadata: metadataBuffer,
        pre_quantum_signature: Buffer.from(pre_quantum_signature, "base64"),
        post_quantum_signature: Buffer.from(post_quantum_signature, "base64"),
      })
      .returning({ file_id: filesTable.file_id });

    if (!result[0]) {
      console.log("[SERVER]  → db.insert returned empty array");
      return err({ message: "Internal Server Error", status: 500 });
    }
    console.log("[SERVER]  → inserted file_id =", result[0].file_id);
    return ok(result[0].file_id);
  } catch (e: any) {
    console.error("[SERVER] insertFileRecord threw:", e);
    return err({ message: "Internal Server Error", status: 500 });
  }
}

export async function POST(
  req: BurgerRequest<{ body: z.infer<typeof schema.post.body> }>
) {
  console.log("[SERVER] POST /api/fs/upload: incoming request");
  if (!req.validated?.body) {
    console.log("[SERVER]  → request body failed validation");
    return Response.json({ message: "Internal Server Error" }, { status: 500 });
  }

  const {
    file_content,
    metadata,
    pre_quantum_signature,
    post_quantum_signature,
  } = req.validated.body;

  console.log(
    "[SERVER]  → received file_content length:",
    file_content.length,
    "metadata length:", metadata.length
  );

  // Authenticate user
  let user;
  try {
    console.log("[SERVER]  → calling getAuthenticatedUserFromRequest");
    const userResult = await getAuthenticatedUserFromRequest(
      req,
      JSON.stringify(req.validated.body)
    );
    if (userResult.isErr()) {
      console.log("[SERVER]  → authentication failed:", userResult.error);
      return Response.json({ message: "Unauthorized" }, { status: 401 });
    }
    user = userResult.value;
    console.log("[SERVER]  → authenticated as user_id =", user.user_id);
  } catch (e: any) {
    console.error("[SERVER] Error in getAuthenticatedUserFromRequest:", e);
    return Response.json({ message: "Internal Server Error" }, { status: 500 });
  }

  // Check size limit
  if (file_content.length > MAX_FILE_SIZE) {
    console.log("[SERVER]  → file_content over MAX_FILE_SIZE");
    return Response.json({ message: "File too large" }, { status: 413 });
  }

  // Verify signatures
  console.log("[SERVER]  → verifying file signatures");
  const userPublicBundle = deserializeKeyBundlePublic(
    JSON.parse(user.public_key_bundle.toString())
  );
  const signatureResult = verifyFileSignatures(
    user.user_id,
    file_content,
    metadata,
    pre_quantum_signature,
    post_quantum_signature,
    userPublicBundle
  );
  if (signatureResult.isErr()) {
    console.log("[SERVER]  → signature verification returned error:", signatureResult.error);
    return Response.json(
      { message: signatureResult.error.message },
      { status: signatureResult.error.status }
    );
  }

  // Write encrypted file to disk
  console.log("[SERVER]  → writing file to disk");
  const storage_path = generateUniqueStoragePath();
  const writeResult = writeFileContent(storage_path, file_content);
  if (writeResult.isErr()) {
    console.log("[SERVER]  → writeFileContent returned error:", writeResult.error);
    return Response.json(
      { message: writeResult.error.message },
      { status: writeResult.error.status }
    );
  }

  // Insert record into DB
  console.log("[SERVER]  → inserting DB record");
  const insertResult = await insertFileRecord(
    user.user_id,
    storage_path,
    metadata,
    pre_quantum_signature,
    post_quantum_signature
  );
  if (insertResult.isErr()) {
    console.log(
      "[SERVER]  → insertFileRecord returned error:",
      insertResult.error
    );
    cleanupFile(storage_path);
    return Response.json(
      { message: insertResult.error.message },
      { status: insertResult.error.status }
    );
  }

  console.log("[SERVER]  → upload successful, returning 201");
  return Response.json(
    {
      message: "File uploaded successfully",
      file_id: insertResult.value,
    },
    { status: 201 }
  );
}
