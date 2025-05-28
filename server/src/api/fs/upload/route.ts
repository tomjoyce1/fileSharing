import { z } from "zod";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { filesTable } from "~/db/schema";
import { createHash, verify, randomUUID } from "node:crypto";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { getAuthenticatedUserFromRequest } from "~/utils/crypto/NetworkingHelper";
import { deserializeKeyBundlePublic } from "~/utils/crypto/KeyHelper";
import { ok, err, Result } from "neverthrow";
import { existsSync, writeFileSync, mkdirSync, unlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import type { KeyBundlePublic } from "~/utils/schema";

const MAX_FILE_SIZE = 50 * 1024 * 1024;

export const schema = {
  post: {
    body: z
      .object({
        file_content: z.string().min(1, "File content is required"),
        metadata_payload: z.string().min(1, "Metadata payload is required"),
        metadata_payload_nonce: z.string().min(1, "Metadata nonce is required"),
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
): Result<void, string> {
  try {
    // Validate base64 format more strictly
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(file_content)) {
      return err("File Write Error");
    }

    // Decode and re-encode to verify it's actually valid base64
    const decoded = Buffer.from(file_content, "base64");
    const reencoded = decoded.toString("base64");
    if (reencoded !== file_content) {
      return err("File Write Error");
    }

    // Ensure the directory exists
    const dir = dirname(storage_path);
    mkdirSync(dir, { recursive: true });

    // Write to disk
    writeFileSync(storage_path, decoded);

    return ok(undefined);
  } catch (error) {
    return err("File Write Error");
  }
}

function cleanupFile(storage_path: string): void {
  try {
    if (existsSync(storage_path)) {
      unlinkSync(storage_path);
    }
  } catch (error) {
    // Log error but don't throw - cleanup is best effort
    console.error(`Failed to cleanup file ${storage_path}:`, error);
  }
}

function verifyFileSignatures(
  user_id: number,
  metadata_payload: string,
  pre_quantum_signature: string,
  post_quantum_signature: string,
  userPublicBundle: KeyBundlePublic
): Result<void, string> {
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

    if (!preQuantumValid || !postQuantumValid) {
      return err("Invalid file signatures");
    }

    return ok(undefined);
  } catch (error) {
    return err("Signature verification failed");
  }
}

async function insertFileRecord(
  user_id: number,
  storage_path: string,
  metadata_payload: string,
  metadata_payload_nonce: string,
  pre_quantum_signature: string,
  post_quantum_signature: string
): Promise<Result<void, string>> {
  try {
    const metadataBuffer = Buffer.from(metadata_payload, "base64");

    await db.insert(filesTable).values({
      owner_user_id: user_id,
      storage_path,
      metadata_payload: metadataBuffer,
      metadata_payload_nonce: Buffer.from(metadata_payload_nonce, "base64"),
      pre_quantum_signature: Buffer.from(pre_quantum_signature, "base64"),
      post_quantum_signature: Buffer.from(post_quantum_signature, "base64"),
    });

    return ok(undefined);
  } catch (error) {
    return err("Database Internal Error");
  }
}

export async function POST(
  req: BurgerRequest<{ body: z.infer<typeof schema.post.body> }>
) {
  if (!req.validated?.body) {
    return Response.json({ message: "Internal Server Error" }, { status: 500 });
  }

  const {
    file_content,
    metadata_payload,
    metadata_payload_nonce,
    pre_quantum_signature,
    post_quantum_signature,
  } = req.validated.body;

  // Authenticate user and get user from database
  const userResult = await getAuthenticatedUserFromRequest(
    req,
    JSON.stringify(req.validated.body)
  );
  if (userResult.isErr()) {
    return Response.json({ message: "Unauthorized" }, { status: 401 });
  }

  const user = userResult.value;

  // ensure file size is within limit
  if (file_content.length > MAX_FILE_SIZE) {
    return Response.json({ message: "File too large" }, { status: 413 });
  }

  // Verify file record signatures
  const userPublicBundle = deserializeKeyBundlePublic(
    JSON.parse(user.public_key_bundle.toString())
  );

  const signatureResult = verifyFileSignatures(
    user.user_id,
    metadata_payload,
    pre_quantum_signature,
    post_quantum_signature,
    userPublicBundle
  );

  if (signatureResult.isErr()) {
    return Response.json({ message: "Unauthorized" }, { status: 401 });
  }

  // Generate unique storage path and write file to disk
  const storage_path = generateUniqueStoragePath();
  const writeResult = writeFileContent(storage_path, file_content);

  if (writeResult.isErr()) {
    return Response.json({ message: "File write error" }, { status: 500 });
  }

  // Insert file record into database
  const insertResult = await insertFileRecord(
    user.user_id,
    storage_path,
    metadata_payload,
    metadata_payload_nonce,
    pre_quantum_signature,
    post_quantum_signature
  );

  if (insertResult.isErr()) {
    // Database failed, try cleanup the file we just wrote
    cleanupFile(storage_path);

    return Response.json({ message: "Database error" }, { status: 500 });
  }

  return Response.json(
    {
      message: "File uploaded successfully",
    },
    { status: 201 }
  );
}
