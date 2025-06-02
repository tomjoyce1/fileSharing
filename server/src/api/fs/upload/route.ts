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
    // Validate base64 format more strictly
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(file_content)) {
      return err({ message: "File Write Error", status: 400 });
    }

    // Decode and re-encode to verify it's actually valid base64
    const decoded = Buffer.from(file_content, "base64");
    const reencoded = decoded.toString("base64");
    if (reencoded !== file_content) {
      return err({ message: "File Write Error", status: 400 });
    }

    // Ensure the directory exists
    const dir = dirname(storage_path);
    mkdirSync(dir, { recursive: true });

    // Write to disk
    writeFileSync(storage_path, decoded);

    return ok(undefined);
  } catch (error) {
    return err({ message: "Internal Server Error", status: 500 });
  }
}

function cleanupFile(storage_path: string): void {
  try {
    if (existsSync(storage_path)) {
      unlinkSync(storage_path);
    }
  } catch (error) {
    // cleanup is best effort - just log
    console.error(`Failed to cleanup file ${storage_path}:`, error);
  }
}

function verifyFileSignatures(
  username: string,
  file_content: string,
  metadata: string,
  pre_quantum_signature: string,
  post_quantum_signature: string,
  userPublicBundle: KeyBundlePublic
): Result<void, APIError> {
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

    if (!preQuantumValid || !postQuantumValid) {
      return err({ message: "Unauthorized", status: 401 });
    }

    return ok(undefined);
  } catch (error) {
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
      return err({ message: "Internal Server Error", status: 500 });
    }

    return ok(result[0].file_id);
  } catch (error) {
    return err({ message: "Internal Server Error", status: 500 });
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
    metadata,
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
    user.username,
    file_content,
    metadata,
    pre_quantum_signature,
    post_quantum_signature,
    userPublicBundle
  );

  if (signatureResult.isErr()) {
    const apiError = signatureResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  // Generate unique storage path and write file to disk
  const storage_path = generateUniqueStoragePath();
  const writeResult = writeFileContent(storage_path, file_content);

  if (writeResult.isErr()) {
    const apiError = writeResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  // Insert file record into database
  const insertResult = await insertFileRecord(
    user.user_id,
    storage_path,
    metadata,
    pre_quantum_signature,
    post_quantum_signature
  );

  if (insertResult.isErr()) {
    // Database failed, try cleanup the file we just wrote
    cleanupFile(storage_path);

    const apiError = insertResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  return Response.json(
    {
      message: "File uploaded successfully",
      file_id: insertResult.value,
    },
    { status: 201 }
  );
}
