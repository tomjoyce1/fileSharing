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
import {
  existsSync,
  writeFileSync,
  mkdirSync,
  unlinkSync,
  appendFileSync,
} from "node:fs";
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

function logSigDebug(label: string, data: any) {
  try {
    const logFilePath = "sig-debug.log";

    // Ensure the file exists or create it
    if (!existsSync(logFilePath)) {
      writeFileSync(logFilePath, "", { flag: "w" });
    }

    appendFileSync(
      logFilePath,
      `[${new Date().toISOString()}] ${label}: ${
        typeof data === "string" ? data : JSON.stringify(data, null, 2)
      }\n`
    );
  } catch (e) {
    console.error("[sig-debug.log] Failed to write log", e);
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
    console.log("Canonical String (dataToSign)", dataToSign);
    console.log(
      "Pre-Quantum Public Key (DER base64)",
      userPublicBundle.preQuantum.identitySigningPublicKey
        .export({ format: "der", type: "spki" })
        .toString("base64")
    );
    console.log("Pre-Quantum Signature (base64)", pre_quantum_signature);
    console.log(
      "Post-Quantum Public Key (base64)",
      Buffer.from(
        userPublicBundle.postQuantum.identitySigningPublicKey
      ).toString("base64")
    );
    console.log("Post-Quantum Signature (base64)", post_quantum_signature);
    const preQuantumValid = verify(
      null,
      Buffer.from(dataToSign),
      userPublicBundle.preQuantum.identitySigningPublicKey,
      Buffer.from(pre_quantum_signature, "base64")
    );
    console.log("Pre-Quantum Verification Result", preQuantumValid);
    const postQuantumValid = ml_dsa87.verify(
      userPublicBundle.postQuantum.identitySigningPublicKey,
      Buffer.from(dataToSign),
      Buffer.from(post_quantum_signature, "base64")
    );
    console.log("Post-Quantum Verification Result", postQuantumValid);
    if (!preQuantumValid || !postQuantumValid) {
      console.log("Signature verification failed", {
        preQuantumValid,
        postQuantumValid,
      });
      return err({ message: "Unauthorized", status: 401 });
    }
    console.log("Signature verification succeeded", {
      preQuantumValid,
      postQuantumValid,
    });
    return ok(undefined);
  } catch (error) {
    console.log(
      "Signature Verification Exception",
      error instanceof Error ? error.stack || error.message : error
    );
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
      console.log("DB INSERT FAILED: result[0] is falsy", result);
      return err({ message: "Internal Server Error", status: 500 });
    }

    return ok(result[0].file_id);
  } catch (error) {
    console.log("DB INSERT FAILED: error", error);
    return err({ message: "Internal Server Error", status: 500 });
  }
}

function logErrorDetails(context: string, error: unknown) {
  console.error(`[Error] Context: ${context}`);
  if (error instanceof Error) {
    console.error(`[Error Details] Message: ${error.message}`);
    console.error(`[Error Details] Stack: ${error.stack}`);
  } else {
    console.error(`[Error Details]`, error);
  }
}

export async function POST(
  req: BurgerRequest<{ body: z.infer<typeof schema.post.body> }>
) {
  // Log every upload attempt
  console.log(
    "UPLOAD ATTEMPT HEADERS",
    Object.fromEntries(
      req.headers.entries ? req.headers.entries() : Object.entries(req.headers)
    )
  );
  console.log("UPLOAD ATTEMPT BODY", req.body ? req.body : req.validated?.body);

  if (!req.validated?.body) {
    console.log("UPLOAD ERROR", "No validated body");
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
    console.log("AUTHENTICATION FAILURE", userResult.error);
    return Response.json({ message: "Unauthorized" }, { status: 401 });
  }

  const user = userResult.value;

  // ensure file size is within limit
  if (file_content.length > MAX_FILE_SIZE) {
    console.log("UPLOAD ERROR", "File too large");
    return Response.json({ message: "File too large" }, { status: 413 });
  }

  // Verify file record signatures
  const userPublicBundle = deserializeKeyBundlePublic(
    JSON.parse(user.public_key_bundle.toString())
  );

  // Log public keys
  console.log("USER PUBLIC BUNDLE", {
    preQuantum: userPublicBundle.preQuantum.identitySigningPublicKey
      .export({ format: "der", type: "spki" })
      .toString("base64"),
    postQuantum: Buffer.from(
      userPublicBundle.postQuantum.identitySigningPublicKey
    ).toString("base64"),
  });

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
    console.log("SIGNATURE VERIFICATION FAILURE", apiError);
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
    console.log("UPLOAD ERROR", apiError);
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  console.log("Inserting file record with:", {
    user: user.user_id,
    storage_path,
    metadata_preview: Buffer.from(metadata, "base64")
      .toString("utf-8")
      .slice(0, 100),
    pre_quantum_signature,
    post_quantum_signature,
  });

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
    console.log("UPLOAD ERROR", apiError);
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  console.log("UPLOAD SUCCESS", { file_id: insertResult.value });
  return Response.json(
    {
      message: "File uploaded successfully",
      file_id: insertResult.value,
    },
    { status: 201 }
  );
}
