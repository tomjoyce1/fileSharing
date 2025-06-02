import { z } from "zod";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { filesTable, sharedAccessTable } from "~/db/schema";
import { getAuthenticatedUserFromRequest } from "~/utils/crypto/NetworkingHelper";
import { ok, err, Result } from "neverthrow";
import { existsSync, readFileSync } from "node:fs";
import { eq, and } from "drizzle-orm";
import type { APIError } from "~/utils/schema";

export const schema = {
  post: {
    body: z
      .object({
        file_id: z
          .number()
          .int()
          .positive("File ID must be a positive integer"),
      })
      .strict(),
  },
};

async function getFileAccess(
  user_id: number,
  file_id: number
): Promise<Result<any, APIError>> {
  try {
    // user owns file?
    const ownedFile = await db
      .select({
        file_id: filesTable.file_id,
        storage_path: filesTable.storage_path,
        metadata: filesTable.metadata,
        pre_quantum_signature: filesTable.pre_quantum_signature,
        post_quantum_signature: filesTable.post_quantum_signature,
        owner_user_id: filesTable.owner_user_id,
      })
      .from(filesTable)
      .where(
        and(
          eq(filesTable.file_id, file_id),
          eq(filesTable.owner_user_id, user_id)
        )
      )
      .limit(1)
      .then((rows) => rows[0]);

    if (ownedFile) {
      return ok({
        ...ownedFile,
        is_owner: true,
      });
    }

    // user has shared access?
    const sharedFile = await db
      .select({
        file_id: filesTable.file_id,
        storage_path: filesTable.storage_path,
        metadata: filesTable.metadata,
        pre_quantum_signature: filesTable.pre_quantum_signature,
        post_quantum_signature: filesTable.post_quantum_signature,
        owner_user_id: filesTable.owner_user_id,
        encrypted_fek: sharedAccessTable.encrypted_fek,
        encrypted_fek_nonce: sharedAccessTable.encrypted_fek_nonce,
        encrypted_mek: sharedAccessTable.encrypted_mek,
        encrypted_mek_nonce: sharedAccessTable.encrypted_mek_nonce,
        ephemeral_public_key: sharedAccessTable.ephemeral_public_key,
        file_content_nonce: sharedAccessTable.file_content_nonce,
        metadata_nonce: sharedAccessTable.metadata_nonce,
      })
      .from(filesTable)
      .innerJoin(
        sharedAccessTable,
        and(
          eq(sharedAccessTable.file_id, filesTable.file_id),
          eq(sharedAccessTable.shared_with_user_id, user_id)
        )
      )
      .where(eq(filesTable.file_id, file_id))
      .limit(1)
      .then((rows) => rows[0]);

    if (sharedFile) {
      return ok({
        file_id: sharedFile.file_id,
        storage_path: sharedFile.storage_path,
        metadata: sharedFile.metadata,
        pre_quantum_signature: sharedFile.pre_quantum_signature,
        post_quantum_signature: sharedFile.post_quantum_signature,
        owner_user_id: sharedFile.owner_user_id,
        is_owner: false,
        shared_access: {
          encrypted_fek: sharedFile.encrypted_fek.toString("base64"),
          encrypted_fek_nonce:
            sharedFile.encrypted_fek_nonce.toString("base64"),
          encrypted_mek: sharedFile.encrypted_mek.toString("base64"),
          encrypted_mek_nonce:
            sharedFile.encrypted_mek_nonce.toString("base64"),
          ephemeral_public_key:
            sharedFile.ephemeral_public_key.toString("base64"),
          file_content_nonce: sharedFile.file_content_nonce.toString("base64"),
          metadata_nonce: sharedFile.metadata_nonce.toString("base64"),
        },
      });
    }

    return err({ message: "File not found", status: 404 });
  } catch (error) {
    return err({ message: "Internal Server Error", status: 500 });
  }
}

function readFileContent(storage_path: string): Result<string, APIError> {
  try {
    if (!existsSync(storage_path)) {
      return err({ message: "Internal Server Error", status: 500 });
    }

    const fileBuffer = readFileSync(storage_path);
    const base64Content = fileBuffer.toString("base64");

    return ok(base64Content);
  } catch (error) {
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
  if (!req.validated?.body) {
    return Response.json({ message: "Internal Server Error" }, { status: 500 });
  }

  const { file_id } = req.validated.body;

  // Authenticate user
  const userResult = await getAuthenticatedUserFromRequest(
    req,
    JSON.stringify(req.validated.body)
  );
  if (userResult.isErr()) {
    return Response.json({ message: "Unauthorized" }, { status: 401 });
  }

  const user = userResult.value;

  // check if user has access to the file (owned or shared)
  const fileResult = await getFileAccess(user.user_id, file_id);
  if (fileResult.isErr()) {
    const apiError = fileResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  const file = fileResult.value;

  // Read file content from disk
  const fileContentResult = readFileContent(file.storage_path);
  if (fileContentResult.isErr()) {
    const apiError = fileContentResult.error;
    logErrorDetails("Read File Content", apiError);
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  const fileContent = fileContentResult.value;
  return Response.json(
    {
      file_content: fileContent,
      metadata: file.metadata,
      pre_quantum_signature: file.pre_quantum_signature.toString("base64"),
      post_quantum_signature: file.post_quantum_signature.toString("base64"),
      owner_user_id: file.owner_user_id,
      is_owner: file.is_owner,
      ...(file.shared_access && { shared_access: file.shared_access }),
    },
    { status: 200 }
  );
}
