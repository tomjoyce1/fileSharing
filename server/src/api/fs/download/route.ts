import { z } from "zod";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { filesTable, sharedAccessTable } from "~/db/schema";
import { getAuthenticatedUserFromRequest } from "~/utils/crypto/NetworkingHelper";
import { ok, err, Result } from "neverthrow";
import { existsSync, readFileSync } from "node:fs";
import { eq, and, or } from "drizzle-orm";
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
        pre_quantum_signature: filesTable.pre_quantum_signature,
        post_quantum_signature: filesTable.post_quantum_signature,
        owner_user_id: filesTable.owner_user_id,
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
        pre_quantum_signature: sharedFile.pre_quantum_signature,
        post_quantum_signature: sharedFile.post_quantum_signature,
        owner_user_id: sharedFile.owner_user_id,
        is_owner: false,
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
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  const fileContent = fileContentResult.value;
  return Response.json(
    {
      file_content: fileContent,
      pre_quantum_signature: file.pre_quantum_signature.toString("base64"),
      post_quantum_signature: file.post_quantum_signature.toString("base64"),
      owner_user_id: file.owner_user_id,
      is_owner: file.is_owner,
    },
    { status: 200 }
  );
}
