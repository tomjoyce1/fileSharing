import { z } from "zod";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { filesTable, sharedAccessTable } from "~/db/schema";
import { getAuthenticatedUserFromRequest } from "~/utils/crypto/NetworkingHelper";
import { ok, err, Result } from "neverthrow";
import { existsSync, readFileSync } from "node:fs";
import { eq, and } from "drizzle-orm";

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

async function checkFileAccess(
  user_id: number,
  file_id: number
): Promise<Result<{ file: any; sharedAccess?: any }, string>> {
  try {
    // check if owner
    const fileRecord = await db
      .select()
      .from(filesTable)
      .where(
        and(
          eq(filesTable.file_id, file_id),
          eq(filesTable.owner_user_id, user_id)
        )
      )
      .limit(1)
      .then((rows) => rows[0]);

    if (fileRecord) {
      return ok({ file: fileRecord });
    }

    // if not owner, check if user has shared access
    const sharedAccessRecord = await db
      .select({
        file: filesTable,
        sharedAccess: sharedAccessTable,
      })
      .from(sharedAccessTable)
      .innerJoin(filesTable, eq(sharedAccessTable.file_id, filesTable.file_id))
      .where(
        and(
          eq(sharedAccessTable.file_id, file_id),
          eq(sharedAccessTable.shared_with_user_id, user_id)
        )
      )
      .limit(1)
      .then((rows) => rows[0]);
    if (!sharedAccessRecord) {
      return err("File not found or access denied");
    }

    return ok({
      file: sharedAccessRecord.file,
      sharedAccess: sharedAccessRecord.sharedAccess,
    });
  } catch (error) {
    return err("Database error");
  }
}

function readFileContent(storage_path: string): Result<string, string> {
  try {
    if (!existsSync(storage_path)) {
      return err("File not found on disk");
    }

    const fileBuffer = readFileSync(storage_path);
    const base64Content = fileBuffer.toString("base64");

    return ok(base64Content);
  } catch (error) {
    return err("File read error");
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

  // Check if user has access to the file
  const accessResult = await checkFileAccess(user.user_id, file_id);
  if (accessResult.isErr()) {
    return Response.json({ message: "File not found" }, { status: 404 });
  }

  const { file, sharedAccess } = accessResult.value;

  // read file content from disk
  const fileContentResult = readFileContent(file.storage_path);
  if (fileContentResult.isErr()) {
    return Response.json({ message: "Internal Server Error" }, { status: 500 });
  }

  const fileContent = fileContentResult.value;

  // prepare response data
  const responseData: any = {
    file_content: fileContent,
  };

  // If this is shared access, include the shared access data for decryption
  if (sharedAccess) {
    responseData.shared_access = {
      encrypted_fek: sharedAccess.encrypted_fek.toString("base64"),
      encrypted_fek_nonce: sharedAccess.encrypted_fek_nonce.toString("base64"),
      pre_quantum_secret_part:
        sharedAccess.pre_quantum_secret_part.toString("base64"),
      post_quantum_secret_part:
        sharedAccess.post_quantum_secret_part.toString("base64"),
    };
  }

  return Response.json(responseData, { status: 200 });
}
