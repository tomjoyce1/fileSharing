import { z } from "zod";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { filesTable } from "~/db/schema";
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

async function checkFileOwnership(
  user_id: number,
  file_id: number
): Promise<Result<any, string>> {
  try {
    // Check if user owns the file
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

    if (!fileRecord) {
      return err("File not found or access denied");
    }

    return ok(fileRecord);
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

  // Check if user owns the file
  const fileResult = await checkFileOwnership(user.user_id, file_id);
  if (fileResult.isErr()) {
    return Response.json({ message: "File not found" }, { status: 404 });
  }

  const file = fileResult.value;

  // Read file content from disk
  const fileContentResult = readFileContent(file.storage_path);
  if (fileContentResult.isErr()) {
    return Response.json({ message: "Internal Server Error" }, { status: 500 });
  }

  const fileContent = fileContentResult.value;

  return Response.json(
    {
      file_content: fileContent,
    },
    { status: 200 }
  );
}
