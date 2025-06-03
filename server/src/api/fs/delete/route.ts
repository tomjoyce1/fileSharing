import { z } from "zod";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { filesTable } from "~/db/schema";
import { getAuthenticatedUserFromRequest } from "~/utils/crypto/NetworkingHelper";
import type { APIError } from "~/utils/schema";
import { ok, err, Result } from "neverthrow";
import { eq } from "drizzle-orm";
import { existsSync, unlinkSync } from "node:fs";

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

async function getStoragePathAndVerifyFileOwnership(
  file_id: number,
  user_id: number
): Promise<Result<{ storage_path: string }, APIError>> {
  try {
    const file = await db
      .select({
        owner_user_id: filesTable.owner_user_id,
        storage_path: filesTable.storage_path,
      })
      .from(filesTable)
      .where(eq(filesTable.file_id, file_id))
      .limit(1)
      .then((rows) => rows[0]);

    if (!file) {
      return err({ message: "Unknown file", status: 400 });
    }

    if (file.owner_user_id !== user_id) {
      return err({ message: "Unauthorized", status: 403 });
    }

    return ok({ storage_path: file.storage_path });
  } catch (error) {
    return err({ message: "Internal Server Error", status: 500 });
  }
}

async function deleteFileRecord(
  file_id: number
): Promise<Result<void, APIError>> {
  try {
    const result = await db
      .delete(filesTable)
      .where(eq(filesTable.file_id, file_id))
      .returning({ file_id: filesTable.file_id });

    if (result.length === 0) {
      return err({ message: "Internal Server Error", status: 500 });
    }

    return ok();
  } catch (error) {
    return err({ message: "Internal Server Error", status: 500 });
  }
}

function deletePhysicalFile(storage_path: string): void {
  try {
    if (existsSync(storage_path)) {
      unlinkSync(storage_path);
    }
  } catch (error) {
    // physical file cleanup is best effort - just log
    console.error(`Failed to delete physical file ${storage_path}:`, error);
  }
}

export async function POST(
  req: BurgerRequest<{ body: z.infer<typeof schema.post.body> }>
) {
  if (!req.validated?.body) {
    return Response.json(
      {
        message: "Internal Server Error",
      },
      { status: 500 }
    );
  }

  // authenticate user and verify request signature
  const userResult = await getAuthenticatedUserFromRequest(
    req,
    JSON.stringify(req.validated.body)
  );
  if (userResult.isErr()) {
    return Response.json({ message: "Unauthorized" }, { status: 401 });
  }

  const user = userResult.value;

  // validate file ownership and get storage path
  const { file_id } = req.validated.body;
  const ownershipResult = await getStoragePathAndVerifyFileOwnership(
    file_id,
    user.user_id
  );
  if (ownershipResult.isErr()) {
    const apiError = ownershipResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  const { storage_path } = ownershipResult.value;

  // delete the file record from database
  const deleteFileResult = await deleteFileRecord(file_id);
  if (deleteFileResult.isErr()) {
    const apiError = deleteFileResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  // delete the physical file (best effort)
  deletePhysicalFile(storage_path);

  return Response.json(
    {
      message: "File deleted successfully",
    },
    { status: 200 }
  );
}
