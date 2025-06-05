import { z } from "zod";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { sharedAccessTable, filesTable, usersTable } from "~/db/schema";
import { getAuthenticatedUserFromRequest } from "~/utils/crypto/NetworkingHelper";
import { Username, type APIError } from "~/utils/schema";
import { ok, err, Result } from "neverthrow";
import { eq, and } from "drizzle-orm";

export const schema = {
  post: {
    body: z
      .object({
        file_id: z
          .number()
          .int()
          .positive("File ID must be a positive integer"),
        username: Username,
      })
      .strict(),
  },
};

// checks if the user owns the file with the given file_id
async function doesOwnFile(
  file_id: number,
  owner_user_id: number
): Promise<Result<boolean, APIError>> {
  try {
    const file = await db
      .select({ owner_user_id: filesTable.owner_user_id })
      .from(filesTable)
      .where(eq(filesTable.file_id, file_id))
      .limit(1)
      .then((rows) => rows[0]);
    if (!file) {
      return err({ message: "Unknown file", status: 400 });
    }

    if (file.owner_user_id !== owner_user_id) {
      return err({ message: "Unauthorized", status: 403 });
    }

    return ok(true);
  } catch (error) {
    return err({ message: "Internal Server Error", status: 500 });
  }
}
// retrieves the user ID for a given username
async function getUserId(username: string): Promise<Result<number, APIError>> {
  try {
    const user = await db
      .select({ user_id: usersTable.user_id })
      .from(usersTable)
      .where(eq(usersTable.username, username))
      .limit(1)
      .then((rows) => rows[0]);
    if (!user) {
      return err({ message: "Unknown user", status: 400 });
    }

    return ok(user.user_id);
  } catch (error) {
    return err({ message: "Internal Server Error", status: 500 });
  }
}

// checks if a share record exists for the given owner, shared user, and file
async function findShareRecord(
  owner_user_id: number,
  shared_with_user_id: number,
  file_id: number
): Promise<Result<number | null, APIError>> {
  try {
    const shareRecord = await db
      .select({ access_id: sharedAccessTable.access_id })
      .from(sharedAccessTable)
      .where(
        and(
          eq(sharedAccessTable.owner_user_id, owner_user_id),
          eq(sharedAccessTable.shared_with_user_id, shared_with_user_id),
          eq(sharedAccessTable.file_id, file_id)
        )
      )
      .limit(1)
      .then((rows) => rows[0]);

    return ok(shareRecord?.access_id ?? null);
  } catch (error) {
    return err({ message: "Internal Server Error", status: 500 });
  }
}

// deletes the share record for the given owner, shared user, and file
async function deleteShareRecord(
  owner_user_id: number,
  shared_with_user_id: number,
  file_id: number
): Promise<Result<void, APIError>> {
  try {
    const result = await db
      .delete(sharedAccessTable)
      .where(
        and(
          eq(sharedAccessTable.owner_user_id, owner_user_id),
          eq(sharedAccessTable.shared_with_user_id, shared_with_user_id),
          eq(sharedAccessTable.file_id, file_id)
        )
      )
      .returning({ access_id: sharedAccessTable.access_id });

    if (result.length === 0) {
      return err({ message: "Internal Server Error", status: 500 });
    }

    return ok();
  } catch (error) {
    return err({ message: "Internal Server Error", status: 500 });
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

  const owner = userResult.value;

  // validate file ownership
  const { file_id, username } = req.validated.body;
  const ownershipResult = await doesOwnFile(file_id, owner.user_id);
  if (ownershipResult.isErr()) {
    const apiError = ownershipResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  // get the user ID for the username we're revoking access from
  const userIdResult = await getUserId(username);
  if (userIdResult.isErr()) {
    const apiError = userIdResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }
  const shared_with_user_id = userIdResult.value;

  // check if user is trying to revoke access from themselves
  if (owner.user_id === shared_with_user_id) {
    return Response.json(
      { message: "Cannot revoke access from self" },
      { status: 400 }
    );
  }

  // check if share record exists
  const shareRecordResult = await findShareRecord(
    owner.user_id,
    shared_with_user_id,
    file_id
  );
  if (shareRecordResult.isErr()) {
    const apiError = shareRecordResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }
  if (shareRecordResult.value === null) {
    return Response.json(
      { message: "File is not shared with this user" },
      { status: 404 }
    );
  }

  // Delete the share record
  const deleteResult = await deleteShareRecord(
    owner.user_id,
    shared_with_user_id,
    file_id
  );
  if (deleteResult.isErr()) {
    const apiError = deleteResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  return Response.json(
    {
      message: "File access revoked successfully",
    },
    { status: 200 }
  );
}
