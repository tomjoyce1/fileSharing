import { z } from "zod";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { sharedAccessTable, filesTable, usersTable } from "~/db/schema";
import { getAuthenticatedUserFromRequest } from "~/utils/crypto/NetworkingHelper";
import { Username, Base64String, type APIError } from "~/utils/schema";
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
        shared_with_username: Username,
        encrypted_fek: Base64String,
        encrypted_fek_nonce: Base64String,
        encrypted_mek: Base64String,
        encrypted_mek_nonce: Base64String,
        ephemeral_public_key: Base64String,
        file_content_nonce: Base64String,
        metadata_nonce: Base64String,
      })
      .strict(),
  },
};

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

async function getSharedWithUserId(
  username: string
): Promise<Result<number, APIError>> {
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

async function checkExistingShare(
  owner_user_id: number,
  shared_with_user_id: number,
  file_id: number
): Promise<Result<boolean, APIError>> {
  try {
    const existingShare = await db
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

    return ok(!!existingShare);
  } catch (error) {
    return err({ message: "Internal Server Error", status: 500 });
  }
}

async function createShareRecord(
  owner_user_id: number,
  shared_with_user_id: number,
  file_id: number,
  shareData: {
    encrypted_fek: string;
    encrypted_fek_nonce: string;
    encrypted_mek: string;
    encrypted_mek_nonce: string;
    ephemeral_public_key: string;
    file_content_nonce: string;
    metadata_nonce: string;
  }
): Promise<Result<number, APIError>> {
  try {
    const result = await db
      .insert(sharedAccessTable)
      .values({
        owner_user_id,
        shared_with_user_id,
        file_id,
        file_content_nonce: Buffer.from(shareData.file_content_nonce, "base64"),
        metadata_nonce: Buffer.from(shareData.metadata_nonce, "base64"),
        encrypted_fek: Buffer.from(shareData.encrypted_fek, "base64"),
        encrypted_fek_nonce: Buffer.from(
          shareData.encrypted_fek_nonce,
          "base64"
        ),
        encrypted_mek: Buffer.from(shareData.encrypted_mek, "base64"),
        encrypted_mek_nonce: Buffer.from(
          shareData.encrypted_mek_nonce,
          "base64"
        ),
        ephemeral_public_key: Buffer.from(
          shareData.ephemeral_public_key,
          "base64"
        ),
      })
      .returning({ access_id: sharedAccessTable.access_id })
      .then((rows) => rows[0]);
    if (!result) {
      return err({ message: "Internal Server Error", status: 500 });
    }

    return ok(result.access_id);
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
  const {
    file_id,
    shared_with_username,
    encrypted_fek,
    encrypted_fek_nonce,
    encrypted_mek,
    encrypted_mek_nonce,
    ephemeral_public_key,
    file_content_nonce,
    metadata_nonce,
  } = req.validated.body;
  const ownershipResult = await doesOwnFile(file_id, owner.user_id);
  if (ownershipResult.isErr()) {
    const apiError = ownershipResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  // get the user ID for the username we're sharing with
  const sharedUserResult = await getSharedWithUserId(shared_with_username);
  if (sharedUserResult.isErr()) {
    const apiError = sharedUserResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }
  const shared_with_user_id = sharedUserResult.value;

  // check if user is trying to share with themselves
  if (owner.user_id === shared_with_user_id) {
    return Response.json(
      { message: "Cannot share file with self" },
      { status: 400 }
    );
  }

  // check if file is already shared with this user
  const existingShareResult = await checkExistingShare(
    owner.user_id,
    shared_with_user_id,
    file_id
  );
  if (existingShareResult.isErr()) {
    const apiError = existingShareResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }
  if (existingShareResult.value) {
    return Response.json(
      { message: "File is already shared with this user" },
      { status: 409 }
    );
  }

  // Create the share record
  const shareResult = await createShareRecord(
    owner.user_id,
    shared_with_user_id,
    file_id,
    {
      encrypted_fek,
      encrypted_fek_nonce,
      encrypted_mek,
      encrypted_mek_nonce,
      ephemeral_public_key,
      file_content_nonce,
      metadata_nonce,
    }
  );
  if (shareResult.isErr()) {
    const apiError = shareResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  return Response.json(
    {
      message: "File shared successfully",
    },
    { status: 201 }
  );
}
