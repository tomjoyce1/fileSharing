import { z } from "zod";
import {
  Username,
  KeyBundlePublicSerializable,
  type APIError,
} from "~/utils/schema";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { usersTable } from "~/db/schema";
import { ok, err, Result } from "neverthrow";
import { eq } from "drizzle-orm";

export const schema = {
  post: {
    body: z
      .object({
        username: Username,
        key_bundle: KeyBundlePublicSerializable,
      })
      .strict(),
  },
};

// registers a new user with the provided username and key bundle
async function registerUser(
  username: string,
  key_bundle: z.infer<typeof KeyBundlePublicSerializable>
): Promise<Result<void, APIError>> {
  try {
    const insertData = {
      username,
      public_key_bundle: Buffer.from(JSON.stringify(key_bundle)),
    };

    await db.insert(usersTable).values(insertData);
    return ok(undefined);
  } catch (error) {
    return err({ message: "Internal Server Error", status: 500 });
  }
}

// handles the POST request to register a new user
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

  const { username, key_bundle } = req.validated.body;

  // check if username is already taken
  const existingUser = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.username, username));
  if (existingUser.length > 0) {
    return Response.json(
      { message: "Username already taken" },
      { status: 400 }
    );
  }

  const registerResult = await registerUser(username, key_bundle);
  if (registerResult.isErr()) {
    const apiError = registerResult.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  return Response.json(
    {
      message: "User registered",
    },
    { status: 201 }
  );
}
