import { z } from "zod";
import { Username, KeyBundlePublicSerializable } from "~/utils/schema";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { usersTable } from "~/db/schema";
import { ok, err, ResultAsync, fromPromise } from "neverthrow";
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

async function registerUser(
  username: string,
  key_bundle: z.infer<typeof KeyBundlePublicSerializable>
): Promise<ResultAsync<void, Error>> {
  // const insertData = {
  //   username,
  //   public_key_bundle: Buffer.from(JSON.stringify(key_bundle)),
  // };

  const insertData = {
    username,
    public_key_bundle: JSON.stringify(key_bundle), // ← no Buffer
  };

  const result = await fromPromise(
    db.insert(usersTable).values(insertData),
    (e) => (e instanceof Error ? e : new Error(String(e)))
  );
  if (result.isErr()) {
    return err(result.error);
  }

  return ok(undefined);
}

export async function POST(
  req: BurgerRequest<{ body: z.infer<typeof schema.post.body> }>
) {
  // Validation somehow was skipped
  // (should not happen, but recommended by docs)
  if (!req.validated?.body) {
    return Response.json(
      {
        message: "Internal Server Error wtf not valid",
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
    return Response.json(
      {
        message: "Internal Server Error",
      },
      { status: 500 }
    );
  }

  return Response.json(
    {
      message: "User registered",
    },
    { status: 201 }
  );
}
