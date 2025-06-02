import { z } from "zod";
import { Username } from "~/utils/schema";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { usersTable } from "~/db/schema";
import { ok, err, Result } from "neverthrow";
import { eq } from "drizzle-orm";
import { getAuthenticatedUserFromRequest } from "~/utils/crypto/NetworkingHelper";

export const schema = {
  post: {
    body: z
      .object({
        username: Username,
      })
      .strict(),
  },
};

async function getUserKeyBundle(
  username: string
): Promise<Result<any, string>> {
  try {
    const user = await db
      .select({
        public_key_bundle: usersTable.public_key_bundle,
      })
      .from(usersTable)
      .where(eq(usersTable.username, username))
      .limit(1)
      .then((rows) => rows[0]);

    if (!user) {
      return err("Invalid username");
    }

    const keyBundle = JSON.parse(user.public_key_bundle.toString());
    return ok(keyBundle);
  } catch (error) {
    return err("Failed to retrieve key bundle");
  }
}

export async function POST(
  req: BurgerRequest<{ body: z.infer<typeof schema.post.body> }>
) {
  // Validation somehow was skipped
  // (should not happen, but recommended by docs)
  if (!req.validated?.body) {
    return Response.json(
      {
        message: "Internal Server Error - validation failed",
      },
      { status: 500 }
    );
  }

  const { username } = req.validated.body;

  // authenticate user and verify request signature
  const userResult = await getAuthenticatedUserFromRequest(
    req,
    JSON.stringify(req.validated.body)
  );
  if (userResult.isErr()) {
    return Response.json({ message: "Unauthorized c" }, { status: 401 });
  }

  const result = await getUserKeyBundle(username);

  if (result.isErr()) {
    if (result.error === "Invalid username") {
      return Response.json({ message: "Invalid username" }, { status: 400 });
    }

    return Response.json({ message: "Internal Server Error" }, { status: 500 });
  }

  return Response.json(
    {
      key_bundle: result.value,
    },
    { status: 200 }
  );
}
