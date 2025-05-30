import { z } from "zod";
import { Username, type APIError } from "~/utils/schema";
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
): Promise<Result<any, APIError>> {
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
      return err({ message: "Internal Server Error", status: 500 });
    }

    const keyBundle = JSON.parse(user.public_key_bundle.toString());
    return ok(keyBundle);
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

  const { username } = req.validated.body;

  // authenticate user and verify request signature
  const userResult = await getAuthenticatedUserFromRequest(
    req,
    JSON.stringify(req.validated.body)
  );
  if (userResult.isErr()) {
    return Response.json({ message: "Unauthorized" }, { status: 401 });
  }

  const result = await getUserKeyBundle(username);

  if (result.isErr()) {
    const apiError = result.error;
    return Response.json(
      { message: apiError.message },
      { status: apiError.status }
    );
  }

  return Response.json(
    {
      key_bundle: result.value,
    },
    { status: 200 }
  );
}
