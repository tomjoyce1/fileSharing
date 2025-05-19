import { z } from "zod";
import { Username, HexString, Base64String } from "~/utils/schema";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { usersTable } from "~/db/schema";
import { base64ToBuffer } from "~/utils/common";
import { ok, err, ResultAsync, fromPromise } from "neverthrow";

export const schema = {
  post: {
    body: z.object({
      username: Username,

      // SRP params
      password_auth_salt: HexString.describe("SRP salt (s), hex encoded").max(
        64
      ),
      password_auth_verifier: HexString.describe(
        "SRP verifier (v), hex encoded"
      ).max(64),

      user_public_key: Base64String.describe(
        "User's Kyber public key, base64 encoded"
      ).max(512),
      client_sk_protection_salt: HexString.describe(
        "Salt for client-side SK protection, hex encoded"
      ).max(64),
    }),
  },
};

async function registerUser(
  username: string,
  password_auth_salt: string,
  password_auth_verifier: string,
  user_public_key: Buffer,
  client_sk_protection_salt: string
): Promise<ResultAsync<void, Error>> {
  const insertData = {
    username,
    password_auth_salt,
    password_auth_verifier,
    user_public_key,
    client_sk_protection_salt,
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
  if (!req.validated?.body) {
    return Response.json(
      {
        message: "Internal Server Error",
      },
      { status: 500 }
    );
  }

  const {
    username,
    password_auth_salt,
    password_auth_verifier,
    user_public_key,
    client_sk_protection_salt,
  } = req.validated.body;

  // attempt to decode the public key
  let decodedPublicKey;
  try {
    decodedPublicKey = base64ToBuffer(user_public_key);
  } catch (error) {
    return Response.json(
      {
        message: "Invalid public key",
      },
      {
        status: 400,
      }
    );
  }

  const registerResult = await registerUser(
    username,
    password_auth_salt,
    password_auth_verifier,
    decodedPublicKey,
    client_sk_protection_salt
  );
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
    { status: 200 }
  );
}
