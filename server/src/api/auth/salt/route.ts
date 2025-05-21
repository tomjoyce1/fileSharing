// src/api/auth/salt/route.ts
import { z } from "zod";
import { Username } from "~/utils/schema";
import { eq } from "drizzle-orm";
import { db } from "~/db";
import { usersTable } from "~/db/schema";
import crypto from "node:crypto";
import { BurgerRequest } from "burger-api";
import { fromPromise } from "neverthrow";

export const schema = {
  get: {
    query: z.object({
      username: Username.describe("The username to look up"),
    }),
  },
};

function deterministicFakeSalt(username: string): string {
  const pepper = process.env.SALT_PEPPER ?? "default-pepper-change-me";
  return crypto
    .createHmac("sha256", pepper)
    .update(username.toLowerCase())
    .digest("hex")
    .slice(0, 64);
}

const MIN_PROCESS_MS = 100;

export async function GET(
  req: BurgerRequest<{ query: z.infer<typeof schema.get.query> }>
) {
  const start = Date.now();

  // 1. Return 400 if username missing (Zod middleware would also catch it)
  if (!req.validated?.query) {
    return Response.json(
      { message: "Missing username" },
      { status: 400 }
    );
  }

  const { username } = req.validated.query;

  // 2. Wrap DB lookup in neverthrow
  const rowResult = await fromPromise(
    db
      .select({ salt: usersTable.password_salt })
      .from(usersTable)
      .where(eq(usersTable.username, username))
      .get(),
    (e) => (e instanceof Error ? e : new Error(String(e)))
  );

  if (rowResult.isErr()) {
    return Response.json(
      { message: "Internal server error" },
      { status: 500 }
    );
  }

  // 3. Compute salt (real or fake) and defend against timing oracles
  const salt = rowResult.value?.salt ?? deterministicFakeSalt(username);

  const elapsed = Date.now() - start;
  if (elapsed < MIN_PROCESS_MS) {
    await new Promise((r) => setTimeout(r, MIN_PROCESS_MS - elapsed));
  }

  // 4. Return 200 with JSON body only
  return Response.json(
    { salt },
    { status: 200 }
  );
}
