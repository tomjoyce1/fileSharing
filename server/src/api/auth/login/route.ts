// src/api/auth/login/route.ts
import { z } from "zod";
import { Username, HexString } from "~/utils/schema";
import { eq } from "drizzle-orm";
import { db } from "~/db";
import { usersTable } from "~/db/schema";
import crypto from "node:crypto";
import { BurgerRequest } from "burger-api";
import { fromPromise } from "neverthrow";

export const schema = {
  post: {
    body: z.object({
      username: Username,
      password_hash: HexString.describe("Client-derived hash").max(256),
    }),
  },
};

const MIN_PROCESS_MS = 100;

/** Constant-time hex comparison, returns false on any error */
function timingSafeHexCompare(a: string, b: string): boolean {
  try {
    // If lengths differ, this still throws inside timingSafeEqual
    return crypto.timingSafeEqual(
      Buffer.from(a, "hex"),
      Buffer.from(b, "hex")
    );
  } catch {
    return false;
  }
}

export async function POST(
  req: BurgerRequest<{ body: z.infer<typeof schema.post.body> }>
) {
  const start = Date.now();

  // 1. Generic 500 on missing validation
  if (!req.validated?.body) {
    return Response.json(
      { message: "Internal server error" },
      { status: 500 }
    );
  }

  const { username, password_hash } = req.validated.body;

  // 2. Wrap DB fetch in neverthrow
  const rowResult = await fromPromise(
    db
      .select({ storedHash: usersTable.password_hash })
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

  // 3. Constant-time path for existing vs missing user
  const fallback = crypto.randomBytes(32).toString("hex");
  const storedHash = rowResult.value?.storedHash ?? fallback;

  const isValid = timingSafeHexCompare(password_hash, storedHash);

  const elapsed = Date.now() - start;
  if (elapsed < MIN_PROCESS_MS) {
    await new Promise((r) => setTimeout(r, MIN_PROCESS_MS - elapsed));
  }

  if (!isValid) {
    return Response.json(
      { message: "Invalid credentials" },
      { status: 401 }
    );
  }

  // 4. Success: 200 with no 'ok' flag
  return Response.json(
    { message: "Authenticated" },
    { status: 200 }
  );
}
