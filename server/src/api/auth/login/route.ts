import { z } from "zod";
import { HexString, Username } from "~/utils/schema";
import { eq } from "drizzle-orm";
import { db } from "~/db";
import { usersTable } from "~/db/schema";
import crypto from "node:crypto";
import { BurgerRequest } from "burger-api";
import { ok, err, ResultAsync, fromPromise } from "neverthrow";

export const schema = {
  post: {
    body: z.object({
      username: Username,
      password_hash: HexString.max(256),
    }),
  },
};

function timingSafeEqualHex(a: string, b: string): boolean {
  // If lengths differ, TSE throws → normalise first
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}

export async function POST(
  req: BurgerRequest<{ body: z.infer<typeof schema.post.body> }>
) {
  if (!req.validated?.body)
    return Response.json({ message: "Validation skipped" }, { status: 500 });

  const { username, password_hash } = req.validated.body;

  // fetch stored hash
  const row = await db
    .select({ storedHash: usersTable.password_hash })
    .from(usersTable)
    .where(eq(usersTable.username, username))
    .get();

  // Always run constant-time compare to reduce timing oracle
  const storedHash = row?.storedHash ?? crypto.randomBytes(32).toString("hex");
  const okLogin = timingSafeEqualHex(password_hash, storedHash);

  if (!okLogin)
    return Response.json({ message: "Invalid credentials" }, { status: 401 });

  // TODO: issue JWT or cookie; placeholder for now
  return Response.json({ ok: true, message: "Authenticated" });
}
