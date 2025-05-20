import { eq } from "drizzle-orm";
import { db } from "~/db";
import { usersTable } from "~/db/schema";
import crypto from "node:crypto";
import { BurgerRequest } from "burger-api";

function deterministicFakeSalt(username: string): string {
  // Use a server-side “pepper” so two servers give the same answer.
  const pepper = Bun.env.SALT_PEPPER ?? "default-pepper-change-me";
  return crypto
    .createHmac("sha256", pepper)
    .update(username.toLowerCase())      // case-insensitive usernames
    .digest("hex")
    .slice(0, 64);                       // 32-byte salt → 64 hex chars
}

/** GET /api/auth/salt?username=alice */
export async function GET(req: BurgerRequest) {
  // Convert the raw URL string to a URL object
  const { searchParams } = new URL(req.url);
  const username = searchParams.get("username") ?? "";

  const row = await db
    .select({ salt: usersTable.password_salt })
    .from(usersTable)
    .where(eq(usersTable.username, username))
    .get();

  const salt = row?.salt ?? deterministicFakeSalt(username);
  return Response.json({ salt });
}

