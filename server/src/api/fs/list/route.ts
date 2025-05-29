import { z } from "zod";
import { BurgerRequest } from "burger-api";
import { db } from "~/db";
import { filesTable, sharedAccessTable } from "~/db/schema";
import { getAuthenticatedUserFromRequest } from "~/utils/crypto/NetworkingHelper";
import type { FileMetadataListItem } from "~/utils/schema";
import { ok, err, Result } from "neverthrow";
import { sql } from "drizzle-orm";

const PAGE_SIZE = 25;

export const schema = {
  post: {
    body: z
      .object({
        page: z.number().int().min(1).default(1),
      })
      .strict(),
  },
};

async function getAccessibleFiles(
  user_id: number,
  page: number
): Promise<
  Result<{ files: FileMetadataListItem[]; hasNextPage: boolean }, string>
> {
  try {
    const offset = (page - 1) * PAGE_SIZE;

    // Use UNION ALL to combine owned and shared files, then apply ordering and pagination
    const query = sql`
      SELECT
        f.file_id,
        f.metadata,
        f.pre_quantum_signature,
        f.post_quantum_signature,
        f.upload_timestamp,
        1 as is_owner,
        NULL as encrypted_fek,
        NULL as encrypted_fek_salt,
        NULL as encrypted_fek_nonce,
        NULL as encrypted_mek,
        NULL as encrypted_mek_salt,
        NULL as encrypted_mek_nonce
      FROM ${filesTable} f
      WHERE f.owner_user_id = ${user_id}

      UNION ALL

      SELECT
        f.file_id,
        f.metadata,
        f.pre_quantum_signature,
        f.post_quantum_signature,
        f.upload_timestamp,
        0 as is_owner,
        sa.encrypted_fek,
        sa.encrypted_fek_salt,
        sa.encrypted_fek_nonce,
        sa.encrypted_mek,
        sa.encrypted_mek_salt,
        sa.encrypted_mek_nonce
      FROM ${sharedAccessTable} sa
      INNER JOIN ${filesTable} f ON sa.file_id = f.file_id
      WHERE sa.shared_with_user_id = ${user_id}

      ORDER BY file_id DESC
      LIMIT ${PAGE_SIZE + 1}
      OFFSET ${offset}
    `;

    const results = await db.all(query);
    const hasNextPage = results.length > PAGE_SIZE;
    const files = hasNextPage ? results.slice(0, PAGE_SIZE) : results;

    // format response
    const fileList: FileMetadataListItem[] = files.map((row: any) => {
      const baseFile: FileMetadataListItem = {
        file_id: row.file_id,
        metadata: Buffer.from(row.metadata).toString("base64"),
        pre_quantum_signature: Buffer.from(row.pre_quantum_signature).toString(
          "base64"
        ),
        post_quantum_signature: Buffer.from(
          row.post_quantum_signature
        ).toString("base64"),
        is_owner: Boolean(row.is_owner),
      };

      // Add shared access data if this is a shared file
      if (!row.is_owner && row.encrypted_fek) {
        baseFile.shared_access = {
          encrypted_fek: Buffer.from(row.encrypted_fek).toString("base64"),
          encrypted_fek_salt: Buffer.from(row.encrypted_fek_salt).toString(
            "base64"
          ),
          encrypted_fek_nonce: Buffer.from(row.encrypted_fek_nonce).toString(
            "base64"
          ),
          encrypted_mek: Buffer.from(row.encrypted_mek).toString("base64"),
          encrypted_mek_salt: Buffer.from(row.encrypted_mek_salt).toString(
            "base64"
          ),
          encrypted_mek_nonce: Buffer.from(row.encrypted_mek_nonce).toString(
            "base64"
          ),
        };
      }

      return baseFile;
    });

    return ok({ files: fileList, hasNextPage });
  } catch (error) {
    return err("Database error");
  }
}

export async function POST(
  req: BurgerRequest<{ body: z.infer<typeof schema.post.body> }>
) {
  if (!req.validated?.body) {
    return Response.json({ message: "Internal Server Error" }, { status: 500 });
  }

  // authenticate user
  const { page } = req.validated.body;
  const userResult = await getAuthenticatedUserFromRequest(
    req,
    JSON.stringify(req.validated.body)
  );
  if (userResult.isErr()) {
    return Response.json({ message: "Unauthorized" }, { status: 401 });
  }

  // get accessible files with page-based pagination
  const user = userResult.value;
  const filesResult = await getAccessibleFiles(user.user_id, page);
  if (filesResult.isErr()) {
    return Response.json({ message: "Internal Server Error" }, { status: 500 });
  }

  const { files, hasNextPage } = filesResult.value;

  return Response.json(
    {
      fileData: files,
      hasNextPage,
    },
    { status: 200 }
  );
}
