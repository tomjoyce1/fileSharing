import { sql } from "drizzle-orm";
import {
  sqliteTable,
  text,
  integer,
  blob,
  uniqueIndex,
  index,
} from "drizzle-orm/sqlite-core";

export const usersTable = sqliteTable("users_table", {
  user_id: integer("user_id").primaryKey({ autoIncrement: true }),
  username: text("username").notNull().unique(),

  // key bundle
  public_key_bundle: blob("public_key_bundle", { mode: "buffer" }).notNull(),

  created_at: integer("created_at", { mode: "timestamp" })
    .notNull()
    .default(sql`(strftime('%s', 'now'))`),
  updated_at: integer("updated_at", { mode: "timestamp" })
    .notNull()
    .default(sql`(strftime('%s', 'now'))`)
    .$onUpdate(() => sql`(strftime('%s', 'now'))`),
});

export const filesTable = sqliteTable(
  "files_table",
  {
    file_id: integer("file_id").primaryKey({ autoIncrement: true }),
    owner_user_id: integer("owner_user_id")
      .notNull()
      .references(() => usersTable.user_id, {
        onDelete: "cascade",
        onUpdate: "cascade",
      }),
    storage_path: text("storage_path").notNull().unique(),

    // encrypted metadata (encrypted with MEK derived from FEK)
    metadata: blob("metadata", { mode: "buffer" }).notNull(),

    // sig for file record
    pre_quantum_signature: blob("pre_quantum_signature", {
      mode: "buffer",
    }).notNull(),
    post_quantum_signature: blob("post_quantum_signature", {
      mode: "buffer",
    }).notNull(),

    upload_timestamp: integer("upload_timestamp", { mode: "timestamp" })
      .notNull()
      .default(sql`(strftime('%s', 'now'))`),
  },
  (table) => ({
    ownerUserIdx: index("fk_Files_Owner_Users_idx").on(table.owner_user_id),
  })
);

export const sharedAccessTable = sqliteTable(
  "shared_access_table",
  {
    access_id: integer("access_id").primaryKey({ autoIncrement: true }),
    owner_user_id: integer("owner_user_id")
      .notNull()
      .references(() => usersTable.user_id, {
        onDelete: "cascade",
        onUpdate: "cascade",
      }),
    shared_with_user_id: integer("shared_with_user_id").references(
      () => usersTable.user_id,
      {
        onDelete: "cascade",
        onUpdate: "cascade",
      }
    ),
    file_id: integer("file_id")
      .notNull()
      .references(() => filesTable.file_id, {
        onDelete: "cascade",
        onUpdate: "cascade",
      }),

    file_content_nonce: blob("file_content_nonce", {
      mode: "buffer",
    }).notNull(),

    metadata_nonce: blob("metadata_nonce", {
      mode: "buffer",
    }).notNull(),

    // Encrypted FEK (for decrypting file content)
    encrypted_fek: blob("encrypted_fek", { mode: "buffer" }).notNull(),
    encrypted_fek_nonce: blob("encrypted_fek_nonce", {
      mode: "buffer",
    }).notNull(),

    // Encrypted MEK (for decrypting metadata)
    encrypted_mek: blob("encrypted_mek", { mode: "buffer" }).notNull(),
    encrypted_mek_nonce: blob("encrypted_mek_nonce", {
      mode: "buffer",
    }).notNull(),

    // Ephemeral public key for ECDH
    ephemeral_public_key: blob("ephemeral_public_key", {
      mode: "buffer",
    }).notNull(),

    shared_at: integer("shared_at", { mode: "timestamp" })
      .notNull()
      .default(sql`(strftime('%s', 'now'))`),
  },
  (table) => ({
    uqUserFileAccess: uniqueIndex("uq_user_file_access_idx").on(
      table.owner_user_id,
      table.shared_with_user_id,
      table.file_id
    ),

    fileIdx: index("fk_UFA_Files_idx").on(table.file_id),
    sharerIdx: index("fk_UFA_Sharer_idx").on(table.owner_user_id),
    shareeIdx: index("fk_UFA_Sharee_idx").on(table.shared_with_user_id),
  })
);
