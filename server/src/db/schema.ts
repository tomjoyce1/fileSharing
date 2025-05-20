import { sql } from "drizzle-orm";
import {
  sqliteTable,
  text,
  integer,
  blob,
  uniqueIndex,
  index,
} from "drizzle-orm/sqlite-core";

// -----------------------------------------------------
// Table `Users`
// Stores user authentication details and their raw public identity key.
// -----------------------------------------------------
export const usersTable = sqliteTable("Users", {
  user_id: integer("user_id").primaryKey({ autoIncrement: true }),
  username: text("username").notNull().unique(),

  password_hash: text("password_hash").notNull(),
  password_salt: text("password_salt").notNull(),

  // The user's raw public identity key (CRYSTALS-Kyber public key).
  // Stored as raw bytes. Drizzle handles this as Uint8Array with Bun's SQLite.
  user_public_key: blob("user_public_key", { mode: "buffer" }).notNull(),

  // Salt used with Argon2id (client-side) to derive the key that encrypts
  // the user's actual Kyber private key (which is stored only client-side).
  client_sk_protection_salt: text("client_sk_protection_salt")
    .notNull()
    .unique(),

  created_at: integer("created_at", { mode: "timestamp" })
    .notNull()
    .default(sql`(strftime('%s', 'now'))`),
  updated_at: integer("updated_at", { mode: "timestamp" })
    .notNull()
    .default(sql`(strftime('%s', 'now'))`)
    .$onUpdate(() => sql`(strftime('%s', 'now'))`),
});

// -----------------------------------------------------
// Table `Files`
// Stores metadata about each encrypted file.
// -----------------------------------------------------
export const filesTable = sqliteTable(
  "Files",
  {
    file_id: integer("file_id").primaryKey({ autoIncrement: true }),
    owner_user_id: integer("owner_user_id")
      .notNull()
      .references(() => usersTable.user_id, {
        onDelete: "cascade",
        onUpdate: "cascade",
      }),
    storage_path: text("storage_path").notNull().unique(),
    encrypted_original_filename: blob("encrypted_original_filename", {
      mode: "buffer",
    }).notNull(),
    filename_encryption_iv: text("filename_encryption_iv").notNull(),
    file_content_auth_tag: blob("file_content_auth_tag", {
      mode: "buffer",
    }).notNull(),
    file_size_bytes: integer("file_size_bytes").notNull(),
    upload_timestamp: integer("upload_timestamp", { mode: "timestamp" })
      .notNull()
      .default(sql`(strftime('%s', 'now'))`),
  },
  (table) => ({
    ownerUserIdx: index("fk_Files_Owner_Users_idx").on(table.owner_user_id),
  })
);

// -----------------------------------------------------
// Table `User_File_Access`
// Manages which user has access to which file and the encrypted DEK for that access.
// -----------------------------------------------------
export const userFileAccessTable = sqliteTable(
  "User_File_Access",
  {
    access_id: integer("access_id").primaryKey({ autoIncrement: true }),
    user_id: integer("user_id")
      .notNull()
      .references(() => usersTable.user_id, {
        onDelete: "cascade",
        onUpdate: "cascade",
      }),
    file_id: integer("file_id")
      .notNull()
      .references(() => filesTable.file_id, {
        onDelete: "cascade",
        onUpdate: "cascade",
      }),

    kyber_encapsulated_key: blob("kyber_encapsulated_key", {
      mode: "buffer",
    }).notNull(), // 'C' from Kyber.Encaps
    encrypted_dek_with_shared_secret: blob("encrypted_dek_with_shared_secret", {
      mode: "buffer",
    }).notNull(), // DEK encrypted by SharedSecret 'SS'
    dek_encryption_iv: text("dek_encryption_iv").notNull(),

    shared_by_user_id: integer("shared_by_user_id").references(
      () => usersTable.user_id,
      { onDelete: "set null", onUpdate: "cascade" }
    ),

    access_granted_at: integer("access_granted_at", { mode: "timestamp" })
      .notNull()
      .default(sql`(strftime('%s', 'now'))`),
  },
  (table) => ({
    uqUserFileAccess: uniqueIndex("uq_user_file_access_idx").on(
      table.user_id,
      table.file_id
    ),

    userIdx: index("fk_UFA_Users_idx").on(table.user_id),
    fileIdx: index("fk_UFA_Files_idx").on(table.file_id),
    sharedByIdx: index("fk_UFA_SharedBy_idx").on(table.shared_by_user_id),
  })
);
