import { defineConfig } from "drizzle-kit";

export default defineConfig({
  out: "./drizzle",
  schema: "./src/db/schema.ts",
  dialect: "sqlite",
  dbCredentials: {
    url: `file:${process.env.DB_FILE_NAME!}`,
  },
  verbose: true,
  strict: true,
});
