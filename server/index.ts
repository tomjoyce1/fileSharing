console.log("Hello via Bun!");

import { db } from "./src/db";
import { usersTable } from "./src/db/schema";

console.log(await db.select().from(usersTable));
