import { Burger } from "burger-api";
import { rateLimit } from "./src/middleware/ratelimit";

// Create a new Burger instance
const burger = new Burger({
  // --- Required ---
  apiDir: "src/api",

  title: "PacketSniffers File Store API",
  version: process.env.API_VERSION!,

  globalMiddleware: [rateLimit],

  apiPrefix: "api", // (so /api/register/route.ts can be accessed as /api/register)
  description: "An amazing API built with BurgerAPI",
  debug: process.env.NODE_ENV === "development",
});

burger.serve(Number(process.env.PORT!));
