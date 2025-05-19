import { Burger } from "burger-api";

// Create a new Burger instance
const burger = new Burger({
  // --- Required ---
  apiDir: "src/api",

  // --- Optional but Recommended ---
  title: "PacketSniffers File Store API",
  version: process.env.API_VERSION!,

  // --- Other Optional Settings ---
  apiPrefix: "api",
  description: "An amazing API built with BurgerAPI",
  debug: process.env.NODE_ENV === "development",
});

burger.serve(Number(process.env.PORT!));
