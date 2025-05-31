import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import wasm from "vite-plugin-wasm";
import { resolve } from "path";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), wasm()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "./src"),
      "~": resolve(__dirname, "./src"),
      "@components": resolve(__dirname, "./src/components"),
      "@lib": resolve(__dirname, "./src/lib"),
      "@styles": resolve(__dirname, "./src/styles"),
      "@types": resolve(__dirname, "./src/types"),
    },
  },
  optimizeDeps: {
    exclude: ["@noble/post-quantum", "argon2-browser"],
  },
  build: {
    target: "esnext",
    outDir: "dist",
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
      },
    }, 
  },
  server: {
    proxy: {
      "/api": "http://localhost:3001", // Proxy all /api requests to backend
    },
    fs: {
      // Allow serving files from the public directory
      allow: [".."],
    },
  },
  // Configure public directory where argon2.wasm is stored
  publicDir: "public",
});
