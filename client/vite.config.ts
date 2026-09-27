import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// API_URL points the dev proxy at the Go API (http://server:8080 inside compose).
const apiUrl = process.env.API_URL ?? "http://localhost:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: true,
    port: 5173,
    // Bind mounts on WSL2 / Docker Desktop don't reliably emit fs events.
    watch: { usePolling: process.env.VITE_USE_POLLING === "true" },
    proxy: {
      "/api": { target: apiUrl, changeOrigin: true },
    },
  },
});
