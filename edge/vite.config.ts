import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri requires a fixed dev server port and disables HMR over the network
// for security. Build output goes to dist/ and is consumed by the Rust side
// via tauri.conf.json's build.frontendDist.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: false,
  },
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    target: "es2022",
    sourcemap: true,
  },
});
