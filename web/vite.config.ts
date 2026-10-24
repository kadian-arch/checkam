import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const api = process.env.CHECKAM_API ?? "http://localhost:8000";
const routes = ["/check", "/run", "/auth", "/analyst", "/alerts", "/traces", "/health"];

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, host: true, proxy: Object.fromEntries(routes.map((r) => [r, api])) },
});
