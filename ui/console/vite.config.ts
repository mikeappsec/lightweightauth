import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [solidPlugin(), tailwindcss()],
  build: {
    target: "esnext",
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 3000,
    proxy: {
      "/v1/controlplane": {
        target: "http://localhost:8443",
        changeOrigin: true,
      },
    },
  },
});
