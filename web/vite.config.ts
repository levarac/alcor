import { defineConfig } from "vite";

export default defineConfig({
  server: {
    proxy: {
      "/challenge": "http://localhost:8787",
      "/bind": "http://localhost:8787",
      "/verify": "http://localhost:8787",
      "/config": "http://localhost:8787",
      "/rp-context": "http://localhost:8787",
      "/credentials": "http://localhost:8787",
    },
  },
});
