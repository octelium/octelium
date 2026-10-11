import { defineConfig } from "playwright/test";

export default defineConfig({
  testDir: "./tests",
  outputDir: "./tmp/playwright",
  use: {
    baseURL: "http://127.0.0.1:4175",
    colorScheme: "light",
  },
  webServer: {
    command: "npm run dev -- --host 127.0.0.1 --port 4175 --strictPort",
    url: "http://127.0.0.1:4175/login",
    reuseExistingServer: false,
  },
});
