import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import svgr from "vite-plugin-svgr";
import { visualizer } from "rollup-plugin-visualizer";

import { readFile } from "fs/promises";

const __dirname = path.resolve();

const mantineShadowDomFix = () => ({
  name: "mantine-shadow-dom-fix",
  enforce: "pre" as const,
  async load(id: string) {
    if (
      id.includes("@mantine/core/") &&
      id.endsWith("/find-element-in-shadow-dom.mjs")
    ) {
      return readFile(
        path.resolve(
          __dirname,
          "src/utils/mantine/find-element-in-shadow-dom.js",
        ),
        "utf8",
      );
    }
  },
});

export default defineConfig({
  plugins: [
    mantineShadowDomFix(),
    react(),
    svgr(),
    ...(process.env.ANALYZE === "true"
      ? [visualizer({ emitFile: true, filename: "tmp/stats.html" })]
      : []),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  optimizeDeps: {
    rolldownOptions: { plugins: [mantineShadowDomFix()] },
  },

  build: {
    manifest: true,
  },

  server: {
    proxy: {
      "/octelium.api": {
        target: "http://127.0.0.1:10003",
        // changeOrigin: true,
        // secure: false,
        // proxyTimeout: 5000,
        headers: {
          "x-octelium": "octelium",
          "content-type": "application/grpc-web-text+proto",
        },
      },
    },
  },
});
