import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import svgr from "vite-plugin-svgr";
import { visualizer } from "rollup-plugin-visualizer";

const __dirname = path.resolve();

export default defineConfig({
  plugins: [
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
