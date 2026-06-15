import react from "@vitejs/plugin-react-swc";
import path from "path";
import { visualizer } from "rollup-plugin-visualizer";
import { defineConfig } from "vite";
import svgr from "vite-plugin-svgr";

import type { RollupCommonJSOptions } from "@rollup/plugin-commonjs";
import { createRequire } from "module";

const require = createRequire(import.meta.url);

const __dirname = path.resolve();

export default defineConfig({
  plugins: [
    react(),
    svgr(),
    visualizer({
      emitFile: true,
      filename: "tmp/stats.html",
    }),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  build: {
    manifest: true,
    commonjsOptions: {
      defaultIsModuleExports(id) {
        try {
          const module = require(id);
          if (module?.default) {
            return false;
          }
          return "auto";
        } catch (error) {
          return "auto";
        }
      },
      transformMixedEsModules: true,
    } as RollupCommonJSOptions,
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
