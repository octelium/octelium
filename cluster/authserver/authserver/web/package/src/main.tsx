import "@fontsource/ubuntu/latin.css";
import "@mantine/core/styles.css";
import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";

import { RouterProvider } from "react-router-dom";

import router from "@/router";
import theme from "@/utils/theme";
import { MantineProvider } from "@mantine/core";
import { QueryClientProvider } from "@tanstack/react-query";
import { queryClient } from "./utils";

const root = document.getElementById("root");
if (!root) {
  throw new Error("The application root element is missing.");
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <MantineProvider theme={theme}>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router()} />
      </QueryClientProvider>
    </MantineProvider>
  </React.StrictMode>,
);
