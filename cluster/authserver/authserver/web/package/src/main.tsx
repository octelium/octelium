import React from "react";
import ReactDOM from "react-dom/client";
import "@mantine/core/styles.css";
import "./index.css";

import { RouterProvider } from "react-router-dom";

import router from "@/router";
import theme from "@/utils/theme";
import { QueryClientProvider } from "@tanstack/react-query";
import { MantineProvider } from "@mantine/core";
import { queryClient } from "./utils";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <MantineProvider theme={theme}>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router()} />
      </QueryClientProvider>
    </MantineProvider>
  </React.StrictMode>
);
