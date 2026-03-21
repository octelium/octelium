import "@mantine/core/styles.css";
import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";

import { Provider } from "react-redux";
import { RouterProvider } from "react-router-dom";

import store from "@/store";

import router from "@/router";
import { queryClient } from "@/utils";
import theme from "@/utils/theme";
import { MantineProvider } from "@mantine/core";
import { QueryClientProvider } from "@tanstack/react-query";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <MantineProvider theme={theme}>
      <Provider store={store}>
        <QueryClientProvider client={queryClient}>
          <RouterProvider router={router()} />
        </QueryClientProvider>
      </Provider>
    </MantineProvider>
  </React.StrictMode>,
);
