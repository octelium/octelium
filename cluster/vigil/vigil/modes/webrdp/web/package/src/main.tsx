import "@fontsource/ubuntu/latin-400.css";
import "@fontsource/ubuntu/latin-500.css";
import "@fontsource/ubuntu/latin-700.css";
import React from "react";
import ReactDOM from "react-dom/client";
import { MantineProvider, createTheme } from "@mantine/core";
import { Notifications } from "@mantine/notifications";

import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import "./index.css";

import { App, AppErrorBoundary } from "./App";

const theme = createTheme({
  primaryColor: "dark",
  autoContrast: true,
  defaultRadius: "md",
  fontFamily: "Ubuntu, sans-serif",
});

const root = document.getElementById("root");
if (!root) {
  throw new Error("The application root element is missing.");
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="dark">
      <Notifications position="top-right" zIndex={1000} />
      <AppErrorBoundary>
        <App />
      </AppErrorBoundary>
    </MantineProvider>
  </React.StrictMode>
);
