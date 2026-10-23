import { QueryClient } from "@tanstack/react-query";

const isDevVal = import.meta.env.MODE === "development";

export function isDev(): boolean {
  return isDevVal;
}

let __domain: string | undefined;

export const getDomain = (): string => {
  if (isDev()) {
    return window.location.host;
  }

  if (__domain) {
    return __domain;
  }

  const domain = window.__OCTELIUM_GLOBALS__?.cluster?.domain;
  if (typeof domain !== "string" || domain.length === 0) {
    throw new Error("The cluster domain is unavailable");
  }

  __domain = domain;

  return __domain;
};

export const getPortalURL = (): string => {
  if (isDev()) {
    return import.meta.env.VITE_PORTAL_URL || window.location.origin;
  }

  return `https://portal.${getDomain()}`;
};

const appCallbackProtocol = "com.octelium.client:";
const appCallbackPath = "/callback/success";

export const getSafeRedirectURL = (value: string): string => {
  const url = new URL(value, window.location.origin);
  if (url.protocol === appCallbackProtocol) {
    if (url.host !== "" || url.pathname !== appCallbackPath) {
      throw new Error("Invalid app callback URL");
    }
    return value;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Unsupported redirect URL protocol");
  }
  return value;
};

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30000,
    },
  },
});
