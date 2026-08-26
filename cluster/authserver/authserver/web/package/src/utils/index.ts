import { QueryClient } from "@tanstack/react-query";

const isDevVal = import.meta.env.MODE === "development";

export function isDev(): boolean {
  return isDevVal;
}

let __domain: string | undefined;

const isValidDomain = (value: string): boolean =>
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?$/i.test(
    value,
  );

export const getDomain = (): string => {
  if (isDev()) {
    return window.location.host;
  }

  if (__domain) {
    return __domain;
  }

  const cookieDomain =
    ("; " + window.document.cookie)
      .split("; octelium_domain=")
      .pop()
      ?.split(";")
      .shift() ?? "";

  try {
    __domain = decodeURIComponent(cookieDomain);
  } catch {
    __domain = "";
  }

  if (!isValidDomain(__domain)) {
    __domain = "";
  }

  return __domain;
};

export const getPortalURL = (): string => {
  if (isDev()) {
    return import.meta.env.VITE_PORTAL_URL || window.location.origin;
  }

  const domain = getDomain();
  return domain ? `https://portal.${domain}` : "/";
};

export const getSafeRedirectURL = (value: string): string => {
  const url = new URL(value, window.location.origin);
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
