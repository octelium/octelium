import { Metadata } from "@octelium/apis/main/metav1";
import { QueryClient } from "@tanstack/react-query";
import { queryRetryDelay, retryQuery } from "./queryPolicy";

const isDevVal = import.meta.env.MODE === "development";

export function isDev(): boolean {
  return isDevVal;
}

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30000,
      retry: retryQuery,
      retryDelay: queryRetryDelay,
    },
  },
});

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

export const getPortalURL = (path: string): string => {
  if (isDev()) {
    return `${window.location.origin}${path}`;
  }
  return `https://${getDomain()}${path}`;
};

export const printResourceNameWithDisplay = (arg: Metadata) => {
  return arg.displayName ? `${arg.name} (${arg.displayName})` : arg.name;
};

export const tokenizeQuery = (query: string): string[] =>
  query.trim().toLowerCase().split(/\s+/).filter(Boolean);

export const matchesAllTokens = (haystack: string, tokens: string[]): boolean =>
  tokens.every((token) => haystack.includes(token));
