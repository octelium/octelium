const messages: Record<string, string> = {
  UNIMPLEMENTED: "This feature is not available on this cluster.",
  PERMISSION_DENIED: "You do not have permission to view this information.",
  UNAUTHENTICATED: "Your session has expired. Sign in again.",
  UNAVAILABLE: "The service is temporarily unavailable. Try again shortly.",
  DEADLINE_EXCEEDED: "The request took too long. Try again.",
  RESOURCE_EXHAUSTED: "The service is busy. Try again shortly.",
  NOT_FOUND: "The requested information could not be found.",
  INVALID_ARGUMENT:
    "The request could not be processed. Check your filters and try again.",
  CANCELLED: "The request was cancelled.",
};

const rpcErrorDetail = (error: unknown) => {
  const value = error as { code?: unknown; message?: unknown } | null;
  return typeof error === "string"
    ? error
    : typeof value?.message === "string"
      ? value.message
      : "";
};

export const rpcErrorCode = (error: unknown): string | undefined => {
  const value = error as { code?: unknown } | null;
  const detail = rpcErrorDetail(error);
  const match = /rpc error:\s*code\s*=\s*(\w+)/i.exec(detail);
  const code = typeof value?.code === "string" ? value.code : match?.[1];
  return code?.replace(/([a-z])([A-Z])/g, "$1_$2").toUpperCase();
};

export const describeRpcError = (error: unknown) => {
  const code = rpcErrorCode(error);

  return {
    message:
      messages[code ?? ""] ??
      "This information could not be loaded. Try again.",
    detail: rpcErrorDetail(error),
    isRpcError: Boolean(code),
  };
};
