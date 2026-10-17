import { rpcErrorCode } from "./rpcError";

const NON_RETRYABLE_CODES = new Set([
  "ABORTED",
  "CANCELLED",
  "CANCELED",
  "FAILED_PRECONDITION",
  "INVALID_ARGUMENT",
  "NOT_FOUND",
  "PERMISSION_DENIED",
  "RESOURCE_EXHAUSTED",
  "UNAUTHENTICATED",
  "UNIMPLEMENTED",
]);

export const retryQuery = (failureCount: number, error: unknown) =>
  failureCount < 2 &&
  (error as { name?: string })?.name !== "AbortError" &&
  !NON_RETRYABLE_CODES.has(rpcErrorCode(error) ?? "");

export const queryRetryDelay = (attempt: number) =>
  Math.min(1000 * 2 ** attempt, 30_000) * (0.5 + Math.random() * 0.5);
