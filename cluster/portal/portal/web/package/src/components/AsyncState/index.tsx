import { Alert, Button, Loader, Skeleton } from "@mantine/core";
import { AlertCircle, Inbox, RefreshCw } from "lucide-react";
import type { ReactNode } from "react";

export const LoadingState = (props: { label?: string }) => (
  <div
    className="flex min-h-[280px] flex-col items-center justify-center gap-3 text-slate-500"
    role="status"
    aria-live="polite"
  >
    <Loader color="dark" size="md" />
    <span className="text-sm font-semibold">{props.label ?? "Loading…"}</span>
  </div>
);

export const ResourceListSkeleton = (props: { count?: number }) => (
  <div
    className="flex w-full flex-col gap-2.5"
    aria-label="Loading resources"
    role="status"
  >
    {Array.from({ length: props.count ?? 5 }, (_, index) => (
      <div
        className="w-full rounded-xl border border-slate-200 bg-white p-4 shadow-xs"
        key={index}
      >
        <div className="flex items-start gap-3">
          <Skeleton height={44} width={44} radius="lg" />
          <div className="flex-1 space-y-2.5 py-0.5">
            <Skeleton height={14} width="34%" />
            <div className="flex gap-2">
              <Skeleton height={18} width={72} radius="sm" />
              <Skeleton height={18} width={96} radius="sm" />
              <Skeleton height={18} width={56} radius="sm" />
            </div>
          </div>
          <Skeleton height={36} width={36} radius="md" />
        </div>
      </div>
    ))}
  </div>
);

export const ErrorState = (props: {
  title?: string;
  message?: string;
  onRetry?: () => void;
}) => (
  <Alert
    color="red"
    icon={<AlertCircle size={18} />}
    title={props.title ?? "Something went wrong"}
    className="my-6"
  >
    <div className="flex flex-wrap items-center gap-3">
      <span>
        {props.message ?? "We could not load this data. Please try again."}
      </span>
      {props.onRetry && (
        <Button
          color="red"
          leftSection={<RefreshCw size={15} />}
          onClick={props.onRetry}
          size="xs"
          variant="outline"
        >
          Try again
        </Button>
      )}
    </div>
  </Alert>
);

export const EmptyState = (props: {
  title: string;
  message?: string;
  icon?: ReactNode;
  action?: ReactNode;
}) => (
  <div className="flex min-h-[240px] flex-col items-center justify-center rounded-xl border border-dashed border-slate-300 bg-white/70 px-6 py-10 text-center">
    <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 text-slate-400 ring-1 ring-slate-200">
      {props.icon ?? <Inbox size={22} aria-hidden />}
    </div>
    <h2 className="text-base font-bold text-slate-800">{props.title}</h2>
    {props.message && (
      <p className="mt-1 max-w-md text-sm font-medium text-slate-500">
        {props.message}
      </p>
    )}
    {props.action && <div className="mt-5">{props.action}</div>}
  </div>
);
