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
  <div className="space-y-4" aria-label="Loading resources" role="status">
    {Array.from({ length: props.count ?? 4 }, (_, index) => (
      <div
        className="rounded-xl border-2 border-slate-200 bg-white p-4 shadow-sm"
        key={index}
      >
        <div className="flex items-center gap-3">
          <Skeleton height={48} circle />
          <div className="flex-1 space-y-2">
            <Skeleton height={16} width="42%" />
            <Skeleton height={12} width="68%" />
          </div>
          <Skeleton height={32} width={88} radius="md" />
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
      <span>{props.message ?? "We could not load this data. Please try again."}</span>
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
  action?: ReactNode;
}) => (
  <div className="my-8 flex min-h-[220px] flex-col items-center justify-center rounded-xl border-2 border-dashed border-slate-300 bg-white/60 px-6 text-center">
    <Inbox className="mb-3 text-slate-400" size={32} aria-hidden />
    <h2 className="text-lg font-bold text-slate-700">{props.title}</h2>
    {props.message && <p className="mt-1 max-w-md text-sm text-slate-500">{props.message}</p>}
    {props.action && <div className="mt-4">{props.action}</div>}
  </div>
);
