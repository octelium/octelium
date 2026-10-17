import { ActionIcon, Button, Tooltip } from "@mantine/core";
import {
  AlertCircle,
  Check,
  Copy,
  Inbox,
  Loader2,
  RefreshCw,
  SearchX,
  UserRound,
  X,
} from "lucide-react";
import * as React from "react";

import { twMerge } from "@/lib/utils";
import { describeRpcError } from "@/utils/rpcError";
import { useCopy } from "./copy";
import { toneClasses, type Tone } from "./tones";

export const DocumentTitle = (props: { title: string }) => (
  <title>{`${props.title} · Octelium Portal`}</title>
);

export const Eyebrow = (props: {
  children: React.ReactNode;
  className?: string;
  id?: string;
}) => (
  <span
    id={props.id}
    className={twMerge(
      "text-micro font-semibold uppercase tracking-[0.07em] text-slate-500",
      props.className,
    )}
  >
    {props.children}
  </span>
);

export const PageHeader = (props: {
  title: React.ReactNode;
  description?: string;
  addon?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}) => (
  <div
    className={twMerge(
      "mb-5 flex w-full items-start justify-between gap-4 sm:gap-6",
      props.className,
    )}
  >
    <div className="flex min-w-0 flex-col gap-1">
      <div className="flex min-w-0 items-center gap-2">
        <h1 className="text-xl font-semibold leading-tight tracking-[-0.015em] text-slate-900 [overflow-wrap:anywhere] sm:text-2xl">
          {props.title}
        </h1>
        {props.addon}
      </div>
      {props.description && (
        <p className="max-w-2xl text-body font-normal text-slate-500">
          {props.description}
        </p>
      )}
    </div>
    {props.actions && (
      <div className="flex shrink-0 flex-wrap items-center gap-2">
        {props.actions}
      </div>
    )}
  </div>
);

export const CountPill = (props: { count?: number; label: string }) =>
  props.count === undefined ? null : (
    <Tooltip
      label={`${props.count.toLocaleString()} ${props.label}`}
      withArrow
      openDelay={300}
    >
      <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-micro font-semibold tabular-nums text-slate-600">
        {props.count.toLocaleString()}
      </span>
    </Tooltip>
  );

export const Card = (props: {
  children: React.ReactNode;
  className?: string;
  interactive?: boolean;
}) => (
  <div
    className={twMerge(
      "rounded-xl border border-slate-200 bg-white",
      props.interactive &&
        "transition-[border-color,box-shadow] duration-150 hover:border-slate-300 hover:shadow-raised",
      props.className,
    )}
  >
    {props.children}
  </div>
);

export const IconTile = (props: {
  children: React.ReactNode;
  tone?: Tone;
  size?: "sm" | "md" | "lg";
  className?: string;
}) => (
  <div
    aria-hidden
    className={twMerge(
      "flex shrink-0 items-center justify-center rounded-lg border",
      toneClasses[props.tone ?? "slate"].icon,
      props.size === "lg"
        ? "h-10 w-10"
        : props.size === "sm"
          ? "h-7 w-7 rounded-md"
          : "h-9 w-9",
      props.className,
    )}
  >
    {props.children}
  </div>
);

export const SectionCard = (props: {
  title: string;
  description?: string;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
}) => (
  <section
    className={twMerge(
      "min-w-0 rounded-xl border border-slate-200 bg-white",
      props.className,
    )}
  >
    <header className="flex items-center justify-between gap-3 border-b border-slate-100 px-4 py-3">
      <div className="flex min-w-0 items-center gap-2.5">
        {props.icon && <IconTile size="sm">{props.icon}</IconTile>}
        <div className="min-w-0">
          <h2 className="text-body font-semibold text-slate-800">
            {props.title}
          </h2>
          {props.description && (
            <p className="text-micro font-normal text-slate-500">
              {props.description}
            </p>
          )}
        </div>
      </div>
      {props.actions && (
        <div className="flex shrink-0 items-center gap-2">{props.actions}</div>
      )}
    </header>
    <div className={twMerge("@container p-4", props.bodyClassName)}>
      {props.children}
    </div>
  </section>
);

export const Badge = (props: {
  tone?: Tone;
  children: React.ReactNode;
  className?: string;
  icon?: React.ReactNode;
  dot?: boolean;
}) => (
  <span
    className={twMerge(
      "inline-flex max-w-full shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 text-micro font-semibold leading-4",
      toneClasses[props.tone ?? "slate"].badge,
      props.className,
    )}
  >
    {props.dot && (
      <span
        aria-hidden
        className={twMerge(
          "h-1.5 w-1.5 shrink-0 rounded-full",
          toneClasses[props.tone ?? "slate"].dot,
        )}
      />
    )}
    {props.icon}
    <span className="truncate">{props.children}</span>
  </span>
);

const initialsOf = (name?: string) =>
  (name ?? "")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0])
    .join("")
    .toUpperCase();

export const Avatar = (props: {
  src?: string;
  name?: string;
  size?: "sm" | "md" | "lg";
  className?: string;
}) => {
  const [failedSrc, setFailedSrc] = React.useState<string>();
  const initials = initialsOf(props.name);
  const showImage = !!props.src && failedSrc !== props.src;

  const size =
    props.size === "sm"
      ? "h-8 w-8 text-[0.625rem]"
      : props.size === "lg"
        ? "h-12 w-12 text-sm"
        : "h-10 w-10 text-xs";

  return (
    <div
      className={twMerge(
        "flex shrink-0 items-center justify-center overflow-hidden rounded-full bg-slate-700 font-semibold text-white",
        size,
        props.className,
      )}
    >
      {showImage ? (
        <img
          src={props.src}
          alt=""
          referrerPolicy="no-referrer"
          onError={() => setFailedSrc(props.src)}
          className="h-full w-full object-cover"
        />
      ) : initials ? (
        <span aria-hidden>{initials}</span>
      ) : (
        <UserRound size={14} strokeWidth={2} aria-hidden />
      )}
    </div>
  );
};

export const Field = (props: {
  label: string;
  description?: string;
  children: React.ReactNode;
}) => {
  const id = React.useId();

  return (
    <div
      role="group"
      aria-labelledby={`${id}-label`}
      aria-describedby={props.description ? `${id}-description` : undefined}
      className="flex flex-col gap-1"
    >
      <span id={`${id}-label`} className="text-xs font-semibold text-slate-700">
        {props.label}
      </span>
      {props.description && (
        <span
          id={`${id}-description`}
          className="mb-0.5 text-xs font-normal leading-[1.45] text-slate-500"
        >
          {props.description}
        </span>
      )}
      {props.children}
    </div>
  );
};

export const InfoGrid = (props: {
  children: React.ReactNode;
  className?: string;
}) => (
  <dl
    className={twMerge(
      "grid grid-cols-1 gap-x-5 gap-y-4 @md:grid-cols-2",
      props.className,
    )}
  >
    {props.children}
  </dl>
);

export const KeyValue = (props: {
  label: string;
  children: React.ReactNode;
  full?: boolean;
}) => (
  <div
    className={twMerge(
      "flex min-w-0 flex-col gap-1",
      props.full && "@md:col-span-2",
    )}
  >
    <dt>
      <Eyebrow>{props.label}</Eyebrow>
    </dt>
    <dd className="m-0 flex min-w-0 flex-wrap items-center gap-x-4 gap-y-1 text-body font-medium text-slate-800">
      {props.children}
    </dd>
  </div>
);

export const CopyButton = (props: {
  value: string;
  label?: string;
  className?: string;
}) => {
  const { state, copy } = useCopy();
  const label =
    state === "copied"
      ? "Copied"
      : state === "failed"
        ? "Copy failed"
        : (props.label ?? "Copy");

  return (
    <Tooltip label={label} withArrow>
      <ActionIcon
        size="sm"
        variant="subtle"
        color="gray"
        aria-label={label}
        className={props.className}
        onClick={(event) => {
          event.stopPropagation();
          copy(props.value);
        }}
      >
        {state === "copied" ? (
          <Check size={12} strokeWidth={2.5} className="text-emerald-600" />
        ) : state === "failed" ? (
          <X size={12} strokeWidth={2.5} className="text-red-600" />
        ) : (
          <Copy size={12} strokeWidth={2.25} />
        )}
      </ActionIcon>
    </Tooltip>
  );
};

export const CopyValue = (props: {
  value: string;
  copyLabel?: string;
  mono?: boolean;
}) => (
  <span className="inline-flex min-w-0 max-w-full items-center gap-1">
    <span
      className={twMerge(
        "min-w-0 [overflow-wrap:anywhere]",
        props.mono !== false && "font-mono text-xs font-medium text-slate-800",
      )}
    >
      {props.value}
    </span>
    <CopyButton value={props.value} label={props.copyLabel} />
  </span>
);

export const Note = (props: {
  tone?: Tone;
  icon?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) => (
  <div
    className={twMerge(
      "flex items-start gap-2 rounded-lg border px-3 py-2.5 text-xs font-normal leading-5",
      toneClasses[props.tone ?? "slate"].soft,
      props.className,
    )}
  >
    {props.icon && <span className="mt-[3px] shrink-0">{props.icon}</span>}
    <div className="min-w-0 flex-1">{props.children}</div>
  </div>
);

export const RefreshButton = (props: {
  onClick: () => void;
  loading?: boolean;
  label?: string;
}) => {
  const label = props.label ?? "Refresh";
  return (
    <Tooltip label={label} withArrow>
      <ActionIcon
        variant="default"
        size={36}
        radius="md"
        aria-label={label}
        aria-busy={props.loading || undefined}
        onClick={props.onClick}
      >
        <RefreshCw
          size={14}
          strokeWidth={2.25}
          className={twMerge(
            "text-slate-600",
            props.loading && "motion-safe:animate-spin",
          )}
        />
      </ActionIcon>
    </Tooltip>
  );
};

export const Loading = (props: { label?: string }) => (
  <div role="status" className="flex w-full items-center justify-center py-16">
    <div className="flex items-center gap-2 text-slate-500">
      <Loader2
        size={15}
        strokeWidth={2.25}
        className="motion-safe:animate-spin"
      />
      <span className="text-xs font-medium">{props.label ?? "Loading…"}</span>
    </div>
  </div>
);

export const SkeletonRows = (props: { rows?: number; label?: string }) => (
  <div
    role="status"
    aria-label={props.label ?? "Loading"}
    className="flex flex-col gap-2"
  >
    {Array.from({ length: props.rows ?? 5 }).map((_, index) => (
      <div
        key={index}
        className="flex items-start gap-3 rounded-xl border border-slate-200 bg-white px-4 py-3.5"
      >
        <div className="h-9 w-9 shrink-0 rounded-lg bg-slate-100 motion-safe:animate-pulse" />
        <div className="flex-1 space-y-2.5 pt-1">
          <div className="h-3 w-1/4 rounded bg-slate-100 motion-safe:animate-pulse" />
          <div className="flex gap-1.5">
            <div className="h-5 w-16 rounded-md bg-slate-50 motion-safe:animate-pulse" />
            <div className="h-5 w-24 rounded-md bg-slate-50 motion-safe:animate-pulse" />
            <div className="h-5 w-14 rounded-md bg-slate-50 motion-safe:animate-pulse" />
          </div>
        </div>
      </div>
    ))}
  </div>
);

export const EmptyState = (props: {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  heading?: boolean;
}) => (
  <div className="flex w-full flex-col items-center justify-center px-6 py-12 text-center">
    <div
      aria-hidden
      className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 text-slate-500"
    >
      {props.icon ?? <Inbox size={18} strokeWidth={2} />}
    </div>
    {props.heading ? (
      <h1 className="text-base font-semibold text-slate-900">{props.title}</h1>
    ) : (
      <p className="text-body font-semibold text-slate-800">{props.title}</p>
    )}
    {props.description && (
      <p className="mt-1 max-w-sm text-xs font-normal leading-5 text-slate-500">
        {props.description}
      </p>
    )}
    {props.action && <div className="mt-4">{props.action}</div>}
  </div>
);

export const ErrorState = (props: {
  title?: string;
  description?: string;
  error?: unknown;
  onRetry?: () => void;
}) => (
  <Card className="p-8">
    <div
      role="alert"
      className="flex w-full flex-col items-center justify-center text-center"
    >
      <div
        aria-hidden
        className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-red-200 bg-red-50 text-red-600"
      >
        <AlertCircle size={18} strokeWidth={2} />
      </div>
      <p className="text-body font-semibold text-slate-800">
        {props.title ?? "Something went wrong"}
      </p>
      <p className="mt-1 max-w-sm text-xs font-normal leading-5 text-slate-500">
        {props.description ??
          (props.error !== undefined
            ? describeRpcError(props.error).message
            : "This information could not be loaded. Try again.")}
      </p>
      {props.onRetry && (
        <Button
          variant="default"
          className="mt-4"
          leftSection={<RefreshCw size={13} strokeWidth={2.25} />}
          onClick={props.onRetry}
        >
          Try again
        </Button>
      )}
    </div>
  </Card>
);

export const NotFoundState = (props: {
  title: string;
  description: string;
  action?: React.ReactNode;
}) => (
  <Card>
    <EmptyState
      icon={<SearchX size={18} strokeWidth={2} />}
      title={props.title}
      description={props.description}
      action={props.action}
      heading
    />
  </Card>
);
