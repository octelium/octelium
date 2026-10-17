import { twMerge } from "@/lib/utils";
import type * as React from "react";
import { Link } from "react-router-dom";

export const ResourceListLabelWrap = (props: {
  children?: React.ReactNode;
  className?: string;
}) => (
  <div
    className={twMerge(
      "flex w-full flex-wrap items-center gap-1.5",
      props.className,
    )}
  >
    {props.children}
  </div>
);

export const ResourceListLabel = (props: {
  children?: React.ReactNode;
  label?: string;
  icon?: React.ReactNode;
  to?: string;
  title?: string;
}) => {
  const content = (
    <span
      className={twMerge(
        "inline-flex min-h-6 max-w-full items-center gap-1.5 rounded-md border px-2 py-1 align-middle",
        "border-slate-200 bg-slate-50/80 text-xs font-normal leading-none text-slate-700",
        "shadow-card transition-[background-color,border-color,color] duration-150",
        "[&_svg]:size-3 [&_svg]:shrink-0 [&_svg]:text-slate-500",
        props.to &&
          "group-hover/label:border-blue-200 group-hover/label:bg-blue-50/70 group-hover/label:text-blue-700",
      )}
    >
      {props.icon}
      {props.label && (
        <>
          <span className="shrink-0 font-semibold text-slate-500">
            {props.label}
            <span className="sr-only">: </span>
          </span>
          <span aria-hidden className="h-3 w-px shrink-0 bg-slate-200" />
        </>
      )}
      <span className="min-w-0 truncate">{props.children}</span>
    </span>
  );

  return props.to ? (
    <Link
      to={props.to}
      title={props.title}
      aria-label={props.title}
      preventScrollReset
      onClick={(event) => event.stopPropagation()}
      className="group/label inline-flex max-w-full rounded-md align-middle outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40 focus-visible:ring-offset-1"
    >
      {content}
    </Link>
  ) : (
    <span title={props.title} className="inline-flex max-w-full">
      {content}
    </span>
  );
};
