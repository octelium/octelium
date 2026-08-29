import { Link } from "react-router-dom";
import type { MouseEventHandler } from "react";
import { twMerge } from "tailwind-merge";
import Label, { type LabelTone } from "../Label";

export const ResourceListWrapper = (props: { children?: React.ReactNode }) => {
  return <div className="flex w-full flex-col gap-2.5">{props.children}</div>;
};

export const ResourceListItem = (props: {
  children?: React.ReactNode;
  className?: string;
  onClick?: MouseEventHandler<HTMLElement>;
}) => {
  return (
    <article
      className={twMerge(
        "group/item relative w-full rounded-xl border border-slate-200 bg-white p-4",
        "shadow-xs transition-all duration-500",
        "hover:border-slate-300 hover:bg-slate-50/70 hover:shadow-md hover:shadow-slate-900/5",
        "focus-within:border-slate-400",
        props.className,
      )}
      onClick={props.onClick}
    >
      {props.children}
    </article>
  );
};

export const ResourceListLabel = (props: {
  children?: React.ReactNode;
  label?: string;
  title?: string;
  tone?: LabelTone;
  className?: string;
  icon?: React.ReactNode;
  to?: string;
}) => {
  const content = (
    <Label tone={props.tone} className={props.className}>
      {props.icon && (
        <span className="flex items-center opacity-70">{props.icon}</span>
      )}
      {props.label && (
        <span className="font-medium text-slate-400">{props.label}</span>
      )}
      <span className="flex min-w-0 items-center">{props.children}</span>
    </Label>
  );

  return props.to ? (
    <Link
      className={twMerge(
        "inline-flex rounded-md transition-transform duration-200",
        "hover:brightness-[0.97] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900",
      )}
      title={props.title}
      to={props.to}
      onClick={(event) => event.stopPropagation()}
    >
      {content}
    </Link>
  ) : (
    <span title={props.title}>{content}</span>
  );
};
