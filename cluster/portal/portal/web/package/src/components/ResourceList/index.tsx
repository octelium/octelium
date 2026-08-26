import { Link } from "react-router-dom";
import type { MouseEventHandler } from "react";
import { twMerge } from "tailwind-merge";
import Label from "../Label";

export const ResourceListWrapper = (props: { children?: React.ReactNode }) => {
  return <div className="flex w-full flex-col gap-3">{props.children}</div>;
};

export const ResourceListItem = (props: {
  children?: React.ReactNode;
  className?: string;
  onClick?: MouseEventHandler<HTMLElement>;
}) => {
  return (
    <article
      className={twMerge("w-full rounded-xl border-2 border-slate-200 bg-white p-4 font-semibold shadow-sm transition-shadow hover:shadow-md", props.className)}
      onClick={props.onClick}
    >
      {props.children}
    </article>
  );
};

export const ResourceListLabel = (props: {
  children?: React.ReactNode;
  label?: string;
  to?: string;
}) => {
  return props.to ? (
    <Link className="inline-flex rounded-full focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900" to={props.to}>
      <Label>
        {props.label && (
          <span className="text-blue-300 mr-1">{props.label}</span>
        )}
        <span className="flex items-center">{props.children}</span>
      </Label>
    </Link>
  ) : (
    <Label>
      {props.label && <span className="text-blue-300 mr-1">{props.label}</span>}
      <span className="flex items-center">{props.children}</span>
    </Label>
  );
};
