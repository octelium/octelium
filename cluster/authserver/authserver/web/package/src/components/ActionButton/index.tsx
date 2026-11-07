import { Loader } from "@mantine/core";
import type { IconType } from "react-icons";
import { Link } from "react-router-dom";
import { twMerge } from "tailwind-merge";

const ActionButton = (props: {
  label: string;
  description?: string;
  Icon: IconType;
  primary?: boolean;
  quiet?: boolean;
  pending?: boolean;
  disabled?: boolean;
  href?: string;
  to?: string;
  onClick?: () => void;
}) => {
  const className = twMerge(
    "grid w-full cursor-pointer grid-cols-[1.25rem_minmax(0,1fr)_1.25rem] items-center gap-2 rounded-lg border border-accent bg-accent px-3 py-3.5 !font-bold text-accent-fg shadow-button transition-[background-color,border-color,box-shadow] duration-500 not-disabled:hover:border-accent-hover not-disabled:hover:bg-accent-hover not-disabled:hover:shadow-button-hover disabled:cursor-not-allowed disabled:shadow-none",
    !props.primary &&
      !props.quiet &&
      "dark:border-line dark:bg-surface dark:text-fg dark:not-disabled:hover:border-line-strong dark:not-disabled:hover:bg-surface-hover",
    props.quiet &&
      "border-line-strong bg-surface text-fg shadow-none not-disabled:hover:border-fg-subtle not-disabled:hover:bg-surface-hover not-disabled:hover:shadow-none dark:border-line dark:bg-transparent dark:not-disabled:hover:border-line-strong",
    props.disabled && !props.pending && "opacity-50",
  );

  const content = (
    <>
      <span className="flex items-center justify-center">
        {props.pending ? (
          <Loader size={16} color="currentColor" aria-hidden />
        ) : (
          <props.Icon className="h-[18px] w-[18px]" aria-hidden />
        )}
      </span>
      {props.description ? (
        <span className="col-span-2 min-w-0 break-words text-left">
          <span className="block">{props.label}</span>
          <span className="mt-0.5 block text-xs leading-5 font-medium opacity-75">
            {props.description}
          </span>
        </span>
      ) : (
        <span className="min-w-0 break-words text-center">{props.label}</span>
      )}
    </>
  );

  if (props.to) {
    return (
      <Link to={props.to} className={className}>
        {content}
      </Link>
    );
  }

  if (props.href) {
    return (
      <a href={props.href} className={className}>
        {content}
      </a>
    );
  }

  return (
    <button
      type="button"
      disabled={props.disabled}
      aria-busy={props.pending}
      className={className}
      onClick={props.onClick}
    >
      {content}
    </button>
  );
};

export default ActionButton;
