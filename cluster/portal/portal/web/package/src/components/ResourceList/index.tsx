import { Link, useNavigate } from "react-router-dom";
import { twJoin, twMerge } from "tailwind-merge";
import TimeAgo from "../TimeAgo";
import { Button } from "@mantine/core";
import Label from "../Label";

export const ResourceListWrapper = (props: { children?: React.ReactNode }) => {
  return <div className="flex flex-col w-full">{props.children}</div>;
};

export const ResourceListItem = (props: {
  children?: React.ReactNode;
  path?: string;
}) => {
  const hasPath = props.path !== undefined && props.path.length > 0;
  const navigate = useNavigate();
  return (
    <div
      className={twMerge(
        "w-full",
        hasPath ? "cursor-pointer" : undefined,
        "transition-all duration-300",
        "bg-white",
        // "hover:bg-transparent",
        "py-4 px-2",
        "font-semibold",
        "rounded-xl",
        "shadow-sm shadow-slate-200",
        "border-[2px] border-slate-300",
        "mb-4"
      )}
      onClick={() => {
        if (hasPath) {
          navigate(props.path!);
        }
      }}
    >
      {props.children}
    </div>
  );
};

export const ResourceListLabel = (props: {
  children?: React.ReactNode;
  label?: string;
  to?: string;
}) => {
  return props.to ? (
    <Link to={props.to}>
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
