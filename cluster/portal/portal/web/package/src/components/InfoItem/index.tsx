import * as React from "react";
import { twMerge } from "tailwind-merge";

export const InfoItem = (props: {
  children?: React.ReactNode;
  title: string;
  className?: string;
}) => {
  return (
    <div className={twMerge("min-w-0 text-left", props.className)}>
      <dt className="text-[11px] font-bold tracking-wide text-slate-400 uppercase">
        {props.title}
      </dt>
      <dd className="m-0 mt-0.5 min-w-0 text-sm font-semibold break-words text-slate-700">
        {props.children}
      </dd>
    </div>
  );
};

export default InfoItem;
