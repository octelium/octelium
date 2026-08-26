import * as React from "react";

export const InfoItem = (props: {
  children?: React.ReactNode;
  title: string;
}) => {
  return (
    <div className="grid w-full items-start text-left text-sm grid-cols-1 gap-1 sm:grid-cols-[minmax(8rem,auto)_minmax(0,1fr)] sm:gap-3">
      <dt className="text-left font-bold text-slate-800">{props.title}</dt>
      <dd className="m-0 min-w-0 break-words text-left font-semibold text-slate-600">{props.children}</dd>
    </div>
  );
};

export default InfoItem;
