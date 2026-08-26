import * as React from "react";

export const InfoItem = (props: {
  children?: React.ReactNode;
  title: string;
}) => {
  return (
    <div className="grid w-full grid-cols-1 gap-1 text-sm sm:grid-cols-[minmax(8rem,auto)_1fr] sm:gap-3">
      <dt className="font-bold text-slate-800">{props.title}</dt>
      <dd className="min-w-0 break-words font-medium text-slate-600">{props.children}</dd>
    </div>
  );
};

export default InfoItem;
