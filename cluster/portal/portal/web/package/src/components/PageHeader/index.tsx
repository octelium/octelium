import type { ReactNode } from "react";

const PageHeader = (props: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) => (
  <div className="mb-6 flex flex-col gap-4 border-b border-line pb-5 sm:flex-row sm:items-end sm:justify-between">
    <div>
      <h1 className="text-2xl font-extrabold tracking-tight text-fg sm:text-3xl">
        {props.title}
      </h1>
      {props.description && (
        <p className="mt-1 max-w-2xl text-sm font-medium text-fg-subtle">
          {props.description}
        </p>
      )}
    </div>
    {props.actions}
  </div>
);

export default PageHeader;
