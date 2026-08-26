import CopyText from "@/components/CopyText";

const ResourceName = (props: {
  name: string;
  displayName?: string;
  splitNamespace?: boolean;
}) => {
  const separatorIndex = props.splitNamespace ? props.name.indexOf(".") : -1;
  const resourceName =
    separatorIndex > 0 ? props.name.slice(0, separatorIndex) : props.name;
  const namespaceName =
    separatorIndex > 0 ? props.name.slice(separatorIndex + 1) : undefined;

  return (
    <>
      <h2 className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-base font-extrabold text-slate-950">
        <span className="min-w-0 break-words">
          <span>{resourceName}</span>
          {namespaceName && (
            <>
              <span className="font-semibold text-slate-300">.</span>
              <span className="font-semibold text-slate-500">
                {namespaceName}
              </span>
            </>
          )}
        </span>
        <CopyText value={props.name} hide />
      </h2>
      {props.displayName && (
        <p className="mt-0.5 truncate text-sm font-semibold text-slate-500">
          {props.displayName}
        </p>
      )}
    </>
  );
};

export default ResourceName;
