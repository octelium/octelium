import CopyText from "@/components/CopyText";
import HighlightText from "@/components/HighlightText";

const ResourceName = (props: {
  name: string;
  displayName?: string;
  splitNamespace?: boolean;
  copyValue?: string;
  highlight?: string[];
}) => {
  const separatorIndex = props.splitNamespace ? props.name.indexOf(".") : -1;
  const resourceName =
    separatorIndex > 0 ? props.name.slice(0, separatorIndex) : props.name;
  const namespaceName =
    separatorIndex > 0 ? props.name.slice(separatorIndex + 1) : undefined;

  return (
    <>
      <div className="flex min-w-0 items-center gap-1">
        <h2 className="min-w-0 truncate text-[15px] font-bold tracking-tight text-slate-900 sm:text-base">
          <HighlightText text={resourceName} tokens={props.highlight} />
          {namespaceName && (
            <>
              <span className="font-semibold text-slate-300">.</span>
              <span className="font-semibold text-slate-500">
                <HighlightText
                  text={namespaceName}
                  tokens={props.highlight}
                />
              </span>
            </>
          )}
        </h2>
        <span className="flex-none text-slate-400 transition-opacity duration-200 focus-within:opacity-100 md:opacity-0 md:group-hover/item:opacity-100">
          <CopyText value={props.copyValue ?? props.name} hide />
        </span>
      </div>
      {props.displayName && (
        <p className="mt-0.5 truncate text-sm font-medium text-slate-500">
          <HighlightText text={props.displayName} tokens={props.highlight} />
        </p>
      )}
    </>
  );
};

export default ResourceName;
