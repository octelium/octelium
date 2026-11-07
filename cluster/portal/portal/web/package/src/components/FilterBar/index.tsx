import { twMerge } from "@/lib/utils";
import { Select, type SelectProps } from "@mantine/core";
import { X } from "lucide-react";
import type * as React from "react";
import { filterInputStyles } from "./styles";

export const FilterBar = (props: {
  label: string;
  children: React.ReactNode;
}) => (
  <div className="z-20 -mx-1 mb-2 bg-canvas px-1 pb-3 sm:sticky sm:top-[60px] sm:pt-3 sm:supports-[backdrop-filter]:bg-canvas/85 sm:supports-[backdrop-filter]:backdrop-blur">
    <div
      role="search"
      aria-label={props.label}
      className="flex flex-col divide-y divide-slate-100 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-surface transition-[border-color] duration-150 focus-within:border-slate-400 lg:flex-row lg:divide-x lg:divide-y-0"
    >
      {props.children}
    </div>
  </div>
);

export const FilterSelect = (
  props: SelectProps & { clearLabel: string; onClear: () => void },
) => {
  const { clearLabel, onClear, className, ...rest } = props;

  return (
    <Select
      {...rest}
      className={twMerge(
        "min-w-0 transition-colors focus-within:bg-slate-50 hover:bg-slate-50 lg:w-56",
        className,
      )}
      styles={filterInputStyles}
      rightSectionPointerEvents={props.value ? "all" : "none"}
      rightSection={
        props.value ? (
          <button
            type="button"
            aria-label={clearLabel}
            title={clearLabel}
            className="flex h-6 w-6 items-center justify-center rounded-md text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-500"
            onClick={onClear}
          >
            <X size={14} strokeWidth={2.4} aria-hidden />
          </button>
        ) : undefined
      }
    />
  );
};

export const FilterClearButton = (props: { onClick: () => void }) => (
  <button
    type="button"
    className="flex min-h-[42px] shrink-0 items-center justify-center gap-1.5 whitespace-nowrap px-3.5 text-xs font-semibold text-slate-600 outline-none transition-colors hover:bg-slate-50 hover:text-slate-900 focus-visible:bg-slate-50 focus-visible:text-slate-900 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-slate-400"
    onClick={props.onClick}
  >
    <X size={13} strokeWidth={2.5} aria-hidden />
    Clear filters
  </button>
);
