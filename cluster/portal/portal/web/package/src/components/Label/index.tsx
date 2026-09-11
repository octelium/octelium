import { twMerge } from "tailwind-merge";

export type LabelTone = "neutral" | "emerald" | "sky" | "amber" | "slate";

const TONES: Record<LabelTone, string> = {
  neutral:
    "bg-slate-50 text-slate-700 ring-slate-200 dark:bg-neutral-800/60 dark:text-neutral-200 dark:ring-neutral-700",
  slate:
    "bg-slate-100 text-slate-700 ring-slate-200 dark:bg-neutral-800 dark:text-neutral-200 dark:ring-neutral-700",
  emerald:
    "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-500/25",
  sky: "bg-sky-50 text-sky-700 ring-sky-200 dark:bg-sky-500/10 dark:text-sky-300 dark:ring-sky-500/25",
  amber:
    "bg-amber-50 text-amber-700 ring-amber-200 dark:bg-amber-500/10 dark:text-amber-300 dark:ring-amber-500/25",
};

const Label = (props: {
  children?: React.ReactNode;
  outlined?: boolean;
  tone?: LabelTone;
  className?: string;
}) => {
  return (
    <span
      className={twMerge(
        "inline-flex flex-row items-center gap-1 rounded-md px-2 py-[3px]",
        "text-xs leading-4 font-semibold whitespace-nowrap ring-1",
        props.outlined
          ? "bg-surface text-fg-muted ring-line-strong"
          : TONES[props.tone ?? "neutral"],
        props.className,
      )}
    >
      {props.children}
    </span>
  );
};

export default Label;
