import { twMerge } from "tailwind-merge";

export type LabelTone = "neutral" | "emerald" | "sky" | "amber" | "slate";

const TONES: Record<LabelTone, string> = {
  neutral: "bg-slate-50 text-slate-700 ring-slate-200",
  slate: "bg-slate-100 text-slate-700 ring-slate-200",
  emerald: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  sky: "bg-sky-50 text-sky-700 ring-sky-200",
  amber: "bg-amber-50 text-amber-700 ring-amber-200",
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
          ? "bg-white text-slate-700 ring-slate-300"
          : TONES[props.tone ?? "neutral"],
        props.className,
      )}
    >
      {props.children}
    </span>
  );
};

export default Label;
