export type Tone = "slate" | "blue" | "emerald" | "amber" | "red";

export const toneClasses: Record<
  Tone,
  { badge: string; soft: string; dot: string; icon: string }
> = {
  slate: {
    badge: "border-slate-200 bg-slate-50 text-slate-600",
    soft: "border-slate-200 bg-slate-50 text-slate-600",
    dot: "bg-slate-400",
    icon: "border-slate-200 bg-slate-50 text-slate-500",
  },
  blue: {
    badge: "border-blue-200 bg-blue-50 text-blue-700",
    soft: "border-blue-200 bg-blue-50 text-blue-800",
    dot: "bg-blue-500",
    icon: "border-blue-200 bg-blue-50 text-blue-700",
  },
  emerald: {
    badge: "border-emerald-200 bg-emerald-50 text-emerald-700",
    soft: "border-emerald-200 bg-emerald-50 text-emerald-800",
    dot: "bg-emerald-500",
    icon: "border-emerald-200 bg-emerald-50 text-emerald-700",
  },
  amber: {
    badge: "border-amber-200 bg-amber-50 text-amber-700",
    soft: "border-amber-200 bg-amber-50 text-amber-800",
    dot: "bg-amber-500",
    icon: "border-amber-200 bg-amber-50 text-amber-700",
  },
  red: {
    badge: "border-red-200 bg-red-50 text-red-700",
    soft: "border-red-200 bg-red-50 text-red-800",
    dot: "bg-red-500",
    icon: "border-red-200 bg-red-50 text-red-700",
  },
};
