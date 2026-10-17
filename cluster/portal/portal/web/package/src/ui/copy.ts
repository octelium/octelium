import * as React from "react";

export type CopyState = "idle" | "copied" | "failed";

const writeToClipboard = async (value: string) => {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }

  const area = document.createElement("textarea");
  area.value = value;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  try {
    if (!document.execCommand("copy")) throw new Error("copy rejected");
  } finally {
    document.body.removeChild(area);
  }
};

export const useCopy = () => {
  const [state, setState] = React.useState<CopyState>("idle");
  const timer = React.useRef<number>(undefined);

  React.useEffect(() => () => window.clearTimeout(timer.current), []);

  const copy = React.useCallback(async (value: string) => {
    let next: CopyState = "copied";
    try {
      await writeToClipboard(value);
    } catch {
      next = "failed";
    }
    setState(next);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setState("idle"), 1600);
  }, []);

  return { state, copy };
};
