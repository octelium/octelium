import { truncateUtf8 } from "@/utils";
import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useRef, useState } from "react";
import { FaCheckDouble } from "react-icons/fa6";
import { MdOutlineContentCopy } from "react-icons/md";

const CopyText = (props: {
  value?: string;
  truncate?: number;
  hide?: boolean;
}) => {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "error">("idle");
  const timeoutRef = useRef<number | undefined>(undefined);
  const { value, hide } = props;

  useEffect(() => () => window.clearTimeout(timeoutRef.current), []);

  if (!value) {
    return <></>;
  }

  const copied = copyState === "copied";

  return (
    <span className="flex items-center justify-start">
      {!hide && (
        <span className="mx-1">
          {props.truncate && props.truncate > 0
            ? `${truncateUtf8(value, props.truncate, { suffix: "..." })}`
            : `${value}`}
        </span>
      )}
      <button
        type="button"
        className="hover:text-black p-0 rounded-full text-slate-700 transition-all duration-500 font-extrabold cursor-pointer"
        aria-label={copied ? "Copied" : "Copy to clipboard"}
        onClick={async (e) => {
          e.stopPropagation();
          e.preventDefault();
          try {
            if (!navigator.clipboard) throw new Error("Clipboard unavailable");
            await navigator.clipboard.writeText(value);
            setCopyState("copied");
          } catch {
            setCopyState("error");
          }
          window.clearTimeout(timeoutRef.current);
          timeoutRef.current = window.setTimeout(() => setCopyState("idle"), 1200);
        }}
      >
        <AnimatePresence initial={false} mode="popLayout">
          <motion.div
            key={copied ? `1` : `2`}
            initial={{ y: 30, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -30, opacity: 0 }}
            transition={{ duration: 0.2, stiffness: 50 }}
          >
            {copied ? <FaCheckDouble /> : <MdOutlineContentCopy />}
          </motion.div>
        </AnimatePresence>
      </button>
      <span className="sr-only" aria-live="polite">
        {copyState === "copied" ? "Copied to clipboard" : copyState === "error" ? "Could not copy to clipboard" : ""}
      </span>
    </span>
  );
};

export default CopyText;
