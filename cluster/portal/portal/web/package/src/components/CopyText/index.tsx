import * as React from "react";

import truncate from "truncate-utf8-bytes";

import { CopyButton, ActionIcon, Tooltip, rem } from "@mantine/core";

import { MdOutlineContentCopy } from "react-icons/md";
import { FaCheckDouble } from "react-icons/fa6";
import { IoCopySharp } from "react-icons/io5";
import { motion, AnimatePresence } from "framer-motion";
import { useState } from "react";

const CopyText = (props: {
  value?: string;
  truncate?: number;
  hide?: boolean;
}) => {
  const [copied, setCopied] = useState(false);
  const { value, hide } = props;
  if (!value) {
    return <></>;
  }

  return (
    <span className="flex items-center justify-center">
      {!hide && (
        <span className="mx-1">
          {props.truncate && props.truncate < value.length
            ? `${truncate(value, props.truncate)}...`
            : `${value}`}
        </span>
      )}
      <button
        className="hover:text-black p-0 rounded-full text-slate-700 transition-all duration-500 font-extrabold cursor-pointer"
        aria-label="Copy to clipboard"
        onClick={(e) => {
          e.stopPropagation();
          e.preventDefault();
          navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1000);
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
    </span>
  );
};

export default CopyText;
