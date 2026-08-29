import { TextInput } from "@mantine/core";
import { Search, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";

const DEBOUNCE_MS = 220;

const SearchField = (props: {
  value: string;
  onChange: (value: string) => void;
  label?: string;
  placeholder?: string;
  className?: string;
}) => {
  const { value, onChange } = props;
  const [text, setText] = useState(value);
  const [lastValue, setLastValue] = useState(value);
  const inputRef = useRef<HTMLInputElement>(null);
  const onChangeRef = useRef(onChange);

  useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);

  if (value !== lastValue) {
    setLastValue(value);
    setText(value);
  }

  useEffect(() => {
    if (text === value) {
      return;
    }
    const timeout = window.setTimeout(
      () => onChangeRef.current(text),
      DEBOUNCE_MS,
    );
    return () => window.clearTimeout(timeout);
  }, [text, value]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (
        event.key !== "/" ||
        event.metaKey ||
        event.ctrlKey ||
        event.altKey ||
        event.defaultPrevented
      ) {
        return;
      }
      const target = event.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.isContentEditable)
      ) {
        return;
      }
      event.preventDefault();
      inputRef.current?.focus();
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const clear = () => {
    setText("");
    onChangeRef.current("");
  };

  return (
    <TextInput
      ref={inputRef}
      className={props.className}
      label={props.label ?? "Search"}
      placeholder={props.placeholder ?? "Search…"}
      value={text}
      spellCheck={false}
      autoComplete="off"
      onChange={(event) => setText(event.currentTarget.value)}
      onKeyDown={(event) => {
        if (event.key === "Escape" && text !== "") {
          event.preventDefault();
          clear();
        }
      }}
      leftSection={<Search size={16} aria-hidden />}
      rightSectionPointerEvents="all"
      rightSection={
        text ? (
          <button
            type="button"
            aria-label="Clear search"
            className="flex h-6 w-6 cursor-pointer items-center justify-center rounded-full text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-800"
            onClick={clear}
          >
            <X size={15} aria-hidden />
          </button>
        ) : (
          <kbd
            aria-hidden
            className="hidden rounded border border-slate-200 bg-slate-50 px-1.5 py-px text-[11px] font-bold text-slate-400 sm:block"
          >
            /
          </kbd>
        )
      }
    />
  );
};

export default SearchField;
