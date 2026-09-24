import { twMerge } from "tailwind-merge";

const Label = (props: { children?: React.ReactNode; outlined?: boolean }) => {
  return (
    <span
      className={twMerge(
        "px-2 py-1 rounded-full font-bold text-xs flex-none mx-1",
        props.outlined
          ? `text-fg-muted border-[1px] border-line shadow-sm`
          : `bg-accent text-accent-fg shadow-lg`,
      )}
    >
      {props.children}
    </span>
  );
};

export default Label;
