import { twMerge } from "tailwind-merge";

export default (props: { children?: React.ReactNode; outlined?: boolean }) => {
  return (
    <span
      className={twMerge(
        "px-2 py-1 rounded-full font-bold text-xs flex-none mx-1",
        props.outlined
          ? `text-gray-800 border-[1px] border-gray-400 shadow-sm`
          : `bg-gray-800 text-white shadow-lg`
      )}
    >
      {props.children}
    </span>
  );
};
