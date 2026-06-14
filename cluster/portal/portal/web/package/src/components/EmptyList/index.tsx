import * as React from "react";
import { twJoin } from "tailwind-merge";

export default (props: { title: string; children?: React.ReactNode }) => {
  return (
    <div className="flex flex-col items-center justify-center">
      <div
        className={twJoin(
          "flex text-center items-center justify-center",
          "font-bold text-4xl text-gray-600",
          "my-16",
        )}
      >
        {props.title}
      </div>
      <div>{props.children}</div>
    </div>
  );
};
