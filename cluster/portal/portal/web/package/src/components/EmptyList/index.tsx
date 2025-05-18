import * as React from "react";
import { twJoin } from "tailwind-merge";

export default (props: { title: string; children?: React.ReactNode }) => {
  return (
    <div className="flex flex-col items-center justify-center">
      <div
        className={twJoin(
          "flex text-center items-center justify-center",
          "font-bold text-4xl text-gray-600",
          "my-16"
        )}
        style={{
          textShadow: "0 2px 8px rgba(0, 0, 0, 0.2)",
        }}
      >
        {props.title}
      </div>
      <div>{props.children}</div>
    </div>
  );
};
