import { PanelTop, Boxes } from "lucide-react";

import * as React from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { twMerge } from "tailwind-merge";

const items = [
  {
    title: "Service",
    url: "/services",
    icon: PanelTop,
  },
  {
    title: "Namespaces",
    url: "/namespaces",
    icon: Boxes,
  },
];

export default function () {
  const loc = useLocation();

  return (
    <div className="min-h-full w-full">
      {items.map((item) => (
        <div key={item.title}>
          <div>
            <Link
              viewTransition
              className={twMerge(
                "transition-all duration-500 hover:bg-slate-200 font-extrabold",
                "flex w-full items-center justify-center",
                "py-1 px-2 rounded-md my-1",
                "text-sm",
                loc.pathname.startsWith(item.url)
                  ? `!text-white bg-zinc-800 hover:bg-black shadow-md`
                  : `text-zinc-600 hover:text-zinc-800`
              )}
              to={item.url}
            >
              <item.icon />
              <span className="flex-1 ml-2">{item.title}</span>
            </Link>
          </div>
        </div>
      ))}
    </div>
  );
}
