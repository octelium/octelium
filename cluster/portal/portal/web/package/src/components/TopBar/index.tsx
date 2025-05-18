/// <reference types="vite-plugin-svgr/client" />

import * as React from "react";
import Logo from "@/assets/l03.svg?react";
import { useNavigate } from "react-router-dom";
import { useAppSelector } from "@/utils/hooks";

const TopBar = () => {
  const navigate = useNavigate();
  const settings = useAppSelector((state) => state.settings);
  const picURL =
    settings.status?.session?.metadata?.picURL ??
    settings.status?.user?.metadata?.picURL;

  return (
    <nav className="w-full h-[60px] border-b-[0px] border-slate-300 flex px-4">
      <a
        className="flex-none flex items-center justify-center"
        href="https://octelium.com"
        target="_blank"
      >
        <Logo className="w-40 h-auto stroke-cyan-400" />
      </a>
      <div className="flex-grow"></div>

      <div className="flex-none flex items-center">
        <div className="flex items-center justify-center align-middle">
          <div className="w-10 h-10 rounded-full border-white border-2 text-gray-600 hover:text-gray-900 font-bold transition-all duration-300">
            {picURL ? (
              <img
                className="rounded-full w-full h-full"
                src={picURL}
                alt="User pic"
              />
            ) : (
              <div className="rounded-full bg-sky-600 hover:bg-indigo-800 transition-all duration-300 w-full h-full"></div>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
};

export default TopBar;
