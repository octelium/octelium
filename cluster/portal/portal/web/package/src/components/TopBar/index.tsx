/// <reference types="vite-plugin-svgr/client" />

import Logo from "@/assets/l03.svg?react";
import { useAppSelector } from "@/utils/hooks";

const TopBar = () => {
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
        aria-label="Octelium website"
      >
        <Logo className="w-40 h-auto stroke-cyan-400" />
      </a>
      <div className="flex-grow"></div>

      <div className="flex-none flex items-center">
        <div className="flex items-center justify-center align-middle">
          <div
            className="h-10 w-10 rounded-full border-2 border-white text-gray-600 transition-all duration-300"
            title="Current user"
          >
            {picURL ? (
              <img
                className="h-full w-full rounded-full object-cover"
                src={picURL}
                alt="Current user"
              />
            ) : (
              <div
                className="h-full w-full rounded-full bg-sky-600 transition-all duration-300 hover:bg-indigo-800"
                aria-hidden
              />
            )}
          </div>
        </div>
      </div>
    </nav>
  );
};

export default TopBar;
