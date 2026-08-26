/// <reference types="vite-plugin-svgr/client" />

import Logo from "@/assets/l03.svg?react";

const TopBar = () => {
  return (
    <nav
      aria-label="Primary"
      className="w-full min-h-[60px] border-b-[0px] border-slate-300 flex px-4 pt-[env(safe-area-inset-top)] items-center"
    >
      <a
        aria-label="Octelium home"
        className="flex-none flex items-center justify-center"
        href="https://octelium.com"
        target="_blank"
      >
        <Logo aria-hidden="true" focusable="false" className="w-40 h-auto stroke-cyan-400" />
      </a>
      <div className="flex-grow"></div>
    </nav>
  );
};

export default TopBar;
