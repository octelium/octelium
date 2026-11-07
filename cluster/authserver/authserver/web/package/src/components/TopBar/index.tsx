/// <reference types="vite-plugin-svgr/client" />

import Logo from "@/assets/l03.svg?react";
import AppearanceControl from "@/components/AppearanceControl";

const TopBar = () => (
  <nav
    aria-label="Primary"
    className="w-full min-h-[60px] flex items-center justify-between gap-2 px-4 pt-[env(safe-area-inset-top)]"
  >
    <a
      aria-label="Octelium home"
      className="flex-none flex items-center justify-center"
      href="https://octelium.com"
      target="_blank"
    >
      <Logo
        aria-hidden="true"
        focusable="false"
        className="w-28 h-auto dark:invert sm:w-40"
      />
    </a>
    <AppearanceControl />
  </nav>
);

export default TopBar;
