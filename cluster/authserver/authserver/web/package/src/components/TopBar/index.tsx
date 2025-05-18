/// <reference types="vite-plugin-svgr/client" />

import * as React from "react";
import Logo from "@/assets/l03.svg?react";
import { useNavigate } from "react-router-dom";

import { BsGithub } from "react-icons/bs";
import { twMerge } from "tailwind-merge";

const TopBar = () => {
  const navigate = useNavigate();

  return (
    <React.Fragment>
      <nav className="w-full h-[60px] border-b-[0px] border-slate-300 flex px-4 items-center">
        <a
          className="flex-none flex items-center justify-center"
          href="https://octelium.com"
          target="_blank"
        >
          <Logo className="w-40 h-auto stroke-cyan-400" />
        </a>
        <div className="flex-grow"></div>
      </nav>
    </React.Fragment>
  );
};

export default TopBar;
