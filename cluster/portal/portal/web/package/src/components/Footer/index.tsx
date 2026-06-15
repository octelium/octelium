import { BsGithub } from "react-icons/bs";
import { twMerge } from "tailwind-merge";

const Footer = () => {
  return (
    <div className="w-full mb-12 mt-6 pt-8 bg-inherit">
      <div className="w-full px-6 flex flex-col items-center">
        <div className="flex flex-wrap items-center justify-center">
          <span className="text-sm text-slate-700 font-bold">
            Octelium is Free and Open Source Software
          </span>

          <a
            target="_blank"
            aria-label="Octelium on GitHub"
            className={twMerge(
              "font-extrabold text-sm md:text-xl",
              "mx-4 my-1",
              "transition-all duration-500",
              "text-slate-600 hover:text-slate-900",
            )}
            href="https://github.com/octelium/octelium"
          >
            <BsGithub aria-hidden />
          </a>
        </div>

        <div className="flex flex-col lg:flex-row items-center justify-center gap-x-3">
          <a href="https://octelium.com" target="_blank">
            <span className="flex items-center text-sm font-semibold transition-all duration-300 text-gray-500 hover:text-gray-600">
              © {new Date().getUTCFullYear()}{" "}
              <span className="ml-1">octelium.com</span>
            </span>
          </a>
          <span className="text-gray-500 text-sm font-bold">
            Octelium Labs, LLC
          </span>
          <span className="text-gray-500 text-sm font-bold">
            All rights reserved
          </span>
        </div>
      </div>
    </div>
  );
};

export default Footer;
