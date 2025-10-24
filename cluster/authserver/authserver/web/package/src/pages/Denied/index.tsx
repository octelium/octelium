import * as React from "react";
import { Outlet } from "react-router-dom";

import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { twMerge } from "tailwind-merge";

import { toast } from "react-hot-toast";
import { getDomain, isDev } from "@/utils";
import * as Auth from "@/apis/authv1/authv1";
import { getClientAuth } from "@/utils/client";
import { useMutation } from "@tanstack/react-query";
import { Divider } from "@mantine/core";
import LogoMain from "@/components/LogoMain";

const Page = () => {
  return (
    <div>
      <title>Unauthorized Page - Octelium</title>
      <div className="flex items-center justify-center mt-4 mb-3">
        <LogoMain />
      </div>

      <div
        className="font-bold text-xl mb-4 text-zinc-900 text-center mt-16"
        style={{
          textShadow: "0 2px 8px rgba(0, 0, 0, 0.2)",
        }}
      >
        <span>You are not authorized to access this resource</span>
      </div>
      <div className="font-bold text-sm my-4 text-zinc-500 text-center">
        <span>
          Visit Octelium Portal{" "}
          <a
            className="text-zinc-800 hover:text-black transition-all duration-500"
            href={`https://portal.${getDomain()}`}
          >
            here
          </a>{" "}
        </span>
      </div>
    </div>
  );
};

export default Page;
