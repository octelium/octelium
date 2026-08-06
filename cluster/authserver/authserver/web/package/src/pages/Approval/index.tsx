import * as React from "react";

import { twMerge } from "tailwind-merge";

import LogoMain from "@/components/LogoMain";
import { getDomain } from "@/utils";
import { toast } from "react-hot-toast";

interface approvalResponse {
  redirectURL: string;
}

const Page = () => {
  const [pending, setPending] = React.useState(false);

  const decide = (isApproved: boolean) => {
    setPending(true);

    fetch("/callback/success/approval", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ isApproved }),
    })
      .then((res) => {
        if (!res.ok) {
          throw new Error(`approval failed: ${res.status}`);
        }
        return res.json();
      })
      .then((data: approvalResponse) => {
        if (!data.redirectURL) {
          throw new Error("missing redirectURL");
        }
        window.location.href = data.redirectURL;
      })
      .catch(() => {
        setPending(false);
        toast.error("Could not complete the request. Please try again.");
      });
  };

  return (
    <div>
      <title>Approve Login - Octelium</title>
      <div className="flex items-center justify-center mt-4 mb-3">
        <LogoMain />
      </div>

      <div className="container mx-auto mt-2 p-2 md:p-4 w-full max-w-lg">
        <h1 className="font-bold text-xl mb-4 text-zinc-700 text-center">
          <span>Approve a Login to</span>
          <span> </span>
          <span className="text-black">Octelium</span>
        </h1>

        <div className="mb-8 text-center text-zinc-600">
          <span>A client running on this device is asking to log in to</span>
          <span> </span>
          <span className="font-semibold text-zinc-900">{getDomain()}</span>
          <span>
            . Approve it only if you have just started a login yourself.
          </span>
        </div>

        <div className="flex flex-col items-center justify-center">
          <button
            className={twMerge(
              "w-full px-2 py-4 md:py-6 transition-all duration-500 mb-4",
              "shadow-2xl rounded-lg cursor-pointer",
              "bg-[#242323] hover:bg-black text-white text-lg",
              pending ? "!bg-[#777] shadow-none" : undefined,
            )}
            disabled={pending}
            aria-busy={pending}
            onClick={() => decide(true)}
          >
            <span className="font-semibold">Approve</span>
          </button>

          <button
            className={twMerge(
              "w-full px-2 py-3 transition-all duration-500",
              "rounded-lg cursor-pointer",
              "text-zinc-500 hover:text-black",
              pending ? "!text-[#aaa]" : undefined,
            )}
            disabled={pending}
            onClick={() => decide(false)}
          >
            <span className="font-semibold">Reject</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default Page;
