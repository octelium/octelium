import * as React from "react";
import { Outlet } from "react-router-dom";
import Footer from "@/components/Footer";
import TopBar from "@/components/TopBar";

import { Toaster } from "react-hot-toast";

export default () => {
  return (
    <div>
      <title>Octelium Login</title>

      <div className=" bg-slate-100 flex flex-col items-center min-h-screen antialiased">
        <TopBar />
        <div className="mb-2"></div>

        <div className="flex-1 w-full flex flex-col items-center">
          <div className="md:container mx-auto mt-2 p-2 md:p-4 w-full !max-w-4xl">
            <div>
              <Outlet />
            </div>
          </div>
        </div>

        <Toaster position="bottom-center" />
        <Footer />
      </div>
    </div>
  );
};
