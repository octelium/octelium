import * as React from "react";
import { Outlet } from "react-router-dom";

const Page = () => {
  return (
    <>
      <Outlet />
    </>
  );
};

export default Page;
