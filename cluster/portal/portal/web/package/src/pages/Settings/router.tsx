/* eslint-disable react-refresh/only-export-components */

import Loading from "@/components/Loading";
import { lazy, Suspense } from "react";
import { RouteObject } from "react-router-dom";

const Settings = lazy(() => import("./index"));

export default (): RouteObject => {
  return {
    path: "settings",
    element: (
      <Suspense fallback={<Loading />}>
        <Settings />
      </Suspense>
    ),
  };
};
