/* eslint-disable react-refresh/only-export-components */

import { RouteObject } from "react-router-dom";
import { lazy, Suspense } from "react";
import Root from "./index";
import Loading from "@/components/Loading";

const List = lazy(() => import("./List"));

export default (): RouteObject => {
  return {
    path: "namespaces",
    element: <Root />,
    children: [
      {
        path: "",
        element: (
          <Suspense fallback={<Loading />}>
            <List />
          </Suspense>
        ),
      },
    ],
  };
};
