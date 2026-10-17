/* eslint-disable react-refresh/only-export-components */

import { NotFoundPage, RouteError } from "@/components/RouteError";
import { Navigate, RouteObject } from "react-router-dom";
import Root from "./index";
import routerNamespaces from "./Namespaces/router";
import routerServices from "./Services/router";
import routerSettings from "./Settings/router";

export default (): RouteObject => {
  return {
    path: "/",
    element: <Root />,
    children: [
      {
        errorElement: <RouteError />,
        children: [
          {
            index: true,
            element: <Navigate to="/services" replace />,
          },
          routerServices(),
          routerNamespaces(),
          routerSettings(),
          {
            path: "*",
            element: <NotFoundPage />,
          },
        ],
      },
    ],
  };
};
