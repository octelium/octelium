/* eslint-disable react-refresh/only-export-components */

import { lazy } from "react";
import { RouteObject } from "react-router-dom";
import Root from "./index";

const List = lazy(() => import("./List"));

export default (): RouteObject => {
  return {
    path: "services",
    element: <Root />,
    children: [
      {
        index: true,
        element: <List />,
      },
    ],
  };
};
