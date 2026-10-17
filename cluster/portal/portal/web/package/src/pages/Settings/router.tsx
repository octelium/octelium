/* eslint-disable react-refresh/only-export-components */

import { lazy } from "react";
import { RouteObject } from "react-router-dom";

const Settings = lazy(() => import("./index"));

export default (): RouteObject => {
  return {
    path: "settings",
    element: <Settings />,
  };
};
