import { Outlet, RouteObject } from "react-router-dom";
import Authenticate from "./Authenticate";

export default (): RouteObject => {
  return {
    path: "authenticator",
    element: (
      <>
        <Outlet />
      </>
    ),

    children: [
      {
        path: "authenticate",
        element: <Authenticate />,
      },
    ],
  };
};
