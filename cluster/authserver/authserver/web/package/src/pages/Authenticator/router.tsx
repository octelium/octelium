import { Outlet, RouteObject } from "react-router-dom";
import Authenticate from "./Authenticate";
import Register from "./Register";

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
      {
        path: "register",
        element: <Register />,
      },
    ],
  };
};
