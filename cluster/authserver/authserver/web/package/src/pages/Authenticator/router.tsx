import { Outlet, RouteObject } from "react-router-dom";
import Authenticate from "./Authenticate";
import Register from "./Register";
import List from "./List";

export default (): RouteObject => {
  return {
    path: "authenticators",
    element: (
      <>
        <Outlet />
      </>
    ),

    children: [
      {
        path: "",
        element: <List />,
      },
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
