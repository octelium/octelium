import { Outlet, RouteObject } from "react-router-dom";
import Authenticate from "./Authenticate";
import List from "./List";
import Register from "./Register";

const authenticatorRouter = (): RouteObject => {
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

export default authenticatorRouter;
