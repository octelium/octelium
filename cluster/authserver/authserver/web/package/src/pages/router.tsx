import { RouteObject } from "react-router-dom";
import RouteError from "@/components/RouteError";
import routerApproval from "./Approval/router";
import routerAuthenticator from "./Authenticator/router";
import Denied from "./Denied";
import Root from "./index";
import Home from "./Home";
import routerLogin from "./Login/router";

const router = (): RouteObject => {
  return {
    path: "/",
    element: <Root />,
    errorElement: <RouteError />,
    children: [
      {
        path: "",
        element: <Home />,
      },
      {
        path: "denied",
        element: <Denied />,
      },

      routerLogin(),
      routerAuthenticator(),
      routerApproval(),
    ],
  };
};

export default router;
