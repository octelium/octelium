import { RouteObject } from "react-router-dom";
import routerAuthenticator from "./Authenticator/router";
import Denied from "./Denied";
import Home from "./Home";
import Root from "./index";
import routerLogin from "./Login/router";

export default (): RouteObject => {
  return {
    path: "/",
    element: <Root />,
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
    ],
  };
};
