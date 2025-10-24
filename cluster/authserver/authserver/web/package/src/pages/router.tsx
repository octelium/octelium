import { RouteObject } from "react-router-dom";
import Root from "./index";
import routerLogin from "./Login/router";
import routerAuthenticator from './Authenticator/router'
import Home from "./Home";
import Denied from './Denied'

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
