import { RouteObject } from "react-router-dom";
import Root from "./index";
import routerLogin from "./Login/router";
import routerAuthenticator from './Authenticator/router'
import Home from "./Home";

export default (): RouteObject => {
  return {
    path: "/",
    element: <Root />,
    children: [
      {
        path: "",
        element: <Home />,
      },
      
      routerLogin(),
      routerAuthenticator(),
    ],
  };
};
