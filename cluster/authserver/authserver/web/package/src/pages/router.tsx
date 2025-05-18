import { RouteObject } from "react-router-dom";
import Root from "./index";
import routerLogin from "./Login/router";
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
    ],
  };
};
