import { RouteObject } from "react-router-dom";
import Root from "./index";
import routerServices from "./Services/router";
import routerNamespaces from './Namespaces/router'
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
      routerServices(),
      routerNamespaces(),
    ],
  };
};
