import { RouteObject } from "react-router-dom";
import Home from "./Home";
import Root from "./index";
import routerNamespaces from "./Namespaces/router";
import routerServices from "./Services/router";

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
