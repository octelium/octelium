import { RouteObject } from "react-router-dom";
import Root from "./index";
import List from "./List";

export default (): RouteObject => {
  return {
    path: "services",
    element: <Root />,
    children: [
      {
        path: "",
        element: <List />,
      },
    ],
  };
};
