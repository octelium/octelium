import { RouteObject } from "react-router-dom";
import Root from "./index";
// import Factors from "../Factors";

export default (): RouteObject => {
  return {
    path: "login",
    element: <Root />,
    /*
    children: [
      {
        path: "factors",
        element: <Factors />,
      },
    ],
    */
  };
};
