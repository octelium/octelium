import { RouteObject } from "react-router-dom";
import Root from "./index";

const loginRouter = (): RouteObject => {
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

export default loginRouter;
