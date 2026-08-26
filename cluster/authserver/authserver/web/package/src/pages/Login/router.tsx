import { RouteObject } from "react-router-dom";
import Login from "./index";

const loginRouter = (): RouteObject => {
  return {
    path: "login",
    element: <Login />,
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
