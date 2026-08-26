import { RouteObject } from "react-router-dom";
import Root from "./index";

const approvalRouter = (): RouteObject => {
  return {
    path: "callback/success/approval",
    element: <Root />,
  };
};

export default approvalRouter;
