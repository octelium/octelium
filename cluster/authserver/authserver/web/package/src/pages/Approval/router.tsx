import { RouteObject } from "react-router-dom";
import Approval from "./index";

const approvalRouter = (): RouteObject => {
  return {
    path: "callback/success/approval",
    element: <Approval />,
  };
};

export default approvalRouter;
