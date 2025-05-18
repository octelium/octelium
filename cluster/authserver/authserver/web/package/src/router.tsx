import { createMemoryRouter, createBrowserRouter } from "react-router-dom";

import routerRoot from "@/pages/router";

const router = () => {
  return createBrowserRouter([routerRoot()]);
};

export default router;
