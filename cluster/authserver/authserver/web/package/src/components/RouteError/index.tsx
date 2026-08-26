import { Button } from "@mantine/core";
import { isRouteErrorResponse, useRouteError } from "react-router-dom";

const RouteError = () => {
  const error = useRouteError();
  const message = isRouteErrorResponse(error)
    ? error.status === 404
      ? "The page you requested could not be found."
      : "The authentication page could not be loaded."
    : "Something went wrong while loading this page.";

  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-slate-100 px-6 text-center">
      <h1 className="text-2xl font-bold text-slate-900">We could not load this page</h1>
      <p className="mt-2 max-w-md text-sm font-medium text-slate-600">{message}</p>
      <div className="mt-6 flex flex-wrap justify-center gap-3">
        <Button variant="filled" onClick={() => window.location.reload()}>
          Try again
        </Button>
        <Button variant="outline" component="a" href="/login">
          Return to login
        </Button>
      </div>
    </main>
  );
};

export default RouteError;
