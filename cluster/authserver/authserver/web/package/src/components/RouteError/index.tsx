import ActionButton from "@/components/ActionButton";
import AuthPage from "@/components/AuthPage";
import { LuLogIn, LuRotateCw } from "react-icons/lu";
import { isRouteErrorResponse, useRouteError } from "react-router-dom";

const RouteError = () => {
  const error = useRouteError();
  const message = isRouteErrorResponse(error)
    ? error.status === 404
      ? "The page you requested could not be found."
      : "The authentication page could not be loaded."
    : "Something went wrong while loading this page.";

  return (
    <div className="flex min-h-screen flex-col bg-canvas">
      <AuthPage title="We could not load this page" description={message}>
        <div className="flex flex-col gap-2.5">
          <ActionButton
            label="Try again"
            Icon={LuRotateCw}
            primary
            onClick={() => window.location.reload()}
          />
          <ActionButton
            label="Return to login"
            Icon={LuLogIn}
            quiet
            href="/login"
          />
        </div>
      </AuthPage>
    </div>
  );
};

export default RouteError;
