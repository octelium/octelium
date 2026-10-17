import { Button } from "@mantine/core";
import { PanelTop, RefreshCw, TriangleAlert } from "lucide-react";
import { Link, useRouteError } from "react-router-dom";

import { Card, DocumentTitle, NotFoundState } from "@/ui";
import { describeRpcError } from "@/utils/rpcError";

export const RouteError = () => {
  const error = useRouteError();
  const message =
    error instanceof Error ? error.message : describeRpcError(error).message;

  return (
    <Card className="p-8">
      <DocumentTitle title="Something went wrong" />
      <div
        role="alert"
        className="flex w-full flex-col items-center justify-center text-center"
      >
        <div
          aria-hidden
          className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-red-200 bg-red-50 text-red-600"
        >
          <TriangleAlert size={18} strokeWidth={2} />
        </div>
        <h1 className="text-body font-semibold text-slate-800">
          This page hit an unexpected error
        </h1>
        <p className="mt-1 max-w-md font-mono text-xs font-normal leading-5 text-slate-500 [overflow-wrap:anywhere]">
          {message}
        </p>
        <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
          <Button
            variant="default"
            leftSection={<RefreshCw size={13} strokeWidth={2.25} />}
            onClick={() => window.location.reload()}
          >
            Reload
          </Button>
          <Button
            component={Link}
            to="/services"
            variant="default"
            leftSection={<PanelTop size={13} strokeWidth={2.25} />}
          >
            Services
          </Button>
        </div>
      </div>
    </Card>
  );
};

export const NotFoundPage = () => (
  <>
    <DocumentTitle title="Page not found" />
    <NotFoundState
      title="Page not found"
      description="This address does not match any page of the portal."
      action={
        <Button component={Link} to="/services" variant="default">
          Go to Services
        </Button>
      }
    />
  </>
);
