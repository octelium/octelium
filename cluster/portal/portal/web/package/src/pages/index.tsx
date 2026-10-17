import Footer from "@/components/Footer";
import PortalShell from "@/components/Sidebar/Shell";
import TopBar from "@/components/TopBar";
import { setStatus } from "@/features/settings/slice";
import { Loading, Note } from "@/ui";
import { getClientUser } from "@/utils/client";
import { useAppDispatch } from "@/utils/hooks";
import { describeRpcError } from "@/utils/rpcError";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import * as React from "react";
import { Outlet, ScrollRestoration } from "react-router-dom";

const Root = () => {
  const dispatch = useAppDispatch();

  const statusQuery = useQuery({
    queryKey: ["user/getStatus"],
    queryFn: async () => {
      const { response } = await getClientUser().getStatus({});
      return response;
    },
    staleTime: 5 * 60 * 1000,
    refetchOnWindowFocus: false,
  });

  React.useEffect(() => {
    if (statusQuery.data) {
      dispatch(setStatus({ status: statusQuery.data }));
    }
  }, [dispatch, statusQuery.data]);

  return (
    <div className="flex min-h-screen w-full flex-col bg-canvas antialiased">
      <ScrollRestoration />
      <a
        href="#portal-main"
        className="sr-only z-[300] rounded-md bg-white px-3 py-2 text-body font-semibold text-slate-900 shadow-raised focus:not-sr-only focus:fixed focus:left-3 focus:top-3"
      >
        Skip to content
      </a>

      <PortalShell header={<TopBar />}>
        {statusQuery.isError && (
          <Note
            tone="amber"
            icon={<AlertTriangle size={14} aria-hidden />}
            className="mb-4"
          >
            <div
              role="alert"
              className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1"
            >
              <span>
                Your account details could not be loaded.{" "}
                {describeRpcError(statusQuery.error).message}
              </span>
              <button
                type="button"
                onClick={() => statusQuery.refetch()}
                className="rounded font-semibold underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-400"
              >
                Retry
              </button>
            </div>
          </Note>
        )}
        <React.Suspense fallback={<Loading label="Loading page…" />}>
          <Outlet />
        </React.Suspense>
        <Footer />
      </PortalShell>
    </div>
  );
};

export default Root;
