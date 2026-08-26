import Footer from "@/components/Footer";
import TopBar from "@/components/TopBar";
import { Outlet } from "react-router-dom";

import Sidebar from "@/components/Sidebar";
import { setStatus } from "@/features/settings/slice";
import { getClientUser } from "@/utils/client";
import { useAppDispatch } from "@/utils/hooks";
import { AppShell, Burger } from "@mantine/core";
import { useDisclosure, useHeadroom } from "@mantine/hooks";
import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { ErrorState } from "@/components/AsyncState";

const Root = () => {
  const dispatch = useAppDispatch();
  const [opened, { toggle, close }] = useDisclosure(false);
  const pinned = useHeadroom({ fixedAt: 120 });
  const location = useLocation();

  const statusQuery = useQuery({
    queryKey: ["user/getStatus"],
    queryFn: async () => {
      const { response } = await getClientUser().getStatus({});
      return response;
    },
  });

  useEffect(() => {
    if (statusQuery.data) {
      dispatch(setStatus({ status: statusQuery.data }));
    }
  }, [dispatch, statusQuery.data]);

  useEffect(() => {
    close();
  }, [close, location.pathname]);

  return (
    <div className="min-h-screen">
      <title>Octelium Portal</title>
      <div className="min-h-screen bg-slate-100 antialiased">
        <AppShell
          className="!bg-transparent"
          header={{ height: 64, collapsed: !pinned, offset: true }}
          navbar={{
            width: 260,
            breakpoint: "sm",
            collapsed: { mobile: !opened },
          }}
          padding="md"
        >
          <AppShell.Header className="border-slate-200 !bg-slate-100">
            <div className="flex h-full items-center">
              <Burger
                opened={opened}
                onClick={toggle}
                hiddenFrom="sm"
                size="sm"
                aria-label={opened ? "Close navigation" : "Open navigation"}
              />
              <TopBar />
            </div>
          </AppShell.Header>

          <AppShell.Navbar className="border-slate-200 !bg-slate-100" p="md">
            <Sidebar onNavigate={close} />
          </AppShell.Navbar>

          <AppShell.Main className="min-h-screen !bg-transparent">
            <div className="mx-auto flex min-h-[calc(100vh-64px)] w-full max-w-6xl flex-col">
              {statusQuery.isError && (
                <ErrorState
                  title="Unable to load your session"
                  message="Some portal data may be unavailable. Check your connection or sign in again."
                  onRetry={() => statusQuery.refetch()}
                />
              )}
              <div className="min-w-0 flex-1">
                <Outlet />
              </div>
              <Footer />
            </div>
          </AppShell.Main>
        </AppShell>
      </div>
    </div>
  );
};

export default Root;
