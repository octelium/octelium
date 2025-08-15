import * as React from "react";
import { Outlet } from "react-router-dom";
import Footer from "@/components/Footer";
import TopBar from "@/components/TopBar";

import { getClientUser } from "@/utils/client";
import { useQuery } from "@tanstack/react-query";
import { useAppDispatch, useAppSelector } from "@/utils/hooks";
import { setStatus } from "@/features/settings/slice";
import { AppShell, Burger } from "@mantine/core";
import { useDisclosure, useHeadroom } from "@mantine/hooks";
import Sidebar from "@/components/Sidebar";
import Links from "./Links";

export default () => {
  const dispatch = useAppDispatch();
  const [opened, { toggle }] = useDisclosure();
  const pinned = useHeadroom({ fixedAt: 120 });

  useQuery({
    queryKey: ["user/getStatus"],
    queryFn: async () => {
      const { response } = await getClientUser().getStatus({});
      console.log("getStatus", response);
      dispatch(setStatus({ status: response }));
      return response;
    },
  });

  return (
    <div>
      <title>Octelium Portal</title>
      <div className=" bg-slate-100 min-h-screen antialiased">
        <AppShell
          className="!bg-transparent"
          header={{ height: 60, collapsed: !pinned, offset: false }}
          navbar={{
            width: 300,
            breakpoint: "sm",
            collapsed: { mobile: !opened },
          }}
          aside={{
            width: 300,
            breakpoint: "md",
            collapsed: { desktop: false, mobile: true },
          }}
          padding="md"
        >
          <AppShell.Header className="!bg-slate-100">
            <div className="flex flex-row items-center justify-center">
              <Burger
                opened={opened}
                onClick={toggle}
                hiddenFrom="sm"
                size="sm"
              />
              <TopBar />
            </div>
          </AppShell.Header>

          <AppShell.Navbar p="md" className="!bg-slate-100" zIndex={-1}>
            <Sidebar />
          </AppShell.Navbar>

          <AppShell.Main className="!bg-transparent h-full w-full mt-[60px]">
            <div className="flex-1 flex flex-col min-h-full min-w-full items-center justify-center">
              <div className="flex-1 w-full h-full">
                <Outlet />
              </div>
              <Footer />
            </div>
          </AppShell.Main>
          <AppShell.Aside
            p="md"
            className="!bg-transparent mt-[60px]"
          >
            <Links />
          </AppShell.Aside>
        </AppShell>
      </div>
    </div>
  );
};
