import { AppShell, Drawer } from "@mantine/core";
import { useDisclosure, useMediaQuery, useReducedMotion } from "@mantine/hooks";
import { Menu } from "lucide-react";
import * as React from "react";
import { useLocation } from "react-router-dom";

import SignOutDialog from "@/components/SignOutDialog";
import Sidebar from ".";

const PortalShell = (props: {
  header: React.ReactNode;
  children: React.ReactNode;
}) => {
  const location = useLocation();
  const desktop = useMediaQuery("(min-width: 48em)");
  const reducedMotion = useReducedMotion();
  const [drawerRoute, setDrawerRoute] = React.useState<string | null>(null);
  const [signOutOpened, { open: openSignOut, close: closeSignOut }] =
    useDisclosure(false);
  const drawerOpened = !desktop && drawerRoute === location.key;
  const closeDrawer = () => setDrawerRoute(null);

  if (desktop && drawerRoute !== null) setDrawerRoute(null);

  return (
    <AppShell
      className="!bg-transparent"
      header={{ height: 60 }}
      navbar={{
        width: 264,
        breakpoint: "sm",
        collapsed: { mobile: true },
      }}
      padding="md"
      transitionDuration={reducedMotion ? 0 : 200}
    >
      <AppShell.Header
        className="!border-slate-200 !bg-canvas"
        style={{ zIndex: 200 }}
      >
        <div className="flex h-full items-center">
          <button
            type="button"
            aria-label="Open navigation"
            aria-haspopup="dialog"
            aria-expanded={drawerOpened}
            onClick={() => setDrawerRoute(location.key)}
            className="ml-2 flex h-11 w-11 shrink-0 items-center justify-center rounded-lg text-slate-600 outline-none transition-colors hover:bg-slate-200/60 focus-visible:ring-2 focus-visible:ring-slate-400 min-[48em]:hidden"
          >
            <Menu size={20} aria-hidden />
          </button>
          {props.header}
        </div>
      </AppShell.Header>

      <AppShell.Navbar
        p={0}
        className="!border-slate-200/80 !bg-canvas"
        style={{ zIndex: 100 }}
        aria-label="Portal sidebar"
        inert={!desktop}
      >
        <Sidebar onSignOut={openSignOut} />
      </AppShell.Navbar>

      <AppShell.Main className="!bg-transparent">
        <div
          id="portal-main"
          tabIndex={-1}
          className="mx-auto flex min-h-[calc(100dvh-60px-2rem)] w-full max-w-[var(--page-max-width)] flex-col outline-none"
        >
          {props.children}
        </div>
      </AppShell.Main>

      <Drawer.Root
        opened={drawerOpened}
        onClose={closeDrawer}
        closeOnEscape={!signOutOpened}
        position="left"
        size="min(320px, calc(100vw - 24px))"
        padding={0}
        zIndex={220}
        transitionProps={{ duration: reducedMotion ? 0 : 200 }}
      >
        <Drawer.Overlay backgroundOpacity={0.28} />
        <Drawer.Content
          aria-label="Portal navigation"
          className="!overflow-hidden !bg-canvas"
        >
          <Drawer.Body className="!h-full !p-0">
            <Sidebar
              onNavigate={closeDrawer}
              onClose={closeDrawer}
              onSignOut={openSignOut}
            />
          </Drawer.Body>
        </Drawer.Content>
      </Drawer.Root>

      <SignOutDialog opened={signOutOpened} onClose={closeSignOut} />
    </AppShell>
  );
};

export default PortalShell;
