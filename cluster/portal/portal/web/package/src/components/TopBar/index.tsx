/// <reference types="vite-plugin-svgr/client" />

import Logo from "@/assets/l03.svg?react";
import SignOutDialog from "@/components/SignOutDialog";
import { Avatar } from "@/ui";
import { getPortalURL } from "@/utils";
import { useAppSelector } from "@/utils/hooks";
import { Menu } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { ChevronDown, LockKeyhole, LogOut, Settings } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";

const TopBar = () => {
  const navigate = useNavigate();
  const status = useAppSelector((state) => state.settings.status);
  const [signOutOpened, { open: openSignOut, close: closeSignOut }] =
    useDisclosure(false);

  const picURL =
    status?.session?.metadata?.picURL || status?.user?.metadata?.picURL;
  const displayName =
    status?.user?.metadata?.displayName?.trim() ||
    status?.user?.metadata?.name?.trim();
  const email = status?.user?.spec?.email?.trim();

  return (
    <nav
      aria-label="Account"
      className="flex h-[60px] w-full min-w-0 items-center gap-3 px-2 sm:px-4"
    >
      <Link
        to="/services"
        aria-label="Portal home"
        className="flex flex-none items-center rounded-md outline-none focus-visible:ring-2 focus-visible:ring-slate-400"
      >
        <Logo className="h-auto w-[108px] text-slate-900 sm:w-[152px]" />
      </Link>

      <div className="flex-1" />

      <Menu position="bottom-end" width={240} withinPortal>
        <Menu.Target>
          <button
            type="button"
            aria-label={
              displayName ? `Account menu for ${displayName}` : "Account menu"
            }
            className="group flex h-10 flex-none items-center gap-2 rounded-lg px-1 outline-none transition-colors duration-150 hover:bg-slate-200/60 focus-visible:ring-2 focus-visible:ring-slate-400 sm:px-2"
          >
            <Avatar
              src={picURL}
              name={displayName}
              size="sm"
              className="ring-2 ring-white ring-offset-1 ring-offset-canvas"
            />
            <ChevronDown
              size={13}
              strokeWidth={2.25}
              className="hidden shrink-0 text-slate-500 sm:block"
              aria-hidden
            />
          </button>
        </Menu.Target>

        <Menu.Dropdown>
          {(displayName || email) && (
            <div className="flex min-w-0 flex-col gap-0.5 px-2.5 pb-2 pt-1.5">
              {displayName && (
                <span className="truncate text-body font-semibold text-slate-900">
                  {displayName}
                </span>
              )}
              {email && (
                <span className="truncate text-xs font-normal text-slate-500">
                  {email}
                </span>
              )}
            </div>
          )}
          {(displayName || email) && <Menu.Divider />}
          <Menu.Item
            leftSection={<Settings size={14} aria-hidden />}
            onClick={() => navigate("/settings")}
          >
            Settings
          </Menu.Item>
          <Menu.Item
            component="a"
            href={getPortalURL("/authenticators")}
            leftSection={<LockKeyhole size={14} aria-hidden />}
          >
            Authenticators
          </Menu.Item>
          <Menu.Divider />
          <Menu.Item
            color="red"
            leftSection={<LogOut size={14} aria-hidden />}
            onClick={openSignOut}
          >
            Sign out
          </Menu.Item>
        </Menu.Dropdown>
      </Menu>

      <SignOutDialog opened={signOutOpened} onClose={closeSignOut} />
    </nav>
  );
};

export default TopBar;
