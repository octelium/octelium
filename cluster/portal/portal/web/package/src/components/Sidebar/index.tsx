import { Alert, Button, Modal } from "@mantine/core";
import { Boxes, LockKeyhole, LogOut, PanelTop } from "lucide-react";

import Links from "@/pages/Links";
import { getPortalURL } from "@/utils";
import { getClientAuth } from "@/utils/client";
import { useDisclosure } from "@mantine/hooks";
import { LogoutRequest } from "@octelium/apis/main/userv1";
import { useMutation } from "@tanstack/react-query";
import { NavLink } from "react-router-dom";
import ReleaseBox from "../ReleaseBox";

const items = [
  {
    title: "Service",
    url: "/services",
    icon: PanelTop,
  },
  {
    title: "Namespaces",
    url: "/namespaces",
    icon: Boxes,
  },
];

export default function Sidebar(props: { onNavigate?: () => void }) {
  const [opened, { open, close }] = useDisclosure(false);

  const mutationLogout = useMutation({
    mutationFn: async () => {
      await getClientAuth().logout(LogoutRequest.create());
    },
    onSuccess: () => {
      window.location.reload();
    },
  });

  return (
    <div className="flex h-full w-full flex-col">
      <div className="flex min-h-0 flex-1 flex-col">
        <nav aria-label="Portal navigation" className="mb-4 space-y-1">
          {items.map(({ title, url, icon: Icon }) => (
            <NavLink
              key={url}
              to={url}
              onClick={props.onNavigate}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-bold transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 ${
                  isActive
                    ? "bg-zinc-900 text-white shadow-md"
                    : "text-slate-600 hover:bg-slate-200 hover:text-slate-900"
                }`
              }
            >
              <Icon size={18} aria-hidden />
              <span>{title}</span>
            </NavLink>
          ))}
        </nav>

        <div className="min-h-0 overflow-y-auto">
          <Links />
          <ReleaseBox />
        </div>

        <div className="mt-auto flex flex-col border-t border-slate-200 pt-4">
          <Button
            className="mb-3 transition-all duration-500"
            fullWidth
            variant="outline"
            component="a"
            href={getPortalURL("/authenticators")}
            leftSection={<LockKeyhole size={17} aria-hidden />}
          >
            Authenticators
          </Button>

          <Button
            fullWidth
            variant="outline"
            className="transition-all duration-500"
            onClick={open}
            leftSection={<LogOut size={17} aria-hidden />}
          >
            Sign out
          </Button>
        </div>
      </div>

      <Modal opened={opened} onClose={close} centered title="Sign out">
        <p className="text-sm font-medium text-slate-600">
          Are you sure you want to sign out of this portal?
        </p>

        {mutationLogout.isError && (
          <Alert className="mt-4" color="red" title="Sign out failed">
            Please try again.
          </Alert>
        )}

        <div className="mt-6 flex items-center justify-end gap-3">
          <Button variant="outline" onClick={close}>
            Cancel
          </Button>
          <Button
            loading={mutationLogout.isPending}
            onClick={() => {
              mutationLogout.mutate();
            }}
            autoFocus
          >
            Sign out
          </Button>
        </div>
      </Modal>
    </div>
  );
}
