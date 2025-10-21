import { Button } from "@mantine/core";
import { PanelTop, Boxes, LogOut, LockKeyhole } from "lucide-react";

import * as React from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { twMerge } from "tailwind-merge";
import { Modal } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useMutation } from "@tanstack/react-query";
import { getClientAuth } from "@/utils/client";
import { LogoutRequest } from "@/apis/userv1/userv1";
import { getDomain } from "@/utils";

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

export default function () {
  const loc = useLocation();
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
    <div className="h-full w-full mt-[60px]">
      <div className="w-full h-full flex flex-col">
        <div>
          {items.map((item) => (
            <div key={item.title}>
              <div>
                <Link
                  viewTransition
                  className={twMerge(
                    "transition-all duration-500 hover:bg-slate-200 font-extrabold",
                    "flex w-full items-center justify-center",
                    "py-1 px-2 rounded-md my-1",
                    "text-sm",
                    loc.pathname.startsWith(item.url)
                      ? `!text-white bg-zinc-800 hover:bg-black shadow-md`
                      : `text-zinc-600 hover:text-zinc-800`
                  )}
                  to={item.url}
                >
                  <item.icon />
                  <span className="flex-1 ml-2">{item.title}</span>
                </Link>
              </div>
            </div>
          ))}
        </div>
        <div className="flex-1"></div>
        <div className="flex flex-col">
          <Button
            className="mb-3"
            fullWidth
            variant="outline"
            component="a"
            href={`https://${getDomain()}/authenticators`}
          >
            <LockKeyhole className="mr-1" />
            <span>Authenticators</span>
          </Button>

          <Button fullWidth variant="outline" onClick={open}>
            <LogOut className="mr-1" />
            <span>Logout</span>
          </Button>
        </div>
      </div>

      <Modal opened={opened} onClose={close} centered>
        <div className="font-bold text-xl mb-4">
          {`Are you sure that you want to logout?`}
        </div>

        <div className="mt-4 flex justify-end items-center">
          <Button variant="outline" onClick={close}>
            Cancel
          </Button>
          <Button
            className="ml-4"
            loading={mutationLogout.isPending}
            onClick={() => {
              mutationLogout.mutate();
            }}
            autoFocus
          >
            Yes, Logout
          </Button>
        </div>
      </Modal>
    </div>
  );
}
