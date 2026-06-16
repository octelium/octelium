import { Button } from "@mantine/core";
import { Boxes, LockKeyhole, LogOut, PanelTop } from "lucide-react";

import Links from "@/pages/Links";
import { getDomain } from "@/utils";
import { getClientAuth } from "@/utils/client";
import { Modal } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { LogoutRequest } from "@octelium/apis/main/userv1";
import { useMutation } from "@tanstack/react-query";
import { useLocation } from "react-router-dom";
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
          <Links />

          <ReleaseBox />
        </div>
        <div className="flex-1"></div>
        <div className="flex flex-col">
          <Button
            className="mb-3 transition-all duration-500"
            fullWidth
            variant="outline"
            component="a"
            href={`https://${getDomain()}/authenticators`}
          >
            <LockKeyhole className="mr-1" />
            <span>Authenticators</span>
          </Button>

          <Button
            fullWidth
            variant="outline"
            className="transition-all duration-500"
            onClick={open}
          >
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
