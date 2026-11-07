import * as React from "react";

import ActionButton from "@/components/ActionButton";
import AuthPage from "@/components/AuthPage";
import { getSafeRedirectURL } from "@/utils";
import { notifications } from "@mantine/notifications";
import { LuCheck, LuX } from "react-icons/lu";

interface approvalResponse {
  redirectURL: string;
}

const isApprovalResponse = (value: unknown): value is approvalResponse =>
  typeof value === "object" &&
  value !== null &&
  "redirectURL" in value &&
  typeof value.redirectURL === "string";

const Page = () => {
  const [pending, setPending] = React.useState<"approve" | "reject" | null>(
    null,
  );

  const decide = (isApproved: boolean) => {
    setPending(isApproved ? "approve" : "reject");

    fetch("/callback/success/approval", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ isApproved }),
    })
      .then((res) => {
        if (!res.ok) {
          throw new Error(`approval failed: ${res.status}`);
        }
        return res.json() as Promise<unknown>;
      })
      .then((data) => {
        if (!isApprovalResponse(data)) {
          throw new Error("missing redirectURL");
        }
        window.location.assign(getSafeRedirectURL(data.redirectURL));
      })
      .catch(() => {
        setPending(null);
        notifications.show({
          color: "red",
          message: "Could not complete the request. Please try again.",
        });
      });
  };

  return (
    <>
      <title>Approve Login - Octelium</title>
      <AuthPage
        title="Approve this sign-in"
        description={
          <span className="font-medium">
            A client running on this device is asking to sign in.
          </span>
        }
      >
        <div className="flex flex-col gap-2.5">
          <ActionButton
            label={pending === "approve" ? "Approving…" : "Approve"}
            Icon={LuCheck}
            primary
            pending={pending === "approve"}
            disabled={pending !== null}
            onClick={() => decide(true)}
          />
          <ActionButton
            label={pending === "reject" ? "Rejecting…" : "Reject"}
            Icon={LuX}
            quiet
            pending={pending === "reject"}
            disabled={pending !== null}
            onClick={() => decide(false)}
          />
        </div>
      </AuthPage>
    </>
  );
};

export default Page;
