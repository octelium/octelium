import OtpInput from "react-otp-input";
import * as React from "react";

import { isDev } from "@/utils";

import * as Auth from "@/apis/authv1/authv1";
import { getClientAuth } from "@/utils/client";
import { useQuery } from "@tanstack/react-query";

import { Timestamp } from "@/apis/google/protobuf/timestamp";
import { ListAvailableAuthenticators } from "../Authenticate";

const devList = Auth.AuthenticatorList.create({
  items: [
    Auth.Authenticator.create({
      metadata: {
        name: "totp-1",
        createdAt: Timestamp.now(),
      },
      spec: {
        displayName: "Google Authenticator",
      },
      status: {
        type: Auth.Authenticator_Status_Type.TOTP,
        isRegistered: true,
      },
    }),
    Auth.Authenticator.create({
      metadata: {
        name: "fido-1",
        createdAt: Timestamp.now(),
      },
      spec: {
        displayName: "My FIDO Key",
      },
      status: {
        type: Auth.Authenticator_Status_Type.FIDO,
      },
    }),
  ],
});

const Page = () => {
  const c = getClientAuth();

  const { isError, isLoading, data } = useQuery({
    queryKey: ["getAvailableAuthenticator"],
    queryFn: async () => {
      if (isDev()) {
        return Auth.GetAvailableAuthenticatorResponse.create({
          mainAuthenticator: devList.items[0],
          availableAuthenticators: devList.items,
        });
      }
      const { response } = await c.getAvailableAuthenticator({});
      return response;
    },
  });

  if (isLoading) {
    return <></>;
  }
  if (!data) {
    return <></>;
  }

  return (
    <div>
      <title>Authenticators - Octelium</title>
      <div className="container mx-auto mt-2 p-2 md:p-4 w-full max-w-lg">
        <ListAvailableAuthenticators resp={data} />
      </div>
    </div>
  );
};

export default Page;
