import { isDev } from "@/utils";

import { getClientAuth } from "@/utils/client";
import * as Auth from "@octelium/apis/main/authv1";
import { useQuery } from "@tanstack/react-query";

import { Loader } from "@mantine/core";
import { Timestamp } from "@octelium/apis/google/protobuf/timestamp";
import { useEffect, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import { ListAvailableAuthenticators } from "../Authenticate";
import { ReturnToPortal } from "../Register";

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
  const [searchParams, setSearchParams] = useSearchParams();

  const queryRef = useRef<URLSearchParams | null>(null);
  if (queryRef.current === null) {
    queryRef.current = new URLSearchParams(searchParams);
  }
  const query = queryRef.current;

  useEffect(() => {
    setSearchParams(new URLSearchParams(), { replace: true });
  }, []);

  const { isError, isLoading, data } = useQuery({
    queryKey: ["getAvailableAuthenticator"],
    queryFn: async () => {
      if (isDev()) {
        return Auth.GetAvailableAuthenticatorResponse.create({
          availableAuthenticators: devList.items,
        });
      }
      const { response } = await c.getAvailableAuthenticator({});
      return response;
    },
  });

  if (isLoading) {
    return (
      <div className="w-full flex items-center justify-center my-24">
        <Loader />
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="container mx-auto mt-2 p-2 md:p-4 w-full max-w-lg">
        <div className="font-bold text-xl text-slate-700 flex items-center justify-center my-4 text-center">
          Could not load your Authenticators. Please refresh and try again.
        </div>
      </div>
    );
  }

  return (
    <div>
      <title>Authenticators - Octelium</title>
      <div className="container mx-auto mt-2 p-2 md:p-4 w-full max-w-lg">
        <ListAvailableAuthenticators resp={data} query={query} />
      </div>

      <ReturnToPortal />
    </div>
  );
};

export default Page;
