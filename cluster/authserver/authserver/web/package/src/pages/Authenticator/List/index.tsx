import OtpInput from "react-otp-input";
import * as React from "react";

import { isDev } from "@/utils";

import * as Auth from "@/apis/authv1/authv1";
import { getClientAuth } from "@/utils/client";
import { useQuery } from "@tanstack/react-query";

import { Timestamp } from "@/apis/google/protobuf/timestamp";
import { Link } from "react-router-dom";
import { Authenticator } from "../Authenticate";

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

const ListAuthenticators = (props: { resp: Auth.GetAvailableAuthenticatorResponse }) => {
  const { resp } = props;

  if (resp.availableAuthenticators.length < 1) {
    return (
      <div className="w-full">
        <div className="font-bold text-xl text-slate-700 flex items-center justify-center my-2 text-center">
          You have no Available Authenticators{" "}
          <Link
            to={`/authenticators/register`}
            className="text-sm mx-4 duration-500 transition-all text-slate-800 hover:text-black text-shadow-sm border-slate-500 border-[1px] py-1 px-2 rounded-md"
          >
            Register
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full">
      <h2 className="font-bold text-xl text-slate-700 flex items-center justify-center my-4 text-center">
        Your Available Authenticators{" "}
        <Link
          to={`/authenticators/register`}
          className="text-sm mx-4 duration-500 transition-all text-slate-800 hover:text-black text-shadow-sm border-slate-500 border-[1px] py-1 px-2 rounded-md"
        >
          Register
        </Link>
      </h2>
      <div className="w-full">
        {resp.availableAuthenticators.map((x) => (
          <Authenticator authn={x} />
        ))}
      </div>
    </div>
  );
};

const Page = () => {
  const c = getClientAuth();

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
    return <></>;
  }
  if (!data) {
    return <></>;
  }

  return (
    <div>
      <title>Authenticators - Octelium</title>
      <div className="container mx-auto mt-2 p-2 md:p-4 w-full max-w-lg">
        <ListAuthenticators resp={data} />
      </div>
    </div>
  );
};

export default Page;
