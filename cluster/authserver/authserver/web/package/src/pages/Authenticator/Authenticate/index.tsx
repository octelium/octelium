import OtpInput from "react-otp-input";
import * as React from "react";

import { isDev } from "@/utils";

import * as Auth from "@/apis/authv1/authv1";
import { getClientAuth } from "@/utils/client";
import { useMutation, useQuery } from "@tanstack/react-query";
import TimeAgo from "@/components/TimeAgo";
import { getResourceRef } from "@/utils/pb";
import { Collapse, PinInput } from "@mantine/core";
import { Timestamp } from "@/apis/google/protobuf/timestamp";
import { twMerge } from "tailwind-merge";

const TOTP = (props: { authn: Auth.Authenticator }) => {
  const { authn } = props;

  const c = getClientAuth();

  const mutation = useMutation({
    mutationFn: async (otp: string) => {
      await c.authenticateAuthenticatorBegin(
        Auth.AuthenticateAuthenticatorBeginRequest.create({
          authenticatorRef: getResourceRef(authn),
        })
      );

      return await c.authenticateWithAuthenticator(
        Auth.AuthenticateWithAuthenticatorRequest.create({
          authenticatorRef: getResourceRef(authn),
          challengeResponse: {
            type: {
              oneofKind: "totp",
              totp: {
                response: otp,
              },
            },
          },
        })
      );
    },
    onSuccess: (r) => {
      window.location.href = "/callback/success";
    },
    onError: (resp) => {},
  });

  return (
    <div className="w-full flex flex-col items-center justify-center">
      <h2 className="font-bold text-xl text-slate-700 flex items-center justify-center my-4 text-center">
        Enter the OTP
      </h2>

      <PinInput
        type={"number"}
        inputType="tel"
        inputMode="numeric"
        length={6}
        autoFocus
        size="lg"
        onComplete={(val) => {
          mutation.mutate(val);
        }}
      />
    </div>
  );
};

const Fido = (props: { authn: Auth.Authenticator }) => {
  const { authn } = props;

  const c = getClientAuth();

  const mutation = useMutation({
    mutationFn: async () => {
      const { response } = await c.authenticateAuthenticatorBegin(
        Auth.AuthenticateAuthenticatorBeginRequest.create({
          authenticatorRef: getResourceRef(authn),
        })
      );

      if (response.challengeRequest?.type.oneofKind === `fido`) {
        try {
          console.log("Got req", response.challengeRequest.type.fido.request);
          const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(
            JSON.parse(response.challengeRequest.type.fido.request)
          );
          const credential = (await navigator.credentials.get({
            publicKey,
          })) as PublicKeyCredential;

          console.log("Got credential", credential.toJSON());

          return await c.authenticateWithAuthenticator(
            Auth.AuthenticateWithAuthenticatorRequest.create({
              authenticatorRef: getResourceRef(authn),
              challengeResponse: {
                type: {
                  oneofKind: "fido",
                  fido: {
                    response: JSON.stringify(credential.toJSON()),
                  },
                },
              },
            })
          );
        } catch (err) {
          console.log("fido get err", err);
          throw err;
        }
      }
    },
    onSuccess: (r) => {
      window.location.href = "/callback/success";
    },
    onError: (resp) => {},
  });

  React.useEffect(() => {
    mutation.mutate();
  }, []);

  return <div></div>;
};

const Authenticator = (props: { authn: Auth.Authenticator }) => {
  const { authn } = props;
  let [open, setOpen] = React.useState(false);
  return (
    <div
      className={twMerge(
        "w-full",
        "p-4 mb-3",
        open
          ? `shadow-sm bg-white`
          : `cursor-pointer bg-slate-50 hover:bg-white`,
        `border-[2px] border-gray-200 rounded-lg`,
        "w-full",

        "transition-all duration-300",
        // "hover:bg-transparent",
        "py-4 px-2",
        "font-semibold",
        "rounded-xl",
        "shadow-sm shadow-slate-200",
        "border-[2px] border-slate-300",
        "mb-4"
      )}
    >
      <div
        onClick={() => {
          setOpen(!open);
        }}
      >
        <div className="w-full font-bold">
          <span className="text-slate-600">{authn.metadata!.name}</span>{" "}
          {authn.spec?.displayName && (
            <span className="text-black ml-2">{authn.spec.displayName}</span>
          )}
        </div>
      </div>

      <div className="text-xs mt-1 mb-2 text-slate-500">
        <span>Created </span>
        <TimeAgo rfc3339={authn.metadata?.createdAt} />
      </div>

      <Collapse in={open} transitionDuration={300}>
        <div>
          {authn.status?.type === Auth.Authenticator_Status_Type.FIDO && (
            <Fido authn={authn} />
          )}

          {authn.status?.type === Auth.Authenticator_Status_Type.TOTP && (
            <TOTP authn={authn} />
          )}
        </div>
      </Collapse>
    </div>
  );
};

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
    queryKey: ["listAvailableAuthenticator"],
    queryFn: async () => {
      return await c.listAvailableAuthenticator({});
    },
  });

  if (isDev()) {
    return (
      <div>
        {devList.items.map((x) => (
          <Authenticator authn={x} />
        ))}
      </div>
    );
  }

  if (isLoading) {
    return <></>;
  }
  if (!data) {
    return <></>;
  }

  return (
    <div>
      <div className="container mx-auto mt-2 p-2 md:p-4 w-full max-w-lg">
        {data.response.items.map((x) => (
          <Authenticator authn={x} />
        ))}
      </div>
    </div>
  );
};

export default Page;
