import OtpInput from "react-otp-input";
import * as React from "react";

import { isDev } from "@/utils";

import * as Auth from "@/apis/authv1/authv1";
import { getClientAuth } from "@/utils/client";
import { useMutation, useQuery } from "@tanstack/react-query";
import TimeAgo from "@/components/TimeAgo";
import { getResourceRef } from "@/utils/pb";
import { Button, Collapse, PinInput, UnstyledButton } from "@mantine/core";
import { Timestamp } from "@/apis/google/protobuf/timestamp";
import { twMerge } from "tailwind-merge";
import { QRCodeSVG } from "qrcode.react";

const TOTP = (props: { authn: Auth.Authenticator }) => {
  const { authn } = props;

  const c = getClientAuth();
  let [url, setURL] = React.useState<string | undefined>(undefined);

  const mutation = useMutation({
    mutationFn: async () => {
      if (isDev()) {
        setURL("https://example.com");
        return;
      }
      const { response } = await c.registerAuthenticatorBegin(
        Auth.AuthenticateAuthenticatorBeginRequest.create({
          authenticatorRef: getResourceRef(authn),
        })
      );

      if (response.challengeRequest?.type.oneofKind === `totp`) {
        setURL(response.challengeRequest.type.totp.url);
      }
    },
    onSuccess: (r) => {},
    onError: (resp) => {},
  });

  const mutationFinish = useMutation({
    mutationFn: async (otp: string) => {
      return await c.registerAuthenticatorFinish(
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

  React.useEffect(() => {
    mutation.mutate();
  }, []);

  return (
    <div className="w-full flex items-center justify-center">
      {url && (
        <div className="w-full flex flex-col items-center justify-center">
          <div className="mt-4 mb-4">
            <QRCodeSVG size={256} value={url} />
          </div>
          <div>
            <PinInput
              type={"number"}
              inputType="tel"
              inputMode="numeric"
              length={6}
              size="lg"
              onComplete={(val) => {
                mutationFinish.mutate(val);
              }}
            />
          </div>
        </div>
      )}
    </div>
  );
};

const Fido = (props: { authn: Auth.Authenticator }) => {
  const { authn } = props;

  const c = getClientAuth();

  const mutation = useMutation({
    mutationFn: async () => {
      const { response } = await c.registerAuthenticatorBegin(
        Auth.AuthenticateAuthenticatorBeginRequest.create({
          authenticatorRef: getResourceRef(authn),
        })
      );

      if (response.challengeRequest?.type.oneofKind === `fido`) {
        console.log("Req", response.challengeRequest.type.fido.request)
        const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
          JSON.parse(response.challengeRequest.type.fido.request)
        );
        const credential = (await navigator.credentials.create({
          publicKey,
        })) as PublicKeyCredential;

        console.log("FIDO response", credential.toJSON())
        console.log("serialized JSON response", JSON.stringify(credential.toJSON()))

        return await c.registerAuthenticatorFinish(
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

const Page = () => {
  const c = getClientAuth();
  let [displayName, setDisplayName] = React.useState<string | undefined>(
    undefined
  );

  let [authn, setAuthn] = React.useState<Auth.Authenticator | undefined>(
    undefined
  );

  const mutation = useMutation({
    mutationFn: async (props: {
      type: Auth.Authenticator_Status_Type;
      displayName?: string;
    }) => {
      if (isDev()) {
        return Auth.Authenticator.create({
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
        });
      }

      const { response } = await c.createAuthenticator(
        Auth.CreateAuthenticatorRequest.create({
          type: props.type,
          displayName: props.displayName,
        })
      );

      return response;
    },
    onSuccess: (r) => {
      setAuthn(r);
    },
    onError: (resp) => {},
  });

  return (
    <div>
      <div className="container mx-auto mt-2 p-2 md:p-4 w-full max-w-lg">
        {!authn && (
          <div className="w-full mt-16">
            <div className="w-full">
              <div
                className="font-bold text-xl mb-4 text-zinc-700 text-center"
                style={{
                  textShadow: "0 2px 8px rgba(0, 0, 0, 0.2)",
                }}
              >
                <span>Register an MFA Authenticator</span>
              </div>
            </div>
            <div className="w-full">
              <button
                className={twMerge(
                  "w-full px-2 py-4 md:py-6 font-bold transition-all duration-500 mb-4",
                  "shadow-2xl rounded-lg cursor-pointer font-bold",
                  "bg-[#242323] hover:bg-black text-white text-lg",
                  mutation.isPending ? "!bg-[#777] shadow-none" : undefined
                )}
                onClick={() => {
                  mutation.mutate({
                    type: Auth.Authenticator_Status_Type.TOTP,
                    displayName,
                  });
                }}
              >
                <span className="font-bold text-lg">TOTP</span>
              </button>

              <button
                className={twMerge(
                  "w-full px-2 py-4 md:py-6 font-bold transition-all duration-500 mb-4",
                  "shadow-2xl rounded-lg cursor-pointer font-bold",
                  "bg-[#242323] hover:bg-black text-white text-lg",
                  mutation.isPending ? "!bg-[#777] shadow-none" : undefined
                )}
                onClick={() => {
                  mutation.mutate({
                    type: Auth.Authenticator_Status_Type.FIDO,
                    displayName,
                  });
                }}
              >
                <span className="font-bold text-lg">FIDO</span>
              </button>
            </div>
          </div>
        )}
        {authn && (
          <div>
            {authn.status?.type == Auth.Authenticator_Status_Type.TOTP && (
              <TOTP authn={authn} />
            )}

            {authn.status?.type == Auth.Authenticator_Status_Type.FIDO && (
              <Fido authn={authn} />
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Page;
