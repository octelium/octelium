import OtpInput from "react-otp-input";
import * as React from "react";

import { isDev } from "@/utils";

import * as Auth from "@/apis/authv1/authv1";
import { getClientAuth } from "@/utils/client";
import { useMutation, useQuery } from "@tanstack/react-query";
import TimeAgo from "@/components/TimeAgo";
import { getResourceRef } from "@/utils/pb";
import {
  Button,
  Collapse,
  Input,
  PinInput,
  TextInput,
  UnstyledButton,
} from "@mantine/core";
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

          <div className="font-bold text-xl text-slate-700 flex items-center justify-center my-2 text-center">
            Scan the QR Code Above by Your TOTP Authenticator (e.g. Google
            Authenticator) then Enter the OTP
          </div>

          <div className="font-bold text-sm text-slate-500 flex items-center justify-center my-2 text-center">
            <span>Or use use the link </span>{" "}
            <a className="ml-2 text-black font-extrabold shadow-2xl" href={url}>
              here
            </a>
          </div>

          <div className="mt-8">
            <PinInput
              type={"number"}
              inputType="number"
              inputMode="numeric"
              length={6}
              size="lg"
              autoFocus
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
        const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
          JSON.parse(response.challengeRequest.type.fido.request)
        );

        try {
          const credential = (await navigator.credentials.create({
            publicKey,
          })) as PublicKeyCredential;

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
        } catch (err) {
          console.log("fido create err", err);
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

const Page = () => {
  const c = getClientAuth();
  let [displayName, setDisplayName] = React.useState<string | undefined>(
    undefined
  );

  let [authn, setAuthn] = React.useState<Auth.Authenticator | undefined>(
    undefined
  );

  const mutation = useMutation({
    mutationFn: async (props: { type: Auth.Authenticator_Status_Type }) => {
      if (isDev()) {
        return Auth.Authenticator.create({
          metadata: {
            name: "authn-1234",
            createdAt: Timestamp.now(),
          },
          spec: {
            displayName,
          },
          status: {
            type: props.type,
          },
        });
      }

      const { response } = await c.createAuthenticator(
        Auth.CreateAuthenticatorRequest.create({
          type: props.type,
          displayName,
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
      <title>Register an Authenticator - Octelium</title>
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

            <div className="w-full my-8">
              <TextInput
                value={displayName}
                className="!active:shadow-none"
                placeholder="My Authenticator"
                variant={"unstyled"}
                description={
                  <span className="text-xs font-bold text-black">
                    Display Name (Optional)
                  </span>
                }
                size="xl"
                onChange={(e) => {
                  setDisplayName(e.target.value);
                }}
              />
            </div>
            <div className="w-full">
              {[
                {
                  name: "TOTP",
                  type: Auth.Authenticator_Status_Type.TOTP,
                  description:
                    "Use Time-based One Time Password (TOTP) Authenticators such as Google Authenticator",
                },
                {
                  name: "FIDO",
                  type: Auth.Authenticator_Status_Type.FIDO,
                  description:
                    "Use WebAuthn/Passkey/FIDO 2 Security Keys, Windows Hello, Android and Compliant Password Managers",
                },
              ].map((x) => (
                <button
                  key={x.name}
                  className={twMerge(
                    "w-full px-3 py-4 md:py-6 font-bold transition-all duration-500 mb-4",
                    "shadow-2xl rounded-lg cursor-pointer font-bold",
                    "bg-[#242323] hover:bg-black text-white text-lg",
                    mutation.isPending ? "!bg-[#777] shadow-none" : undefined
                  )}
                  onClick={() => {
                    mutation.mutate({
                      type: x.type,
                    });
                  }}
                >
                  <div className="flex items-center">
                    <span className="font-bold text-xl">{x.name}</span>
                    <span className="font-bold text-sm flex-1 text-left ml-4 text-slate-300">
                      {x.description}
                    </span>
                  </div>
                </button>
              ))}
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
