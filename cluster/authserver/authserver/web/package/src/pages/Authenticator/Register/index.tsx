import * as React from "react";

import { getDomain, isDev } from "@/utils";

import { getClientAuth } from "@/utils/client";
import { getResourceRef } from "@/utils/pb";
import { Button, Loader, PinInput, TextInput } from "@mantine/core";
import { Timestamp } from "@octelium/apis/google/protobuf/timestamp";
import * as Auth from "@octelium/apis/main/authv1";
import { useMutation } from "@tanstack/react-query";
import { QRCodeSVG } from "qrcode.react";
import toast from "react-hot-toast";
import { twMerge } from "tailwind-merge";

const isUserCancellation = (err: unknown) =>
  err instanceof DOMException &&
  (err.name === "NotAllowedError" || err.name === "AbortError");

const TOTP = (props: { authn: Auth.Authenticator }) => {
  const { authn } = props;

  const c = getClientAuth();
  const [url, setURL] = React.useState<string | undefined>(undefined);
  const [otp, setOtp] = React.useState("");
  const startedRef = React.useRef(false);

  const mutation = useMutation({
    mutationFn: async () => {
      if (isDev()) {
        setURL("https://example.com");
        return;
      }
      const { response } = await c.registerAuthenticatorBegin(
        Auth.AuthenticateAuthenticatorBeginRequest.create({
          authenticatorRef: getResourceRef(authn),
        }),
      );

      if (response.challengeRequest?.type.oneofKind !== `totp`) {
        throw new Error("Unexpected challenge type");
      }

      setURL(response.challengeRequest.type.totp.url);
    },
    onError: () => {
      toast.error("Could not start registration. Please try again.");
    },
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
        }),
      );
    },
    onSuccess: () => {
      window.location.href = "/callback/success";
    },
    onError: () => {
      setOtp("");
      toast.error("Could not verify the code. Please try again.");
    },
  });

  React.useEffect(() => {
    if (startedRef.current) {
      return;
    }
    startedRef.current = true;
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
            <span>Or use the link </span>{" "}
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
              value={otp}
              onChange={setOtp}
              onComplete={(val) => {
                mutationFinish.mutate(val);
              }}
            />
          </div>
        </div>
      )}

      {!url && mutation.isPending && (
        <div className="my-24 flex items-center justify-center">
          <Loader />
        </div>
      )}

      {!url && mutation.isError && (
        <div className="w-full flex flex-col items-center justify-center my-4">
          <div className="font-bold text-xl text-slate-700 flex items-center justify-center my-2 text-center">
            Could not start registration
          </div>
          <Button
            onClick={() => {
              mutation.mutate();
            }}
          >
            Try again
          </Button>
        </div>
      )}
    </div>
  );
};

const Fido = (props: { authn: Auth.Authenticator }) => {
  const { authn } = props;

  const c = getClientAuth();
  const startedRef = React.useRef(false);

  const mutation = useMutation({
    mutationFn: async () => {
      const { response } = await c.registerAuthenticatorBegin(
        Auth.AuthenticateAuthenticatorBeginRequest.create({
          authenticatorRef: getResourceRef(authn),
        }),
      );

      if (response.challengeRequest?.type.oneofKind !== `fido`) {
        throw new Error("Unexpected challenge type");
      }

      const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
        JSON.parse(response.challengeRequest.type.fido.request),
      );

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
        }),
      );
    },
    onSuccess: () => {
      window.location.href = "/callback/success";
    },
    onError: (err) => {
      if (!isUserCancellation(err)) {
        toast.error("Could not register your security key. Please try again.");
      }
    },
  });

  React.useEffect(() => {
    if (startedRef.current) {
      return;
    }
    startedRef.current = true;
    mutation.mutate();
  }, []);

  return (
    <div className="w-full flex flex-col items-center justify-center my-4">
      {mutation.isPending && (
        <div className="font-bold text-xl text-slate-700 flex items-center justify-center my-4 text-center">
          Waiting for your security key
        </div>
      )}
      {mutation.isError && (
        <div className="w-full flex flex-col items-center justify-center">
          <div className="font-bold text-xl text-slate-700 flex items-center justify-center my-4 text-center">
            Registration was not completed
          </div>
          <Button
            onClick={() => {
              mutation.mutate();
            }}
          >
            Try again
          </Button>
        </div>
      )}
    </div>
  );
};

const Page = () => {
  const c = getClientAuth();
  const [displayName, setDisplayName] = React.useState<string>("");

  const [authn, setAuthn] = React.useState<Auth.Authenticator | undefined>(
    undefined,
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
        }),
      );

      return response;
    },
    onSuccess: (r) => {
      setAuthn(r);
    },
    onError: () => {
      toast.error("Could not create the Authenticator. Please try again.");
    },
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
                    mutation.isPending ? "!bg-[#777] shadow-none" : undefined,
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
            {authn.status?.type === Auth.Authenticator_Status_Type.TOTP && (
              <TOTP authn={authn} />
            )}

            {authn.status?.type === Auth.Authenticator_Status_Type.FIDO && (
              <Fido authn={authn} />
            )}
          </div>
        )}
      </div>

      <ReturnToPortal />
    </div>
  );
};

export const ReturnToPortal = () => {
  return (
    <div className="w-full flex items-center mt-8 text-center justify-center">
      <a
        className="text-center font-bold text-gray-700 hover:text-gray-900 transition-all duration-500 text-shadow-2xs"
        href={`https://portal.${getDomain()}`}
      >
        Return to Portal
      </a>
    </div>
  );
};

export default Page;
