import * as React from "react";

import { getPortalURL, isDev } from "@/utils";

import ActionButton from "@/components/ActionButton";
import AuthPage from "@/components/AuthPage";
import CodeInput from "@/components/CodeInput";
import { getClientAuth } from "@/utils/client";
import { getResourceRef } from "@/utils/pb";
import { Loader, TextInput } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { Timestamp } from "@octelium/apis/google/protobuf/timestamp";
import * as Auth from "@octelium/apis/main/authv1";
import { useMutation } from "@tanstack/react-query";
import { QRCodeSVG } from "qrcode.react";
import { IoIosFingerPrint } from "react-icons/io";
import { LuArrowLeft, LuRotateCw, LuSmartphone } from "react-icons/lu";

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
      notifications.show({
        color: "red",
        message: "Could not start registration. Please try again.",
      });
    },
  });
  const { mutate: startTotp } = mutation;

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
      notifications.show({
        color: "red",
        message: "Could not verify the code. Please try again.",
      });
    },
  });

  React.useEffect(() => {
    if (startedRef.current) {
      return;
    }
    startedRef.current = true;
    startTotp();
  }, [startTotp]);

  if (url) {
    return (
      <AuthPage
        compact
        title="Scan the QR code"
        description="Use a TOTP app such as Google Authenticator, then enter the 6-digit code it shows."
      >
        <div className="flex flex-col items-center">
          <div className="rounded-xl bg-white p-3 shadow-button">
            <QRCodeSVG size={176} value={url} />
          </div>

          <p className="mt-4 mb-6 text-center text-xs font-medium text-fg-subtle">
            Cannot scan it?{" "}
            <a
              className="font-semibold text-fg-muted transition-colors duration-500 hover:text-fg"
              href={url}
            >
              Open the setup link
            </a>
          </p>

          <CodeInput
            value={otp}
            disabled={mutationFinish.isPending}
            onChange={setOtp}
            onComplete={(val) => {
              mutationFinish.mutate(val);
            }}
          />

          {mutationFinish.isPending && (
            <div
              className="mt-3 flex items-center gap-2 text-sm font-semibold text-fg-subtle"
              role="status"
            >
              <Loader size="xs" /> Verifying…
            </div>
          )}
        </div>

        <ReturnToPortal />
      </AuthPage>
    );
  }

  if (mutation.isError) {
    return (
      <AuthPage title="Could not start registration">
        <ActionButton
          label="Try again"
          Icon={LuRotateCw}
          primary
          onClick={() => {
            mutation.mutate();
          }}
        />
        <ReturnToPortal />
      </AuthPage>
    );
  }

  return (
    <main className="flex flex-1 items-center justify-center">
      <Loader aria-label="Starting registration" />
    </main>
  );
};

const Fido = (props: { authn: Auth.Authenticator }) => {
  const { authn } = props;

  const c = getClientAuth();
  const startedRef = React.useRef(false);

  const mutation = useMutation({
    mutationFn: async () => {
      if (
        typeof PublicKeyCredential === "undefined" ||
        typeof PublicKeyCredential.parseCreationOptionsFromJSON !== "function"
      ) {
        throw new Error("Security keys are not supported by this browser");
      }

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
      if (!credential) {
        throw new Error("No security key credential was returned");
      }

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
        notifications.show({
          color: "red",
          message: "Could not register your security key. Please try again.",
        });
      }
    },
  });
  const { mutate: startFido } = mutation;

  React.useEffect(() => {
    if (startedRef.current) {
      return;
    }
    startedRef.current = true;
    startFido();
  }, [startFido]);

  if (mutation.isError) {
    return (
      <AuthPage title="Registration was not completed">
        <ActionButton
          label="Try again"
          Icon={LuRotateCw}
          primary
          onClick={() => {
            mutation.mutate();
          }}
        />
        <ReturnToPortal />
      </AuthPage>
    );
  }

  return (
    <AuthPage
      title="Waiting for your security key"
      description="Follow the prompt from your browser to continue."
    >
      <div className="flex justify-center" role="status">
        <Loader size="sm" aria-label="Waiting for your security key" />
      </div>
      <ReturnToPortal />
    </AuthPage>
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
      notifications.show({
        color: "red",
        message: "Could not create the Authenticator. Please try again.",
      });
    },
  });

  return (
    <>
      <title>Register an Authenticator - Octelium</title>
      {!authn && (
        <AuthPage
          title="Register an Authenticator"
          description="Choose how you want to verify your identity."
        >
          <TextInput
            className="mb-6"
            label="Display name (optional)"
            placeholder="My Authenticator"
            size="md"
            value={displayName}
            onChange={(e) => {
              setDisplayName(e.target.value);
            }}
          />

          <div className="flex flex-col gap-2.5">
            {[
              {
                name: "TOTP",
                Icon: LuSmartphone,
                type: Auth.Authenticator_Status_Type.TOTP,
                description:
                  "Time-based One Time Password apps such as Google Authenticator",
              },
              {
                name: "FIDO",
                Icon: IoIosFingerPrint,
                type: Auth.Authenticator_Status_Type.FIDO,
                description:
                  "WebAuthn/Passkey/FIDO 2 security keys, Windows Hello, Android and compliant password managers",
              },
            ].map((x) => (
              <ActionButton
                key={x.name}
                label={x.name}
                description={x.description}
                Icon={x.Icon}
                pending={
                  mutation.isPending && mutation.variables?.type === x.type
                }
                disabled={mutation.isPending}
                onClick={() => {
                  mutation.mutate({
                    type: x.type,
                  });
                }}
              />
            ))}
          </div>

          <ReturnToPortal />
        </AuthPage>
      )}

      {authn?.status?.type === Auth.Authenticator_Status_Type.TOTP && (
        <TOTP authn={authn} />
      )}

      {authn?.status?.type === Auth.Authenticator_Status_Type.FIDO && (
        <Fido authn={authn} />
      )}
    </>
  );
};

export const ReturnToPortal = () => {
  return (
    <a
      className="mx-auto mt-6 flex w-fit items-center gap-1.5 text-sm font-semibold text-fg-subtle transition-colors duration-500 hover:text-fg"
      href={getPortalURL()}
    >
      <LuArrowLeft className="h-4 w-4" aria-hidden />
      Return to Portal
    </a>
  );
};

export default Page;
