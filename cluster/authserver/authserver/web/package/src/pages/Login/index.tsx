import * as React from "react";

import { useSearchParams } from "react-router-dom";

import ActionButton from "@/components/ActionButton";
import AuthPage from "@/components/AuthPage";
import { getSafeRedirectURL, isDev } from "@/utils";
import { getClientAuth } from "@/utils/client";
import { notifications } from "@mantine/notifications";
import * as Auth from "@octelium/apis/main/authv1";
import { useMutation } from "@tanstack/react-query";
import { IoIosFingerPrint } from "react-icons/io";
import { LuCircleAlert, LuLogIn } from "react-icons/lu";

import type { IconType } from "react-icons";
import {
  FaAws,
  FaGithub,
  FaGitlab,
  FaGoogle,
  FaMicrosoft,
} from "react-icons/fa";
import { SiAuth0, SiAuthentik, SiKeycloak, SiOkta } from "react-icons/si";

interface authResponse {
  loginURL: string;
}

interface authReqCommon {
  query?: string;
  userAgent: string;
}

const isAuthResponse = (value: unknown): value is authResponse =>
  typeof value === "object" &&
  value !== null &&
  "loginURL" in value &&
  typeof value.loginURL === "string";

interface State {
  domain: string;
  identityProviders?: StateProvider[];
  isPasskeyLoginEnabled?: boolean;
}

interface StateProvider {
  uid: string;
  displayName: string;
  picURL?: string;
}

const PASSKEY_ID = "__passkey__";

const normalizeState = (value: unknown): State => {
  if (typeof value !== "object" || value === null) {
    return { domain: "", identityProviders: [], isPasskeyLoginEnabled: false };
  }

  const state = value as Partial<State>;
  const identityProviders = Array.isArray(state.identityProviders)
    ? state.identityProviders.filter(
        (provider): provider is StateProvider =>
          typeof provider === "object" &&
          provider !== null &&
          typeof provider.uid === "string" &&
          typeof provider.displayName === "string",
      )
    : [];

  return {
    domain: typeof state.domain === "string" ? state.domain : "",
    identityProviders,
    isPasskeyLoginEnabled: state.isPasskeyLoginEnabled === true,
  };
};

const PROVIDER_ICONS: { keywords: string[]; Icon: IconType }[] = [
  { keywords: ["github"], Icon: FaGithub },
  { keywords: ["gitlab"], Icon: FaGitlab },
  { keywords: ["google", "gsuite"], Icon: FaGoogle },
  {
    keywords: ["microsoft", "azure", "entra", "adfs", "ad fs"],
    Icon: FaMicrosoft,
  },
  { keywords: ["okta"], Icon: SiOkta },
  { keywords: ["auth0"], Icon: SiAuth0 },
  { keywords: ["keycloak"], Icon: SiKeycloak },
  { keywords: ["amazon", "aws", "cognito"], Icon: FaAws },
  { keywords: ["authentik"], Icon: SiAuthentik },
];

function getProviderIcon(displayName: string): IconType {
  const name = displayName.toLowerCase().trim();

  const match = PROVIDER_ICONS.find((p) =>
    p.keywords.some((k) => name.includes(k)),
  );

  return match?.Icon ?? LuLogIn;
}

function getState(): State {
  const value = (window as Window & { __OCTELIUM_STATE__?: unknown })
    .__OCTELIUM_STATE__;

  return normalizeState(
    isDev()
      ? (value ?? {
          domain: "example.com",
          isPasskeyLoginEnabled: true,
          identityProviders: [
            { uid: "github", displayName: "GitHub" },
            { uid: "gitlab-1", displayName: "Gitlab" },
          ],
        })
      : value,
  );
}

const Passkey = (props: {
  query?: string;
  primary: boolean;
  pending: string | null;
  setPending: (v: string | null) => void;
}) => {
  const c = getClientAuth();
  const isPending = props.pending === PASSKEY_ID;

  const mutation = useMutation({
    mutationFn: async () => {
      if (
        typeof PublicKeyCredential === "undefined" ||
        typeof PublicKeyCredential.parseRequestOptionsFromJSON !== "function"
      ) {
        throw new Error("Passkeys are not supported by this browser");
      }

      const { response } = await c.authenticateWithPasskeyBegin(
        Auth.AuthenticateWithPasskeyBeginRequest.create({
          query: props.query,
        }),
      );

      const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(
        JSON.parse(response.request),
      );
      const credential = await navigator.credentials.get({
        publicKey,
      });
      if (!(credential instanceof PublicKeyCredential)) {
        throw new Error("No passkey credential was returned");
      }

      return await c.authenticateWithPasskey(
        Auth.AuthenticateWithPasskeyRequest.create({
          response: JSON.stringify(credential.toJSON()),
        }),
      );
    },
    onMutate: () => {
      props.setPending(PASSKEY_ID);
    },
    onSuccess: () => {
      window.location.href = "/callback/success";
    },
    onError: () => {
      props.setPending(null);

      notifications.show({
        color: "red",
        message: "Passkey sign-in failed. Please try again.",
      });
    },
  });

  return (
    <ActionButton
      label={isPending ? "Waiting for your passkey…" : "Continue with a passkey"}
      Icon={IoIosFingerPrint}
      primary={props.primary}
      pending={isPending}
      disabled={props.pending !== null}
      onClick={() => mutation.mutate()}
    />
  );
};

const Page = () => {
  const state = getState();

  const [pending, setPending] = React.useState<string | null>(null);
  const [hasLoginError] = React.useState(() =>
    new URLSearchParams(window.location.search).has("error"),
  );
  const [reqCommon] = React.useState<authReqCommon>(() => ({
    query: new URLSearchParams(window.location.search).toString() || undefined,
    userAgent: window.navigator.userAgent,
  }));

  const [searchParams, setSearchParams] = useSearchParams();

  React.useEffect(() => {
    if (searchParams.toString()) {
      setSearchParams(new URLSearchParams(), { replace: true });
    }
  }, [searchParams, setSearchParams]);

  const busy = pending !== null;
  const providers = state.identityProviders ?? [];
  const hasProviders = providers.length > 0;
  const hasPasskey = state.isPasskeyLoginEnabled === true;
  const hasSingleMethod = providers.length + (hasPasskey ? 1 : 0) === 1;

  const beginLogin = (uid: string) => {
    setPending(uid);

    fetch("/begin", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        uid,
        ...reqCommon,
      }),
    })
      .then((res) => {
        if (!res.ok) {
          throw new Error(`begin failed: ${res.status}`);
        }
        return res.json() as Promise<unknown>;
      })
      .then((data) => {
        if (!isAuthResponse(data)) {
          throw new Error("missing loginURL");
        }
        window.location.assign(getSafeRedirectURL(data.loginURL));
      })
      .catch(() => {
        setPending(null);
        notifications.show({
          color: "red",
          message: "Could not sign in. Please try again.",
        });
      });
  };

  return (
    <AuthPage title="Sign in to Octelium">
      {hasLoginError && (
        <div
          role="alert"
          className="mb-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-400/30 dark:bg-red-400/10 dark:text-red-300"
        >
          <LuCircleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          We could not start sign-in. Please try again.
        </div>
      )}

      {!hasProviders && !hasPasskey && (
        <p className="text-center text-sm leading-6 text-fg-muted">
          No sign-in methods are available for this Cluster. Contact your
          administrator.
        </p>
      )}

      <div className="flex flex-col gap-2.5">
        {providers.map((c) => (
          <ActionButton
            key={c.uid}
            label={
              pending === c.uid
                ? `Redirecting to ${c.displayName}…`
                : `Continue with ${c.displayName}`
            }
            Icon={getProviderIcon(c.displayName)}
            primary={hasSingleMethod}
            pending={pending === c.uid}
            disabled={busy}
            onClick={() => beginLogin(c.uid)}
          />
        ))}

        {hasProviders && hasPasskey && (
          <div
            role="separator"
            className="my-1.5 flex items-center gap-3 text-xs text-fg-subtle"
          >
            <span aria-hidden className="h-px flex-1 bg-line" />
            or
            <span aria-hidden className="h-px flex-1 bg-line" />
          </div>
        )}

        {hasPasskey && (
          <Passkey
            query={reqCommon?.query}
            primary={hasSingleMethod}
            pending={pending}
            setPending={setPending}
          />
        )}
      </div>
    </AuthPage>
  );
};

export default Page;
