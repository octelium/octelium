import * as React from "react";

import { useSearchParams } from "react-router-dom";
import { twMerge } from "tailwind-merge";

import LogoMain from "@/components/LogoMain";
import { isDev } from "@/utils";
import { getClientAuth } from "@/utils/client";
import { Divider } from "@mantine/core";
import * as Auth from "@octelium/apis/main/authv1";
import { useMutation } from "@tanstack/react-query";
import { toast } from "react-hot-toast";
import { IoIosFingerPrint } from "react-icons/io";

interface authResponse {
  loginURL: string;
}

interface authReqCommon {
  query?: string;
  userAgent: string;
}

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

function getState(): State {
  if (!isDev()) {
    return (
      ((window as any).__OCTELIUM_STATE__ as State) ?? ({ domain: "" } as State)
    );
  }

  return {
    domain: "example.com",
    isPasskeyLoginEnabled: true,
    identityProviders: [
      {
        uid: "github",
        displayName: "GitHub",
      },
      {
        uid: "gitlab-1",
        displayName: "Gitlab",
      },
    ],
  } as State;
}

const Passkey = (props: {
  query?: string;
  pending: string | null;
  setPending: (v: string | null) => void;
}) => {
  const c = getClientAuth();
  const busy = props.pending !== null;

  const mutation = useMutation({
    mutationFn: async () => {
      const { response } = await c.authenticateWithPasskeyBegin(
        Auth.AuthenticateWithPasskeyBeginRequest.create({
          query: props.query,
        }),
      );

      const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(
        JSON.parse(response.request),
      );
      const credential = (await navigator.credentials.get({
        publicKey,
      })) as PublicKeyCredential;

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
    onError: (err) => {
      props.setPending(null);

      toast.error("Passkey sign-in failed. Please try again.");
    },
  });

  return (
    <div className="w-full">
      <button
        disabled={busy}
        aria-busy={props.pending === PASSKEY_ID}
        className={twMerge(
          "w-full px-2 py-4 md:py-6 transition-all duration-500 mb-4",
          "shadow-2xl rounded-lg cursor-pointer",
          "bg-[#242323] hover:bg-black text-white text-lg",
          busy ? "!bg-[#777] shadow-none" : undefined,
        )}
        onClick={() => {
          mutation.mutate();
        }}
      >
        <span className="flex items-center justify-center gap-2 font-bold text-lg">
          <IoIosFingerPrint className="h-8 w-8 shrink-0" aria-hidden />
          <span className="font-semibold">Login with a Passkey</span>
        </span>
      </button>
    </div>
  );
};

const Page = () => {
  const state = getState();

  const [pending, setPending] = React.useState<string | null>(null);
  const [reqCommon, setReqCommon] = React.useState<authReqCommon | null>(null);

  const [searchParams, setSearchParams] = useSearchParams();

  React.useEffect(() => {
    const query = searchParams.toString();

    setReqCommon({
      query: query || undefined,
      userAgent: window.navigator.userAgent,
    });

    const err = searchParams.get("error");
    if (err) {
      console.log("Error: ", err);
    }

    setSearchParams(new URLSearchParams(), { replace: true });
  }, []);

  const busy = pending !== null;
  const providers = state.identityProviders ?? [];
  const hasProviders = providers.length > 0;

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
        return res.json();
      })
      .then((data: authResponse) => {
        if (!data.loginURL) {
          throw new Error("missing loginURL");
        }
        window.location.href = data.loginURL;
      })
      .catch(() => {
        setPending(null);
        toast.error("Could not login. Please try again.");
      });
  };

  return (
    <div>
      <div className="flex items-center justify-center mt-4 mb-3">
        <LogoMain />
      </div>

      {!hasProviders && (
        <div className="container mx-auto mt-2 p-2 md:p-8 w-full max-w-lg">
          {!state.isPasskeyLoginEnabled && (
            <h2 className="font-bold text-2xl text-slate-700 flex items-center justify-center mb-4 text-center">
              No Available Identity Providers
            </h2>
          )}

          {state.isPasskeyLoginEnabled && (
            <div>
              <Passkey
                query={reqCommon?.query}
                pending={pending}
                setPending={setPending}
              />
            </div>
          )}
        </div>
      )}
      {hasProviders && (
        <div className="container mx-auto mt-2 p-2 md:p-4 w-full max-w-lg">
          <h1 className="font-bold text-xl mb-4 text-zinc-700 text-center">
            <span>Login to</span>
            <span> </span>
            <span className="text-black">Octelium</span>
            <span> </span>
            <span>with an Identity Provider</span>
          </h1>

          <div className="flex flex-col items-center justify-center">
            {providers.map((c) => {
              return (
                <button
                  className={twMerge(
                    "w-full px-2 py-4 md:py-6 transition-all duration-500 mb-4",
                    "shadow-2xl rounded-lg cursor-pointer",
                    "bg-[#242323] hover:bg-black text-white text-lg",
                    busy ? "!bg-[#777] shadow-none" : undefined,
                  )}
                  disabled={busy}
                  aria-busy={pending === c.uid}
                  key={c.uid}
                  onClick={() => beginLogin(c.uid)}
                >
                  <div className="w-full flex flex-row items-center justify-center">
                    <span className="flex-1 flex items-center justify-center font-semibold">
                      {c.displayName}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
          {state.isPasskeyLoginEnabled && (
            <div>
              <Divider my="lg" label="OR" labelPosition="center" />
              <Passkey
                query={reqCommon?.query}
                pending={pending}
                setPending={setPending}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Page;
