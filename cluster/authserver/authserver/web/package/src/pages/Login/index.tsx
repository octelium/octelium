import * as React from "react";
import { Outlet } from "react-router-dom";

import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { twMerge } from "tailwind-merge";

import { toast } from "react-hot-toast";
import { isDev } from "@/utils";
import * as Auth from "@/apis/authv1/authv1";
import { getClientAuth } from "@/utils/client";
import { useMutation } from "@tanstack/react-query";
import { Divider } from "@mantine/core";
import LogoMain from "@/components/LogoMain";

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

function getState() {
  if (!isDev()) {
    return (window as any).__OCTELIUM_STATE__ as State;
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
      {
        uid: "gitlab-2",
        displayName: "Gitlab",
      },
    ],
  } as State;
}

const Passkey = (props: { query?: string }) => {
  const c = getClientAuth();

  const mutation = useMutation({
    mutationFn: async () => {
      const { response } = await c.authenticateWithPasskeyBegin(
        Auth.AuthenticateWithPasskeyBeginRequest.create({
          query: props.query,
        })
      );

      try {
        const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(
          JSON.parse(response.request)
        );
        const credential = (await navigator.credentials.get({
          publicKey,
        })) as PublicKeyCredential;

        return await c.authenticateWithPasskey(
          Auth.AuthenticateWithPasskeyRequest.create({
            response: JSON.stringify(credential.toJSON()),
          })
        );
      } catch (err) {
        console.log("fido get err", err);
        throw err;
      }
    },
    onSuccess: (r) => {
      window.location.href = "/callback/success";
    },
    onError: (resp) => {},
  });

  return (
    <div className="w-full">
      <button
        disabled={mutation.isPending}
        className={twMerge(
          "w-full px-2 py-4 md:py-6 font-bold transition-all duration-500 mb-4",
          "shadow-2xl rounded-lg cursor-pointer font-bold",
          "bg-[#242323] hover:bg-black text-white text-lg",
          mutation.isPending ? "!bg-[#777] shadow-none" : undefined
        )}
        onClick={() => {
          mutation.mutate();
        }}
      >
        <span className="font-bold text-lg">Login with a Passkey</span>
      </button>
    </div>
  );
};

const Page = () => {
  const state = getState();

  let [loginActive, setLoginActive] = React.useState<boolean>(false);
  let [reqCommon, setReqCommon] = React.useState<authReqCommon | null>(null);

  const [searchParams, setSearchParams] = useSearchParams();

  React.useEffect(() => {
    setReqCommon({
      query: searchParams.toString() ?? undefined,
      userAgent: window.navigator.userAgent,
    });

    if (searchParams.has("error")) {
      toast.error(searchParams.get("error"));
    }
    searchParams.forEach((val, key, parent) => {
      searchParams.delete(key);
    });
    setSearchParams(searchParams);
  }, []);

  return (
    <div>
      <div className="flex items-center justify-center mt-4 mb-3">
        <LogoMain />
      </div>

      {(!state.identityProviders || state.identityProviders.length < 1) && (
        <div className="container mx-auto mt-2 p-2 md:p-8 w-full max-w-lg">
          {!state.isPasskeyLoginEnabled && (
            <h2 className="font-bold text-2xl text-slate-700 flex items-center justify-center mb-4 text-center">
              No Available Identity Providers
            </h2>
          )}

          {state.isPasskeyLoginEnabled && (
            <div>
              <Passkey query={reqCommon?.query} />
            </div>
          )}
        </div>
      )}
      {state.identityProviders && state.identityProviders.length > 0 && (
        <div className="container mx-auto mt-2 p-2 md:p-4 w-full max-w-lg">
          <div
            className="font-bold text-xl mb-4 text-zinc-700 text-center"
            style={{
              textShadow: "0 2px 8px rgba(0, 0, 0, 0.2)",
            }}
          >
            <span>Login to</span>
            <span> </span>
            <span className="text-black">Octelium</span>
            <span> </span>
            <span>with an Identity Provider</span>
          </div>

          <div className="flex flex-col items-center justify-center">
            {state.identityProviders.map((c) => {
              return (
                <button
                  className={twMerge(
                    "w-full px-2 py-4 md:py-6 font-bold transition-all duration-500 mb-4",
                    "shadow-2xl rounded-lg cursor-pointer font-bold",
                    "bg-[#242323] hover:bg-black text-white text-lg",
                    loginActive ? "!bg-[#777] shadow-none" : undefined
                  )}
                  disabled={loginActive}
                  key={c.uid}
                  onClick={() => {
                    setLoginActive(true);
                    fetch("/begin", {
                      method: "POST",
                      headers: {
                        "Content-Type": "application/json",
                        Accept: "application/json",
                      },
                      body: JSON.stringify({
                        uid: c.uid,
                        ...reqCommon,
                      }),
                    })
                      .then((res) => res.json())
                      .then((data: authResponse) => {
                        window.location.href = data.loginURL;
                      });
                  }}
                >
                  <div className="w-full flex flex-row items-center justify-center">
                    <span className="flex-1 flex items-center justify-center font-bold">
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
              <Passkey query={reqCommon?.query} />
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Page;
