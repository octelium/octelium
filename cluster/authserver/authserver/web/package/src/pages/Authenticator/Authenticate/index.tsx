import * as React from "react";

import { isDev, queryClient } from "@/utils";

import ActionButton from "@/components/ActionButton";
import AuthPage from "@/components/AuthPage";
import CodeInput from "@/components/CodeInput";
import TimeAgo from "@/components/TimeAgo";
import { getClientAuth } from "@/utils/client";
import { getResourceRef } from "@/utils/pb";
import {
  ActionIcon,
  Button,
  Collapse,
  Loader,
  Modal,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { Timestamp } from "@octelium/apis/google/protobuf/timestamp";
import * as Auth from "@octelium/apis/main/authv1";
import { DeleteOptions } from "@octelium/apis/main/metav1";
import { useMutation, useQuery } from "@tanstack/react-query";
import { IoIosFingerPrint } from "react-icons/io";
import {
  LuCheck,
  LuPencil,
  LuPencilOff,
  LuPlus,
  LuRotateCw,
  LuSmartphone,
  LuTrash2,
} from "react-icons/lu";
import { useSearchParams } from "react-router-dom";
import { ReturnToPortal } from "../Register";

const buildSuccessURL = (query: URLSearchParams | null) => {
  const qs = query?.toString() ?? "";
  return qs.length > 0 ? `/callback/success?${qs}` : "/callback/success";
};

const isUserCancellation = (err: unknown) =>
  err instanceof DOMException &&
  (err.name === "NotAllowedError" || err.name === "AbortError");

const TOTP = (props: {
  authn: Auth.Authenticator;
  query: URLSearchParams | null;
}) => {
  const { authn, query } = props;

  const c = getClientAuth();
  const [otp, setOtp] = React.useState("");

  const mutation = useMutation({
    mutationFn: async (otp: string) => {
      await c.authenticateAuthenticatorBegin(
        Auth.AuthenticateAuthenticatorBeginRequest.create({
          authenticatorRef: getResourceRef(authn),
        }),
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
        }),
      );
    },
    onSuccess: () => {
      window.location.href = buildSuccessURL(query);
    },
    onError: () => {
      setOtp("");
      notifications.show({
        color: "red",
        message: "Could not verify the code. Please try again.",
      });
    },
  });

  return (
    <div className="flex w-full flex-col items-center gap-4">
      <h2 className="text-center text-sm font-semibold text-fg-muted">
        Enter the 6-digit code from your authenticator app
      </h2>

      <CodeInput
        value={otp}
        disabled={mutation.isPending}
        onChange={setOtp}
        onComplete={(val) => {
          mutation.mutate(val);
        }}
      />
      {mutation.isPending && (
        <div
          className="flex items-center gap-2 text-sm font-semibold text-fg-subtle"
          role="status"
        >
          <Loader size="xs" /> Verifying…
        </div>
      )}
    </div>
  );
};

const Fido = (props: {
  authn: Auth.Authenticator;
  query: URLSearchParams | null;
}) => {
  const { authn, query } = props;

  const c = getClientAuth();
  const startedRef = React.useRef(false);

  const mutation = useMutation({
    mutationFn: async () => {
      if (
        typeof PublicKeyCredential === "undefined" ||
        typeof PublicKeyCredential.parseRequestOptionsFromJSON !== "function"
      ) {
        throw new Error("Security keys are not supported by this browser");
      }

      const { response } = await c.authenticateAuthenticatorBegin(
        Auth.AuthenticateAuthenticatorBeginRequest.create({
          authenticatorRef: getResourceRef(authn),
        }),
      );

      if (response.challengeRequest?.type.oneofKind !== `fido`) {
        throw new Error("Unexpected challenge type");
      }

      const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(
        JSON.parse(response.challengeRequest.type.fido.request),
      );
      const credential = (await navigator.credentials.get({
        publicKey,
      })) as PublicKeyCredential;
      if (!credential) {
        throw new Error("No security key credential was returned");
      }

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
        }),
      );
    },
    onSuccess: () => {
      window.location.href = buildSuccessURL(query);
    },
    onError: (err) => {
      if (!isUserCancellation(err)) {
        notifications.show({
          color: "red",
          message: "Could not verify your security key. Please try again.",
        });
      }
    },
  });
  const { mutate } = mutation;

  React.useEffect(() => {
    if (startedRef.current) {
      return;
    }
    startedRef.current = true;
    mutate();
  }, [mutate]);

  return (
    <div className="flex w-full flex-col items-center gap-4">
      {mutation.isPending && (
        <h2
          className="flex items-center justify-center gap-2 text-center text-sm font-semibold text-fg-muted"
          role="status"
        >
          <Loader size="xs" />
          Waiting for your security key
        </h2>
      )}
      {mutation.isError && (
        <>
          <h2 className="text-center text-sm font-semibold text-fg-muted">
            Authentication was not completed
          </h2>
          <ActionButton
            label="Try again"
            Icon={LuRotateCw}
            primary
            onClick={() => {
              mutation.mutate();
            }}
          />
        </>
      )}
    </div>
  );
};

const UnsupportedAuthenticator = () => (
  <div
    className="text-center text-sm font-semibold text-red-700 dark:text-red-300"
    role="alert"
  >
    This authenticator type is not supported by this version of the portal.
  </div>
);

const Challenge = (props: {
  authn: Auth.Authenticator;
  query: URLSearchParams | null;
}) => {
  const { authn, query } = props;

  if (authn.status?.type === Auth.Authenticator_Status_Type.FIDO) {
    return <Fido authn={authn} query={query} />;
  }

  if (authn.status?.type === Auth.Authenticator_Status_Type.TOTP) {
    return <TOTP authn={authn} query={query} />;
  }

  return <UnsupportedAuthenticator />;
};

export const Authenticator = (props: {
  authn: Auth.Authenticator;
  query: URLSearchParams | null;
}) => {
  const { authn, query } = props;
  const [open, setOpen] = React.useState(false);
  const [isEdit, setIsEdit] = React.useState(false);
  const [displayName, setDisplayName] = React.useState(
    authn.spec?.displayName ?? "",
  );
  const canonicalName = authn.metadata?.name ?? "Unnamed authenticator";
  const isFido = authn.status?.type === Auth.Authenticator_Status_Type.FIDO;
  const isTotp = authn.status?.type === Auth.Authenticator_Status_Type.TOTP;
  const TypeIcon = isFido ? IoIosFingerPrint : LuSmartphone;

  const isDelete = useDisclosure(false);
  const c = getClientAuth();

  const mutationDelete = useMutation({
    mutationFn: async () => {
      return await c.deleteAuthenticator(
        DeleteOptions.create({
          uid: authn.metadata?.uid,
          name: authn.metadata?.name,
        }),
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["getAvailableAuthenticator"],
      });
    },
    onError: () => {
      notifications.show({
        color: "red",
        message: "Could not delete the Authenticator. Please try again.",
      });
    },
  });

  const mutationUpdate = useMutation({
    mutationFn: async () => {
      const req = Auth.Authenticator.clone(authn);
      if (!req.spec) {
        throw new Error("Authenticator specification is missing");
      }
      req.spec.displayName = displayName.trim();

      await c.updateAuthenticator(req);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["getAvailableAuthenticator"],
      });
      setIsEdit(false);
    },
    onError: () => {
      notifications.show({
        color: "red",
        message: "Could not update the Authenticator. Please try again.",
      });
    },
  });

  return (
    <div className="w-full rounded-xl border border-line bg-surface p-4 shadow-xs">
      <div className="flex items-start gap-3">
        <span
          aria-hidden
          className="flex h-10 w-10 flex-none items-center justify-center rounded-lg bg-surface-strong text-fg"
        >
          <TypeIcon className="h-5 w-5" />
        </span>

        <div className="min-w-0 flex-1">
          {!isEdit && (
            <div className="break-words font-bold text-fg">
              {displayName.length > 0 ? displayName : canonicalName}
            </div>
          )}
          {isEdit && (
            <div className="flex min-w-0 items-center gap-1">
              <TextInput
                className="min-w-0 flex-1"
                size="xs"
                placeholder="My Authenticator"
                aria-label="Authenticator display name"
                autoFocus
                value={displayName}
                onChange={(e) => {
                  setDisplayName(e.target.value);
                }}
                onKeyDown={(e) => {
                  if (
                    e.key === "Enter" &&
                    !mutationUpdate.isPending &&
                    displayName.trim().length > 0
                  ) {
                    mutationUpdate.mutate();
                  }
                }}
              />

              <ActionIcon
                aria-label="Save Display Name"
                disabled={
                  mutationUpdate.isPending || displayName.trim().length === 0
                }
                loading={mutationUpdate.isPending}
                onClick={() => {
                  mutationUpdate.mutate();
                }}
              >
                <LuCheck />
              </ActionIcon>
            </div>
          )}

          {displayName.length > 0 && (
            <div className="break-words text-xs font-medium text-fg-muted">
              {canonicalName}
            </div>
          )}
          {!!authn.status?.description && (
            <div className="text-xs font-medium text-fg-subtle">
              {authn.status.description}
            </div>
          )}
          <div className="mt-1 text-xs font-medium text-fg-subtle">
            {isFido && "FIDO · "}
            {isTotp && "TOTP · "}
            <span>Created </span>
            <TimeAgo rfc3339={authn.metadata?.createdAt} />
          </div>
        </div>

        <div className="flex flex-none items-center">
          <Tooltip label="Edit Display Name">
            <ActionIcon
              className="!text-fg-subtle transition-colors duration-500 hover:!text-fg"
              variant="subtle"
              color="gray"
              size="lg"
              aria-label="Edit Display Name"
              onClick={() => {
                setIsEdit(!isEdit);
              }}
            >
              {isEdit ? <LuPencilOff /> : <LuPencil />}
            </ActionIcon>
          </Tooltip>
          <Tooltip label="Delete">
            <ActionIcon
              className="!text-fg-subtle transition-colors duration-500 hover:!text-fg"
              variant="subtle"
              color="gray"
              size="lg"
              aria-label="Delete"
              onClick={isDelete[1].open}
            >
              <LuTrash2 />
            </ActionIcon>
          </Tooltip>
        </div>
      </div>

      {authn.status?.isRegistered && (
        <Button
          className="mt-4"
          fullWidth
          size="md"
          variant={open ? "default" : undefined}
          onClick={() => {
            setOpen(!open);
          }}
        >
          {open ? "Cancel" : "Authenticate"}
        </Button>
      )}

      <Collapse expanded={open} transitionDuration={300}>
        {open && (
          <div className="pt-4">
            <Challenge authn={authn} query={query} />
          </div>
        )}
      </Collapse>

      <Modal
        opened={isDelete[0]}
        onClose={isDelete[1].close}
        title="Delete this Authenticator?"
      >
        <p className="text-sm leading-6 text-fg-muted">
          You will no longer be able to use{" "}
          <span className="font-semibold text-fg">
            {displayName.length > 0 ? displayName : canonicalName}
          </span>{" "}
          to verify your identity.
        </p>

        <div className="mt-6 flex items-center justify-end gap-3">
          <Button variant="default" onClick={isDelete[1].close}>
            Cancel
          </Button>
          <Button
            color="red"
            loading={mutationDelete.isPending}
            onClick={() => {
              mutationDelete.mutate();
            }}
            autoFocus
          >
            Delete
          </Button>
        </div>
      </Modal>
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
        description: "FIDO Security Key",
      },
    }),
  ],
});

const getDevAuthenticators = () => {
  const value = (
    window as Window & {
      __OCTELIUM_AUTHENTICATORS__?: { main?: string; items?: string[] };
    }
  ).__OCTELIUM_AUTHENTICATORS__;

  return Auth.GetAvailableAuthenticatorResponse.create({
    mainAuthenticator: devList.items.find(
      (x) => x.metadata?.name === value?.main,
    ),
    availableAuthenticators: devList.items.filter(
      (x) => !value?.items || value.items.includes(x.metadata?.name ?? ""),
    ),
  });
};

export const WithAuthenticators = (props: {
  children: (data: Auth.GetAvailableAuthenticatorResponse) => React.ReactNode;
}) => {
  const c = getClientAuth();

  const { isError, isLoading, data, refetch } = useQuery({
    queryKey: ["getAvailableAuthenticator"],
    queryFn: async () => {
      if (isDev()) {
        return getDevAuthenticators();
      }
      const { response } = await c.getAvailableAuthenticator({});
      return response;
    },
  });

  if (isLoading) {
    return (
      <main className="flex flex-1 items-center justify-center">
        <Loader aria-label="Loading authenticators" />
      </main>
    );
  }

  if (isError || !data) {
    return (
      <div className="flex flex-1 flex-col" role="alert">
        <AuthPage title="Could not load your Authenticators">
          <ActionButton
            label="Try again"
            Icon={LuRotateCw}
            primary
            onClick={() => refetch()}
          />
          <ReturnToPortal />
        </AuthPage>
      </div>
    );
  }

  return props.children(data);
};

export const ListAvailableAuthenticators = (props: {
  resp: Auth.GetAvailableAuthenticatorResponse;
  query: URLSearchParams | null;
}) => {
  const { resp, query } = props;

  if (resp.availableAuthenticators.length < 1) {
    return (
      <AuthPage
        title="No Authenticators yet"
        description="Register an Authenticator to verify your identity."
      >
        <ActionButton
          label="Register an Authenticator"
          Icon={LuPlus}
          primary
          to="/authenticators/register"
        />
        <ReturnToPortal />
      </AuthPage>
    );
  }

  return (
    <AuthPage
      compact
      wide
      title="Your Authenticators"
      description="Authenticate with one of your Authenticators or register a new one."
    >
      {resp.mainAuthenticator && (
        <section className="mb-7">
          <h2 className="mb-2.5 text-sm font-semibold text-fg-subtle">
            Your Session's Main Authenticator
          </h2>

          <Authenticator authn={resp.mainAuthenticator} query={query} />
        </section>
      )}

      <section>
        {resp.mainAuthenticator && (
          <h2 className="mb-2.5 text-sm font-semibold text-fg-subtle">
            Your Available Authenticators
          </h2>
        )}
        <div className="flex flex-col gap-2.5">
          {resp.availableAuthenticators.map((x, index) => (
            <Authenticator
              key={x.metadata?.uid || x.metadata?.name || index}
              authn={x}
              query={query}
            />
          ))}

          <ActionButton
            label="Register an Authenticator"
            Icon={LuPlus}
            quiet
            to="/authenticators/register"
          />
        </div>
      </section>

      <ReturnToPortal />
    </AuthPage>
  );
};

const Page = () => {
  const [searchParams, setSearchParams] = useSearchParams();

  const [query] = React.useState(() => new URLSearchParams(searchParams));

  React.useEffect(() => {
    if (searchParams.toString()) {
      setSearchParams(new URLSearchParams(), { replace: true });
    }
  }, [searchParams, setSearchParams]);

  return (
    <>
      <title>Authenticate with an Authenticator - Octelium</title>
      <WithAuthenticators>
        {(data) =>
          data.mainAuthenticator ? (
            <AuthPage
              title="Verify your identity"
              description={
                data.mainAuthenticator.spec?.displayName ||
                data.mainAuthenticator.metadata?.name
              }
            >
              <Challenge authn={data.mainAuthenticator} query={query} />
              <ReturnToPortal />
            </AuthPage>
          ) : (
            <ListAvailableAuthenticators resp={data} query={query} />
          )
        }
      </WithAuthenticators>
    </>
  );
};

export default Page;
