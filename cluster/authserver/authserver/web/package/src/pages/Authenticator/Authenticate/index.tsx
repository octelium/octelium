import * as React from "react";

import { isDev, queryClient } from "@/utils";

import TimeAgo from "@/components/TimeAgo";
import { getClientAuth } from "@/utils/client";
import { getResourceRef } from "@/utils/pb";
import {
  ActionIcon,
  Button,
  Collapse,
  Input,
  Loader,
  Modal,
  PinInput,
  Tooltip,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Timestamp } from "@octelium/apis/google/protobuf/timestamp";
import * as Auth from "@octelium/apis/main/authv1";
import { DeleteOptions } from "@octelium/apis/main/metav1";
import { useMutation, useQuery } from "@tanstack/react-query";
import toast from "react-hot-toast";
import { IoMdSend } from "react-icons/io";
import { MdEdit, MdEditOff } from "react-icons/md";
import { Link, useSearchParams } from "react-router-dom";
import { twMerge } from "tailwind-merge";
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
      toast.error("Could not verify the code. Please try again.");
    },
  });

  return (
    <div className="w-full flex flex-col items-center justify-center">
      <h2 className="font-bold text-xl text-slate-700 flex items-center justify-center my-4 text-center">
        Enter the OTP
      </h2>

      <PinInput
        type={"number"}
        inputType="number"
        inputMode="numeric"
        length={6}
        autoFocus
        size="lg"
        value={otp}
        disabled={mutation.isPending}
        onChange={setOtp}
        onComplete={(val) => {
          mutation.mutate(val);
        }}
      />
      {mutation.isPending && (
        <div className="mt-3 flex items-center gap-2 text-sm font-semibold text-slate-500" role="status">
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
        toast.error("Could not verify your security key. Please try again.");
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
    <div className="w-full flex flex-col items-center justify-center my-4">
      {mutation.isPending && (
        <h2
          className="font-bold text-xl text-slate-700 flex items-center justify-center gap-2 my-4 text-center"
          role="status"
        >
          <Loader size="sm" />
          Waiting for your security key
        </h2>
      )}
      {mutation.isError && (
        <div className="w-full flex flex-col items-center justify-center">
          <h2 className="font-bold text-xl text-slate-700 flex items-center justify-center my-4 text-center">
            Authentication was not completed
          </h2>
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
      toast.error("Could not delete the Authenticator. Please try again.");
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
      toast.error("Could not update the Authenticator. Please try again.");
    },
  });

  return (
    <div
      className={twMerge(
        "w-full",
        "p-4 mb-3",

        `bg-slate-50 hover:bg-white`,
        `border-[2px] border-gray-200 rounded-lg`,
        "w-full",

        "transition-all duration-300",
        // "hover:bg-transparent",
        "py-4 px-2",
        "font-semibold",
        "rounded-xl",
        "shadow-sm shadow-slate-200",
        "border-[2px] border-slate-300",
        "mb-4",
      )}
    >
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
        <div className="min-w-0 flex-1 font-bold">
          <div className="flex min-w-0 items-start gap-2">
            <span className="flex-none text-white bg-slate-800 rounded-lg py-2 px-2 text-xs shadow-md">
              {authn.status?.type === Auth.Authenticator_Status_Type.FIDO &&
                "FIDO"}
              {authn.status?.type === Auth.Authenticator_Status_Type.TOTP &&
                "TOTP"}
            </span>{" "}
            <div className="min-w-0 flex-1">
              <div className="text-black flex min-w-0 items-center w-full">
                <Tooltip label="Edit Display Name">
                  <ActionIcon
                    variant="transparent"
                    aria-label="Edit Display Name"
                    onClick={() => {
                      setIsEdit(!isEdit);
                    }}
                  >
                    {isEdit ? (
                      <MdEditOff className="text-slate-500" />
                    ) : (
                      <MdEdit className="text-slate-500" />
                    )}
                  </ActionIcon>
                </Tooltip>

                {!isEdit && (
                  <span>
                    {displayName.length > 0 ? displayName : canonicalName}
                  </span>
                )}
                {isEdit && (
                  <div className="flex min-w-0 flex-1 items-center w-full">
                    <Input
                      placeholder="My Authenticator"
                      variant={"unstyled"}
                      aria-label="Authenticator display name"
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
                      aria-label="Submit"
                      disabled={
                        mutationUpdate.isPending || displayName.trim().length === 0
                      }
                      loading={mutationUpdate.isPending}
                      onClick={() => {
                        mutationUpdate.mutate();
                      }}
                    >
                      <IoMdSend />
                    </ActionIcon>
                  </div>
                )}
              </div>

              {displayName.length > 0 && (
                <div className="break-words text-slate-700 text-xs">
                  {canonicalName}
                </div>
              )}
              {!!authn.status?.description && (
                <div className="text-slate-500 text-xs ml-1">
                  {authn.status.description}
                </div>
              )}
            </div>
          </div>
          <div className="text-xs mt-1 mb-2 text-slate-500">
            <span>Created </span>
            <TimeAgo rfc3339={authn.metadata?.createdAt} />
          </div>
        </div>
        <div className="flex w-full flex-row items-center gap-2 sm:w-auto sm:flex-col sm:items-stretch">
          {authn.status?.isRegistered && (
            <Button
              className="w-full sm:w-auto"
              onClick={() => {
                setOpen(!open);
              }}
              variant={open ? "outline" : undefined}
            >
              {open ? "Cancel" : "Authenticate"}
            </Button>
          )}
          <Button
            className="mt-0 w-full !rounded-md !transition-all !duration-500 !border-slate-500 sm:mt-3"
            fullWidth
            size="compact-xs"
            variant="outline"
            onClick={isDelete[1].open}
          >
            <span className="text-slate-600">Delete</span>
          </Button>
        </div>
      </div>

      <Collapse expanded={open} transitionDuration={300}>
        {open && (
          <div>
            {authn.status?.type === Auth.Authenticator_Status_Type.FIDO && (
              <Fido authn={authn} query={query} />
            )}

            {authn.status?.type === Auth.Authenticator_Status_Type.TOTP && (
              <TOTP authn={authn} query={query} />
            )}

            {authn.status?.type !== Auth.Authenticator_Status_Type.FIDO &&
              authn.status?.type !== Auth.Authenticator_Status_Type.TOTP && (
                <div
                  className="my-4 text-center text-sm font-semibold text-red-700"
                  role="alert"
                >
                  This authenticator type is not supported by this version of the portal.
                </div>
              )}
          </div>
        )}
      </Collapse>

      <Modal opened={isDelete[0]} onClose={isDelete[1].close} centered>
        <div className="font-bold text-xl mb-4">
          {`Do you really want to delete this Authenticator?`}
        </div>

        <div className="mt-4 flex justify-end items-center">
          <Button variant="outline" onClick={isDelete[1].close}>
            Cancel
          </Button>
          <Button
            className="ml-4"
            loading={mutationDelete.isPending}
            onClick={() => {
              mutationDelete.mutate();
            }}
            autoFocus
          >
            Yes, Delete
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

export const ListAvailableAuthenticators = (props: {
  resp: Auth.GetAvailableAuthenticatorResponse;
  query: URLSearchParams | null;
}) => {
  const { resp, query } = props;

  if (resp.availableAuthenticators.length < 1) {
    return (
      <div className="w-full">
        <div className="font-bold text-xl text-slate-700 flex items-center justify-center my-2 text-center">
          You have no Available Authenticators{" "}
          <Button
            className="ml-2 shadow-md"
            component={Link}
            to={`/authenticators/register`}
          >
            Register
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full">
      {resp.mainAuthenticator && (
        <div className="mb-24">
          <div className="font-bold text-xl text-slate-700 flex items-center justify-center my-2 text-center">
            Your Session's Main Authenticator
          </div>

          <Authenticator authn={resp.mainAuthenticator} query={query} />
        </div>
      )}
      <div>
        <h2 className="font-bold text-xl text-slate-700 flex items-center justify-center my-4 text-center">
          Your Available Authenticators{" "}
          <Button
            className="ml-2 shadow-md"
            component={Link}
            to={`/authenticators/register`}
          >
            Register
          </Button>
        </h2>
        <div className="w-full">
          {resp.availableAuthenticators.map((x, index) => (
            <Authenticator
              key={x.metadata?.uid || x.metadata?.name || index}
              authn={x}
              query={query}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

const Page = () => {
  const c = getClientAuth();
  const [searchParams, setSearchParams] = useSearchParams();

  const [query] = React.useState(() => new URLSearchParams(searchParams));

  React.useEffect(() => {
    if (searchParams.toString()) {
      setSearchParams(new URLSearchParams(), { replace: true });
    }
  }, [searchParams, setSearchParams]);

  const { isError, isLoading, data, refetch } = useQuery({
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
    return (
      <div className="w-full flex items-center justify-center my-24">
        <Loader aria-label="Loading authenticators" />
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="container mx-auto mt-2 p-2 md:p-4 w-full max-w-lg">
        <div
          className="flex flex-col items-center justify-center my-4 text-center"
          role="alert"
        >
          <div className="font-bold text-xl text-slate-700">
            Could not load your Authenticators.
          </div>
          <Button className="mt-4" onClick={() => refetch()}>
            Try again
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div>
      <title>Authenticate with an Authenticator - Octelium</title>
      <div className="container mx-auto mt-2 p-2 md:p-4 w-full max-w-lg">
        {data.mainAuthenticator && (
          <div>
            {data.mainAuthenticator.status?.type ===
              Auth.Authenticator_Status_Type.FIDO && (
              <Fido authn={data.mainAuthenticator} query={query} />
            )}

            {data.mainAuthenticator.status?.type ===
              Auth.Authenticator_Status_Type.TOTP && (
              <TOTP authn={data.mainAuthenticator} query={query} />
            )}

            {data.mainAuthenticator.status?.type !==
              Auth.Authenticator_Status_Type.FIDO &&
              data.mainAuthenticator.status?.type !==
                Auth.Authenticator_Status_Type.TOTP && (
                <div className="my-4 text-center text-sm font-semibold text-red-700" role="alert">
                  This authenticator type is not supported by this version of the portal.
                </div>
              )}
          </div>
        )}

        {!data.mainAuthenticator && (
          <ListAvailableAuthenticators resp={data} query={query} />
        )}
      </div>
      <ReturnToPortal />
    </div>
  );
};

export default Page;
