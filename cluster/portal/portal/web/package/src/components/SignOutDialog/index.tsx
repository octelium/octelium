import { getClientAuth } from "@/utils/client";
import { describeRpcError } from "@/utils/rpcError";
import { Button, Modal } from "@mantine/core";
import { LogoutRequest } from "@octelium/apis/main/userv1";
import { useMutation } from "@tanstack/react-query";
import { AlertCircle, LogOut, X } from "lucide-react";

const SignOutDialog = (props: { opened: boolean; onClose: () => void }) => {
  const mutation = useMutation({
    mutationFn: async () => {
      await getClientAuth().logout(LogoutRequest.create());
    },
    onSuccess: () => {
      window.location.reload();
    },
  });

  return (
    <Modal
      opened={props.opened}
      onClose={props.onClose}
      centered
      withCloseButton={false}
      padding={0}
      size="sm"
      closeOnEscape={!mutation.isPending}
      closeOnClickOutside={!mutation.isPending}
    >
      <div className="flex flex-col">
        <div className="flex items-center gap-2 border-b border-slate-200 bg-slate-50/70 px-5 py-3.5">
          <LogOut
            size={14}
            className="shrink-0 text-red-500"
            strokeWidth={2.25}
            aria-hidden
          />
          <Modal.Title className="text-body font-semibold leading-5 text-slate-900">
            Sign out
          </Modal.Title>
        </div>

        <div className="flex flex-col gap-3 px-5 py-4">
          <p className="text-body font-normal text-slate-600">
            Are you sure you want to sign out of this session?
          </p>
          {mutation.isError && (
            <p
              role="alert"
              className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs font-medium text-red-700"
            >
              <AlertCircle size={14} className="mt-px shrink-0" aria-hidden />
              {describeRpcError(mutation.error).message}
            </p>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-slate-200 bg-slate-50/70 px-5 py-3">
          <Button
            variant="default"
            size="sm"
            leftSection={<X size={13} strokeWidth={2.25} />}
            disabled={mutation.isPending}
            onClick={props.onClose}
          >
            Cancel
          </Button>
          <Button
            variant="filled"
            color="red"
            size="sm"
            leftSection={<LogOut size={13} strokeWidth={2.25} />}
            loading={mutation.isPending}
            onClick={() => mutation.mutate()}
            data-autofocus
          >
            Sign out
          </Button>
        </div>
      </div>
    </Modal>
  );
};

export default SignOutDialog;
