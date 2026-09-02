import type {
  IronError,
  UserInteraction,
} from "@devolutions/iron-remote-desktop";

export type RdpExtensions = {
  displayControl: (enabled: boolean) => unknown;
  preConnectionBlob: (value: string) => unknown;
  kdcProxyUrl: (value: string) => unknown;
  enableCredssp?: (enabled: boolean) => unknown;
};

export type LoadedIronRdp = {
  backend: unknown;
  extensions: RdpExtensions;
};

export async function loadIronRdp(): Promise<LoadedIronRdp> {
  const [coreMod, rdpMod] = await Promise.all([
    import("@devolutions/iron-remote-desktop"),
    import("@devolutions/iron-remote-desktop-rdp"),
  ]);

  await rdpMod.init("INFO");

  void coreMod;

  return {
    backend: rdpMod.Backend,
    extensions: {
      displayControl: rdpMod.displayControl,
      preConnectionBlob: rdpMod.preConnectionBlob,
      kdcProxyUrl: rdpMod.kdcProxyUrl,
      enableCredssp: rdpMod.enableCredssp,
    },
  };
}

export function getReadyUserInteraction(event: Event): UserInteraction | null {
  const customEvent = event as CustomEvent;
  const detail = customEvent.detail;
  const candidate = detail?.irgUserInteraction ?? detail;

  if (
    typeof candidate !== "object" ||
    candidate === null ||
    typeof (candidate as UserInteraction).configBuilder !== "function" ||
    typeof (candidate as UserInteraction).connect !== "function" ||
    typeof (candidate as UserInteraction).setVisibility !== "function" ||
    typeof (candidate as UserInteraction).shutdown !== "function"
  ) {
    return null;
  }

  return candidate as UserInteraction;
}

export function isIronError(error: unknown): error is IronError {
  return (
    typeof error === "object" &&
    error !== null &&
    typeof (error as IronError).backtrace === "function" &&
    typeof (error as IronError).kind === "function"
  );
}

export function getErrorMessage(error: unknown): string {
  if (isIronError(error)) {
    return error.backtrace();
  }

  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}
