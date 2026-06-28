export type OcteliumRdpWebGlobals = {
  webSocketPath?: string;
  destination?: string;
};

declare global {
  interface Window {
    __OCTELIUM_RDP_WEB__?: OcteliumRdpWebGlobals;
  }
}

export function getRdpWebGlobals(): Required<OcteliumRdpWebGlobals> {
  const globals = window.__OCTELIUM_RDP_WEB__ ?? {};

  return {
    webSocketPath: normalizePath(globals.webSocketPath || "/ws"),
    destination: globals.destination?.trim() || "octelium-rdp:3389",
  };
}

export function getWebSocketURL(path: string): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${normalizePath(path)}`;
}

function normalizePath(path: string): string {
  const trimmed = path.trim();
  if (trimmed === "") {
    return "/ws";
  }

  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}
