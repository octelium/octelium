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
  const webSocketPath =
    typeof globals.webSocketPath === "string" ? globals.webSocketPath : "/ws";
  const destination =
    typeof globals.destination === "string" ? globals.destination.trim() : "";

  return {
    webSocketPath: normalizePath(webSocketPath),
    destination: destination || "octelium-rdp:3389",
  };
}

export function getWebSocketURL(path: string): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${normalizePath(path)}`;
}

function normalizePath(path: string): string {
  const trimmed = path.trim().replace(/^\/+/u, "/");
  if (trimmed === "") {
    return "/ws";
  }

  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}
