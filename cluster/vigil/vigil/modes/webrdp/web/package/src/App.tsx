import {
  Alert,
  Badge,
  Button,
  Group,
  Loader,
  Paper,
  Stack,
  Text,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  AlertCircle,
  Keyboard,
  Maximize2,
  Minimize2,
  MonitorUp,
  Power,
  RefreshCw,
} from "lucide-react";
import { Component, type ErrorInfo, type ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { UserInteraction } from "@devolutions/iron-remote-desktop";

import { getLogLevel, getRdpWebGlobals, getWebSocketURL } from "./lib/globals";
import {
  getErrorMessage,
  getReadyUserInteraction,
  loadIronRdp,
  type RdpExtensions,
} from "./lib/iron";
import "./App.css";

type ScreenScale = Parameters<UserInteraction["setScale"]>[0];

const SCREEN_SCALE: Record<"fit" | "real" | "full", ScreenScale> = {
  fit: 1 as ScreenScale,
  full: 2 as ScreenScale,
  real: 3 as ScreenScale,
};

type ConnectionState =
  | "loading"
  | "ready"
  | "connecting"
  | "connected"
  | "disconnecting"
  | "disconnected"
  | "error";

const FRIENDLY_CONNECTION_ERROR =
  "We couldn't start the remote desktop session. Please try again.";

const RESIZE_DEBOUNCE_MS = 400;
const MIN_DESKTOP_WIDTH = 320;
const MIN_DESKTOP_HEIGHT = 240;

type DesktopSize = { width: number; height: number };

function toEvenSize(value: number, min: number): number {
  const size = Math.max(Math.floor(value), min);
  return size % 2 === 0 ? size : size - 1;
}

type ErrorBoundaryProps = { children: ReactNode };
type ErrorBoundaryState = { hasError: boolean };

export class AppErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Unexpected RDP web client error", error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <main className="ow-fallback" role="alert">
          <div className="ow-fallback-card">
            <Text component="h1" className="ow-title">
              Remote desktop unavailable
            </Text>
            <Text size="sm" c="dimmed">
              An unexpected error interrupted the session. Please reload the
              page to try again.
            </Text>
          </div>
        </main>
      );
    }

    return this.props.children;
  }
}

function OcteliumLogo({ size = 120 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 7616 7616"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <path
        d="M7616 3808C7616 5911.1 5911.1 7616 3808 7616C1704.9 7616 0 5911.1 0 3808C0 1704.9 1704.9 0 3808 0C5911.1 0 7616 1704.9 7616 3808Z"
        fill="black"
      />
      <path
        d="M4030.83 5310.33C3720.87 5238.74 3399.85 5228.91 3086.09 5281.38C2772.34 5333.86 2471.99 5447.62 2202.2 5616.17L2717.22 6440.55C2878.76 6339.64 3058.59 6271.53 3246.44 6240.11C3434.3 6208.69 3626.5 6214.58 3812.08 6257.44L4030.83 5310.33Z"
        fill="white"
      />
      <path
        d="M5028.37 4712.95C4758.58 4881.5 4524.63 5101.54 4339.88 5360.51C4155.12 5619.48 4023.18 5912.3 3951.6 6222.25L4898.7 6441C4941.56 6255.42 5020.56 6080.1 5131.18 5925.05C5241.8 5770 5381.87 5638.25 5543.4 5537.33L5028.37 4712.95Z"
        fill="white"
      />
      <path
        d="M5311.33 3585.17C5239.74 3895.13 5229.91 4216.15 5282.38 4529.91C5334.86 4843.66 5448.62 5144.01 5617.17 5413.8L6441.56 4898.78C6340.64 4737.24 6272.53 4557.41 6241.11 4369.56C6209.69 4181.7 6215.58 3989.5 6258.44 3803.92L5311.33 3585.17Z"
        fill="white"
      />
      <path
        d="M4713.95 2587.63C4882.5 2857.42 5102.54 3091.37 5361.51 3276.12C5620.48 3460.88 5913.3 3592.82 6223.25 3664.4L6442 2717.3C6256.42 2674.43 6081.1 2595.44 5926.05 2484.82C5771 2374.2 5639.25 2234.13 5538.33 2072.6L4713.95 2587.63Z"
        fill="white"
      />
      <path
        d="M3586.17 2304.67C3896.13 2376.26 4217.15 2386.09 4530.9 2333.62C4844.66 2281.14 5145.01 2167.38 5414.8 1998.83L4899.78 1174.44C4738.24 1275.36 4558.41 1343.47 4370.56 1374.89C4182.7 1406.31 3990.5 1400.42 3804.92 1357.56L3586.17 2304.67Z"
        fill="white"
      />
      <path
        d="M2588.63 2902.05C2858.42 2733.5 3092.37 2513.46 3277.12 2254.49C3461.88 1995.52 3593.82 1702.7 3665.4 1392.75L2718.3 1174C2675.43 1359.58 2596.44 1534.9 2485.82 1689.95C2375.2 1845 2235.13 1976.75 2073.6 2077.67L2588.63 2902.05Z"
        fill="white"
      />
      <path
        d="M2305.67 4029.83C2377.26 3719.87 2387.09 3398.85 2334.62 3085.1C2282.14 2771.34 2168.38 2470.99 1999.83 2201.2L1175.44 2716.23C1276.36 2877.76 1344.47 3057.59 1375.89 3245.44C1407.31 3433.3 1401.42 3625.5 1358.56 3811.08L2305.67 4029.83Z"
        fill="white"
      />
      <path
        d="M2903.05 5027.37C2734.5 4757.58 2514.46 4523.63 2255.49 4338.88C1996.52 4154.12 1703.7 4022.18 1393.75 3950.6L1175 4897.7C1360.58 4940.56 1535.9 5019.56 1690.95 5130.18C1846 5240.8 1977.75 5380.87 2078.67 5542.4L2903.05 5027.37Z"
        fill="white"
      />
    </svg>
  );
}

export function App() {
  const globals = useMemo(() => getRdpWebGlobals(), []);
  const wsURL = useMemo(
    () => getWebSocketURL(globals.webSocketPath),
    [globals.webSocketPath],
  );

  const [backend, setBackend] = useState<unknown>(null);
  const [extensions, setExtensions] = useState<RdpExtensions | null>(null);
  const [moduleReady, setModuleReady] = useState(false);
  const [interactionReady, setInteractionReady] = useState(false);
  const [sessionVisible, setSessionVisible] = useState(false);
  const [connectionState, setConnectionState] =
    useState<ConnectionState>("loading");
  const [status, setStatus] = useState("Initializing RDP client...");
  const [error, setError] = useState<string | null>(null);
  const [errorDetails, setErrorDetails] = useState<string | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const userInteractionRef = useRef<UserInteraction | null>(null);
  const remoteElementRef = useRef<HTMLElement | null>(null);
  const readyListenerRef = useRef<((event: Event) => void) | null>(null);
  const autoStartedRef = useRef(false);
  const loadAttemptRef = useRef(0);
  const sessionAttemptRef = useRef(0);
  const canvasRef = useRef<HTMLDivElement | null>(null);
  const desktopSizeRef = useRef<DesktopSize | null>(null);

  const getCanvasSize = useCallback((): DesktopSize => {
    const canvas = canvasRef.current;
    return {
      width: toEvenSize(
        canvas?.clientWidth || window.innerWidth,
        MIN_DESKTOP_WIDTH,
      ),
      height: toEvenSize(
        canvas?.clientHeight || window.innerHeight,
        MIN_DESKTOP_HEIGHT,
      ),
    };
  }, []);

  const showError = useCallback((message: string, details?: string) => {
    setError(message);
    setErrorDetails(details && details !== message ? details : null);
    setConnectionState("error");
  }, []);

  const loadClient = useCallback(async () => {
    const attempt = ++loadAttemptRef.current;

    autoStartedRef.current = false;
    setModuleReady(false);
    setInteractionReady(false);
    setConnectionState("loading");
    setStatus("Loading secure RDP client...");
    setError(null);
    setErrorDetails(null);

    try {
      const loaded = await loadIronRdp(getLogLevel());
      if (attempt !== loadAttemptRef.current) {
        return;
      }

      setBackend(loaded.backend);
      setExtensions(loaded.extensions);
      setModuleReady(true);
      setStatus("Preparing remote desktop...");
      setConnectionState("ready");
    } catch (err) {
      if (attempt !== loadAttemptRef.current) {
        return;
      }

      showError(
        "We couldn't load the secure remote desktop client. Please try again or reload the page.",
        getErrorMessage(err),
      );
      setStatus("RDP client unavailable");
    }
  }, [showError]);

  useEffect(() => {
    // This effect intentionally starts the asynchronous client bootstrap once.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void loadClient();

    return () => {
      loadAttemptRef.current += 1;
      sessionAttemptRef.current += 1;
    };
  }, [loadClient]);

  const onRemoteElement = useCallback((el: HTMLElement | null) => {
    const previousElement = remoteElementRef.current;
    if (previousElement && readyListenerRef.current) {
      previousElement.removeEventListener("ready", readyListenerRef.current);
    }

    readyListenerRef.current = null;
    remoteElementRef.current = el;
    userInteractionRef.current = null;
    setInteractionReady(false);

    if (!el) {
      return;
    }

    const readyListener = (event: Event) => {
      const ui = getReadyUserInteraction(event);
      if (!ui) {
        showError("The remote desktop client did not finish initializing.");
        return;
      }

      userInteractionRef.current = ui;
      setInteractionReady(true);
      setStatus("Ready");
      setConnectionState("ready");
    };

    readyListenerRef.current = readyListener;
    el.addEventListener("ready", readyListener);
  }, [showError]);

  const startSession = useCallback(async () => {
    const ui = userInteractionRef.current;
    const exts = extensions;

    if (connectionState === "connecting" || connectionState === "connected") {
      return;
    }

    if (!moduleReady || !backend || !exts) {
      setStatus("Loading secure RDP client...");
      return;
    }

    if (!ui) {
      setStatus("Preparing remote desktop...");
      return;
    }

    const attempt = ++sessionAttemptRef.current;
    setConnectionState("connecting");
    setError(null);
    setErrorDetails(null);
    setStatus("Connecting...");

    try {
      ui.setEnableClipboard(true);
      ui.setKeyboardUnicodeMode(false);

      const desktopSize = getCanvasSize();
      desktopSizeRef.current = desktopSize;

      const builder = ui
        .configBuilder()
        .withUsername("")
        .withPassword("")
        .withDestination(globals.destination)
        .withProxyAddress(wsURL)
        .withAuthToken("octelium")
        .withDesktopSize(desktopSize)
        .withExtension(exts.displayControl(true));

      if (exts.enableCredssp) {
        builder.withExtension(exts.enableCredssp(false));
      }

      const sessionInfo = await ui.connect(builder.build());
      if (attempt !== sessionAttemptRef.current) {
        return;
      }

      setSessionVisible(true);
      setConnectionState("connected");
      setStatus("Connected");
      ui.setVisibility(true);

      const termInfo = await sessionInfo.run();
      if (attempt !== sessionAttemptRef.current) {
        return;
      }

      setSessionVisible(false);
      setConnectionState("disconnected");
      setStatus("Disconnected");
      console.debug("RDP session terminated", termInfo);
    } catch (err) {
      if (attempt !== sessionAttemptRef.current) {
        return;
      }

      setSessionVisible(false);
      setStatus("Connection failed");
      showError(FRIENDLY_CONNECTION_ERROR, getErrorMessage(err));
    }
  }, [
    backend,
    connectionState,
    extensions,
    getCanvasSize,
    globals.destination,
    moduleReady,
    showError,
    wsURL,
  ]);

  useEffect(() => {
    if (moduleReady && interactionReady && !autoStartedRef.current) {
      autoStartedRef.current = true;
      void startSession();
    }
  }, [moduleReady, interactionReady, startSession]);

  const shutdownSession = async () => {
    sessionAttemptRef.current += 1;
    setConnectionState("disconnecting");
    setStatus("Disconnecting...");

    try {
      userInteractionRef.current?.shutdown();
    } finally {
      setSessionVisible(false);
      setConnectionState("disconnected");
      setStatus("Disconnected");
    }
  };

  const toggleFullscreen = async () => {
    if (!document.fullscreenEnabled) {
      notifications.show({
        color: "yellow",
        title: "Fullscreen unavailable",
        message: "Your browser does not allow fullscreen mode here.",
      });
      return;
    }

    try {
      if (document.fullscreenElement) {
        await document.exitFullscreen();
      } else {
        await document.documentElement.requestFullscreen();
      }
    } catch {
      notifications.show({
        color: "yellow",
        title: "Fullscreen unavailable",
        message: "Fullscreen mode could not be enabled in this browser.",
      });
    }
  };

  useEffect(() => {
    const onFullscreenChange = () => {
      setIsFullscreen(Boolean(document.fullscreenElement));
    };

    document.addEventListener("fullscreenchange", onFullscreenChange);
    return () => {
      document.removeEventListener("fullscreenchange", onFullscreenChange);
    };
  }, []);

  useEffect(() => {
    if (!sessionVisible || !canvasRef.current) {
      return;
    }

    let timer: number | undefined;

    const resize = () => {
      const ui = userInteractionRef.current;
      if (!ui) {
        return;
      }

      const size = getCanvasSize();
      const current = desktopSizeRef.current;
      if (
        current &&
        current.width === size.width &&
        current.height === size.height
      ) {
        return;
      }

      desktopSizeRef.current = size;
      ui.resize(size.width, size.height);
    };

    const scheduleResize = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(resize, RESIZE_DEBOUNCE_MS);
    };

    scheduleResize();
    const observer = new ResizeObserver(scheduleResize);
    observer.observe(canvasRef.current);

    return () => {
      window.clearTimeout(timer);
      observer.disconnect();
    };
  }, [getCanvasSize, sessionVisible]);

  const sendCtrlAltDel = () => {
    userInteractionRef.current?.ctrlAltDel();
  };

  const sendMetaKey = () => {
    userInteractionRef.current?.metaKey();
  };

  const setScale = (scale: "fit" | "real" | "full") => {
    userInteractionRef.current?.setScale(SCREEN_SCALE[scale]);
  };

  const connecting = connectionState === "connecting";
  const working = !error &&
    (connectionState === "loading" ||
      connectionState === "ready" ||
      connectionState === "connecting");
  const showButton =
    !sessionVisible &&
    !connecting &&
    (connectionState === "error" || connectionState === "disconnected");
  const actionLabel = error ? "Try again" : "Reconnect";
  const handleBootstrapAction = () => {
    if (!moduleReady || !interactionReady) {
      void loadClient();
      return;
    }

    void startSession();
  };

  return (
    <div className="ow-root">
      {!sessionVisible && (
        <div className="ow-shell">
          <Paper className="ow-bootstrap-card" withBorder shadow="md">
            <div
              className={`ow-stage ${error ? "ow-stage--error" : ""} ${working ? "ow-stage--working" : ""}`}
              aria-hidden
            >
              <span className="ow-ring ow-ring--1" />
              <span className="ow-ring ow-ring--2" />
              <span className="ow-halo" />
              <span className="ow-logo">
                <OcteliumLogo size={124} />
              </span>
            </div>

            <Stack gap="md" align="stretch">
              <div className="ow-intro">
                <Text component="h1" className="ow-title">
                  Secure remote desktop
                </Text>
                <Text size="sm" c="dimmed">
                  Establishing a protected RDP session through Octelium.
                </Text>
              </div>

              <div className="ow-status" role="status" aria-live="polite">
                {working && <Loader size="sm" color="cyan" />}
                {!working && connectionState === "disconnected" && (
                  <MonitorUp size={16} aria-hidden />
                )}
                <span>{status}</span>
              </div>

              {error && (
                <Alert
                  color="red"
                  variant="light"
                  icon={<AlertCircle size={18} aria-hidden />}
                  title="Remote desktop unavailable"
                  role="alert"
                >
                  {error}
                  {errorDetails && (
                    <details className="ow-error-details">
                      <summary>Technical details</summary>
                      <pre>{errorDetails}</pre>
                    </details>
                  )}
                </Alert>
              )}

              {showButton && (
                <Button
                  fullWidth
                  size="md"
                  color="dark"
                  leftSection={<RefreshCw size={17} aria-hidden />}
                  onClick={handleBootstrapAction}
                  aria-label={actionLabel}
                >
                  {actionLabel}
                </Button>
              )}
            </Stack>
          </Paper>
        </div>
      )}

      <div
        className={`ow-session ${sessionVisible ? "" : "ow-session--hidden"}`}
        aria-hidden={!sessionVisible}
      >
        <div className="ow-toolbar">
          <Group gap="xs" className="ow-toolbar-main">
            <Badge color="teal" variant="light" className="ow-status-badge">
              {status}
            </Badge>

            <Tooltip label="Ctrl+Alt+Del">
              <Button
                size="xs"
                variant="subtle"
                color="gray"
                leftSection={<Keyboard size={14} />}
                onClick={sendCtrlAltDel}
                aria-label="Send Ctrl+Alt+Del"
              >
                <span className="ow-control-label">Ctrl+Alt+Del</span>
              </Button>
            </Tooltip>

            <Tooltip label="Windows key">
              <Button
                size="xs"
                variant="subtle"
                color="gray"
                leftSection={<Keyboard size={14} />}
                onClick={sendMetaKey}
                aria-label="Send Windows key"
              >
                <span className="ow-control-label">Meta</span>
              </Button>
            </Tooltip>

            <Button
              size="xs"
              variant="subtle"
              color="gray"
              onClick={() => setScale("fit")}
              aria-label="Fit remote desktop to window"
            >
              <span className="ow-control-label ow-scale-label">Fit</span>
            </Button>
            <Button
              size="xs"
              variant="subtle"
              color="gray"
              onClick={() => setScale("real")}
              aria-label="Use actual remote desktop size"
            >
              <span className="ow-control-label ow-scale-label">Real</span>
            </Button>
            <Button
              size="xs"
              variant="subtle"
              color="gray"
              onClick={() => setScale("full")}
              aria-label="Fill available remote desktop area"
            >
              <span className="ow-control-label ow-scale-label">Full</span>
            </Button>

            <Tooltip label={isFullscreen ? "Exit fullscreen" : "Fullscreen"}>
              <Button
                size="xs"
                variant="subtle"
                color="gray"
                leftSection={
                  isFullscreen ? (
                    <Minimize2 size={14} />
                  ) : (
                    <Maximize2 size={14} />
                  )
                }
                onClick={() => void toggleFullscreen()}
                aria-label={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
              >
                <span className="ow-control-label">
                  {isFullscreen ? "Exit fullscreen" : "Fullscreen"}
                </span>
              </Button>
            </Tooltip>
          </Group>

          <Button
            size="xs"
            color="red"
            variant="light"
            leftSection={<Power size={14} />}
            onClick={() => void shutdownSession()}
            aria-label="Disconnect remote desktop session"
          >
            <span className="ow-control-label">Disconnect</span>
          </Button>
        </div>

        <div className="ow-canvas" ref={canvasRef}>
          {moduleReady && (
            <iron-remote-desktop
              ref={onRemoteElement}
              verbose="false"
              debugwasm="OFF"
              scale="fit"
              flexcentre="true"
              module={backend}
            />
          )}
        </div>
      </div>
    </div>
  );
}
