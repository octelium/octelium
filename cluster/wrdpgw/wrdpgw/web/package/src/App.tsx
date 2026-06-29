import { Badge, Button, Group, Tooltip } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  AlertCircle,
  Keyboard,
  Maximize2,
  Power,
  RotateCcw,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { UserInteraction } from "@devolutions/iron-remote-desktop";

import { getRdpWebGlobals, getWebSocketURL } from "./lib/globals";
import {
  getErrorMessage,
  getReadyUserInteraction,
  loadIronRdp,
  type RdpExtensions,
} from "./lib/iron";

type ScreenScale = Parameters<UserInteraction["setScale"]>[0];

const SCREEN_SCALE: Record<"fit" | "real" | "full", ScreenScale> = {
  fit: 1 as ScreenScale,
  full: 2 as ScreenScale,
  real: 3 as ScreenScale,
};

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
  const [connecting, setConnecting] = useState(false);
  const [status, setStatus] = useState("Initializing RDP client...");
  const [error, setError] = useState<string | null>(null);

  const userInteractionRef = useRef<UserInteraction | null>(null);
  const remoteElementRef = useRef<HTMLElement | null>(null);
  const autoStartedRef = useRef(false);

  useEffect(() => {
    let cancelled = false;

    void loadIronRdp()
      .then((loaded) => {
        if (cancelled) {
          return;
        }

        setBackend(loaded.backend);
        setExtensions(loaded.extensions);
        setModuleReady(true);
        setStatus("Ready");
      })
      .catch((err) => {
        const msg = getErrorMessage(err);
        setStatus("Failed to load RDP client");
        setError(msg);
        notifications.show({
          color: "red",
          title: "Failed to load RDP client",
          message: msg,
        });
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const onRemoteElement = useCallback((el: HTMLElement | null) => {
    if (!el || remoteElementRef.current === el) {
      return;
    }

    remoteElementRef.current = el;

    el.addEventListener("ready", (event) => {
      const ui = getReadyUserInteraction(event);
      if (!ui) {
        setError("RDP component emitted ready without UserInteraction");
        return;
      }

      userInteractionRef.current = ui;
      setInteractionReady(true);
      setStatus("Ready");
    });
  }, []);

  const startSession = useCallback(async () => {
    const ui = userInteractionRef.current;
    const exts = extensions;

    if (!moduleReady || !backend || !exts) {
      setError("RDP client is still loading.");
      return;
    }

    if (!ui) {
      setError("RDP component is not ready yet.");
      return;
    }

    setConnecting(true);
    setError(null);
    setStatus("Connecting...");

    try {
      ui.setEnableClipboard(true);
      ui.setKeyboardUnicodeMode(false);

      const builder = ui
        .configBuilder()
        .withUsername("")
        .withPassword("")
        .withDestination(globals.destination)
        .withProxyAddress(wsURL)
        .withAuthToken("octelium")
        .withDesktopSize({
          width: Math.max(window.innerWidth, 1024),
          height: Math.max(window.innerHeight, 768),
        })
        .withExtension(exts.displayControl(true));

      if (exts.enableCredssp) {
        builder.withExtension(exts.enableCredssp(false));
      }

      const sessionInfo = await ui.connect(builder.build());

      setSessionVisible(true);
      setConnecting(false);
      setStatus("Connected");
      ui.setVisibility(true);

      const termInfo = await sessionInfo.run();

      setSessionVisible(false);
      setStatus("Disconnected");
      console.debug("RDP session terminated", termInfo);
    } catch (err) {
      const msg = getErrorMessage(err);

      setConnecting(false);
      setSessionVisible(false);
      setStatus("Connection failed");
      setError(msg);

      notifications.show({
        color: "red",
        title: "RDP connection failed",
        message: msg,
      });
    }
  }, [extensions, backend, moduleReady, wsURL, globals.destination]);

  useEffect(() => {
    if (moduleReady && interactionReady && !autoStartedRef.current) {
      autoStartedRef.current = true;
      void startSession();
    }
  }, [moduleReady, interactionReady, startSession]);

  const shutdownSession = async () => {
    setStatus("Disconnecting...");

    try {
      await userInteractionRef.current?.shutdown();
    } finally {
      setSessionVisible(false);
      setStatus("Disconnected");
    }
  };

  const sendCtrlAltDel = () => {
    userInteractionRef.current?.ctrlAltDel();
  };

  const sendMetaKey = () => {
    userInteractionRef.current?.metaKey();
  };

  const setScale = (scale: "fit" | "real" | "full") => {
    userInteractionRef.current?.setScale(SCREEN_SCALE[scale]);
  };

  const working = !error && (connecting || !moduleReady || !interactionReady);
  const showButton =
    !connecting && (!!error || (moduleReady && interactionReady));
  const buttonDisabled = !error && (!moduleReady || !interactionReady);

  return (
    <div className="ow-root">
      <style>{ROOT_STYLES}</style>

      {!sessionVisible && (
        <div className="ow-shell">
          <div
            className={`ow-stage ${error ? "ow-stage--error" : ""} ${working ? "ow-stage--working" : ""}`}
          >
            <span className="ow-ring ow-ring--1" />
            <span className="ow-ring ow-ring--2" />
            <span className="ow-halo" />
            <span className="ow-logo">
              <OcteliumLogo size={124} />
            </span>
          </div>

          {error && (
            <div className="ow-error" role="alert">
              <AlertCircle size={16} aria-hidden />
              <span className="ow-error-text">{error}</span>
            </div>
          )}

          {showButton && (
            <button
              type="button"
              className="ow-cta"
              disabled={buttonDisabled}
              onClick={() => void startSession()}
            >
              <RotateCcw size={16} aria-hidden />
              {error ? "Try again" : "Connect"}
            </button>
          )}
        </div>
      )}

      <div
        className="ow-session"
        style={{ display: sessionVisible ? "flex" : "none" }}
      >
        <Group justify="space-between" className="ow-toolbar">
          <Group gap="xs">
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
              >
                Ctrl+Alt+Del
              </Button>
            </Tooltip>

            <Tooltip label="Windows key">
              <Button
                size="xs"
                variant="subtle"
                color="gray"
                onClick={sendMetaKey}
              >
                Meta
              </Button>
            </Tooltip>

            <Button
              size="xs"
              variant="subtle"
              color="gray"
              onClick={() => setScale("fit")}
            >
              Fit
            </Button>
            <Button
              size="xs"
              variant="subtle"
              color="gray"
              onClick={() => setScale("real")}
            >
              Real
            </Button>
            <Button
              size="xs"
              variant="subtle"
              color="gray"
              onClick={() => setScale("full")}
            >
              Full
            </Button>

            <Tooltip label="Fullscreen">
              <Button
                size="xs"
                variant="subtle"
                color="gray"
                leftSection={<Maximize2 size={14} />}
                onClick={() => document.documentElement.requestFullscreen()}
              >
                Fullscreen
              </Button>
            </Tooltip>
          </Group>

          <Button
            size="xs"
            color="red"
            variant="light"
            leftSection={<Power size={14} />}
            onClick={() => void shutdownSession()}
          >
            Disconnect
          </Button>
        </Group>

        <div className="ow-canvas">
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

const ROOT_STYLES = `
.ow-root {
  min-height: 100vh;
  background:
    radial-gradient(900px 600px at 50% 38%, rgba(56, 189, 248, 0.08), transparent 62%),
    #06080d;
  color: #e6edf6;
}

.ow-shell {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 30px;
  padding: 40px 24px;
}

.ow-stage {
  position: relative;
  width: 260px;
  height: 260px;
  display: grid;
  place-items: center;
}

.ow-logo {
  position: relative;
  z-index: 3;
  display: grid;
  place-items: center;
  filter: drop-shadow(0 16px 44px rgba(56, 189, 248, 0.28));
}

.ow-stage--working .ow-logo {
  animation: ow-breathe 3s ease-in-out infinite;
}

.ow-halo {
  position: absolute;
  z-index: 1;
  width: 150px;
  height: 150px;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(56, 189, 248, 0.30), transparent 70%);
  opacity: 0.7;
}

.ow-stage--working .ow-halo {
  animation: ow-glow 3s ease-in-out infinite;
}

.ow-ring {
  position: absolute;
  z-index: 2;
  width: 132px;
  height: 132px;
  border-radius: 50%;
  border: 1px solid rgba(125, 211, 252, 0.40);
  opacity: 0;
}

.ow-stage--working .ow-ring--1 {
  animation: ow-ping 2.8s cubic-bezier(0, 0, 0.2, 1) infinite;
}

.ow-stage--working .ow-ring--2 {
  animation: ow-ping 2.8s cubic-bezier(0, 0, 0.2, 1) infinite 1.4s;
}

.ow-stage--error .ow-logo {
  filter: drop-shadow(0 16px 44px rgba(248, 113, 113, 0.28));
}

.ow-stage--error .ow-halo {
  background: radial-gradient(circle, rgba(248, 113, 113, 0.26), transparent 70%);
}

@keyframes ow-breathe {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.045); }
}

@keyframes ow-glow {
  0%, 100% { opacity: 0.5; transform: scale(0.96); }
  50% { opacity: 0.95; transform: scale(1.08); }
}

@keyframes ow-ping {
  0% { opacity: 0.5; transform: scale(1); }
  100% { opacity: 0; transform: scale(1.9); }
}

.ow-error {
  display: flex;
  align-items: flex-start;
  gap: 9px;
  max-width: 380px;
  padding: 12px 16px;
  border-radius: 12px;
  color: #fca5a5;
  background: rgba(248, 113, 113, 0.08);
  border: 1px solid rgba(248, 113, 113, 0.22);
  text-align: left;
}

.ow-error-text {
  font-size: 13px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-word;
}

.ow-cta {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  padding: 11px 24px;
  border-radius: 12px;
  font-size: 14.5px;
  font-weight: 600;
  color: #04121b;
  background: linear-gradient(180deg, #7dd3fc, #38bdf8);
  border: 1px solid rgba(125, 211, 252, 0.5);
  cursor: pointer;
  transition: transform 0.12s ease, box-shadow 0.2s ease, opacity 0.2s ease;
  box-shadow: 0 10px 30px -12px rgba(56, 189, 248, 0.6);
}

.ow-cta:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 14px 36px -12px rgba(56, 189, 248, 0.7);
}

.ow-cta:active:not(:disabled) { transform: translateY(0); }

.ow-cta:disabled { opacity: 0.45; cursor: not-allowed; }

.ow-cta:focus-visible {
  outline: 2px solid #7dd3fc;
  outline-offset: 3px;
}

.ow-session {
  position: fixed;
  inset: 0;
  z-index: 50;
  flex-direction: column;
  background: #000;
}

.ow-toolbar {
  padding: 8px 12px;
  background: rgba(6, 8, 13, 0.96);
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  backdrop-filter: blur(6px);
}

.ow-status-badge { text-transform: none; }

.ow-canvas {
  flex: 1 1 auto;
  min-height: 0;
}

@media (prefers-reduced-motion: reduce) {
  .ow-stage--working .ow-logo,
  .ow-stage--working .ow-halo,
  .ow-stage--working .ow-ring--1,
  .ow-stage--working .ow-ring--2 {
    animation: none;
  }
  .ow-stage--working .ow-ring--1 { opacity: 0.35; }
  .ow-cta { transition: none; }
}
`;
