import {
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  Container,
  Group,
  Loader,
  LoadingOverlay,
  Stack,
  Text,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  AlertCircle,
  Keyboard,
  Maximize2,
  Monitor,
  Power,
  Shield,
  TerminalSquare,
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
        .withAuthToken("")
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

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <LoadingOverlay visible={connecting} overlayProps={{ blur: 2 }} />

      {!sessionVisible && (
        <Container size="sm" className="py-12">
          <Stack gap="lg">
            <Group justify="space-between" align="center">
              <Group gap="sm">
                <div className="rounded-xl bg-blue-600/15 p-3 text-blue-300">
                  <Monitor size={26} />
                </div>
                <div>
                  <Title order={2}>Octelium RDP Web</Title>
                  <Text size="sm" c="dimmed">
                    Browser-based RDP access through Octelium.
                  </Text>
                </div>
              </Group>

              <Badge
                color={moduleReady ? "green" : "yellow"}
                variant="light"
                leftSection={<Shield size={13} />}
              >
                {status}
              </Badge>
            </Group>

            <Card withBorder shadow="md" padding="xl" radius="lg">
              <Stack gap="md" align="center" className="py-6 text-center">
                {connecting ? <Loader size="lg" /> : <Monitor size={42} />}

                <Title order={3}>{connecting ? "Connecting" : status}</Title>

                <Text size="sm" c="dimmed">
                  Securely connecting to {globals.destination}. Credentials are
                  injected by the gateway, so no sign-in is required.
                </Text>

                {error && (
                  <Alert
                    color="red"
                    icon={<AlertCircle size={18} />}
                    title="Connection error"
                    className="w-full text-left"
                  >
                    <Text className="whitespace-pre-wrap" size="sm">
                      {error}
                    </Text>
                  </Alert>
                )}

                {!connecting && (
                  <Button
                    size="md"
                    leftSection={<TerminalSquare size={18} />}
                    disabled={!moduleReady || !interactionReady}
                    onClick={() => void startSession()}
                  >
                    {error ? "Retry" : "Reconnect"}
                  </Button>
                )}

                <Text size="xs" c="dimmed">
                  WebSocket endpoint:{" "}
                  <Anchor component="span" c="dimmed">
                    {wsURL}
                  </Anchor>
                </Text>
              </Stack>
            </Card>
          </Stack>
        </Container>
      )}

      <div
        className="fixed inset-0 z-50 flex flex-col bg-black"
        style={{ display: sessionVisible ? "flex" : "none" }}
      >
        <Group
          justify="space-between"
          className="border-b border-slate-800 bg-slate-950/95 px-3 py-2"
        >
          <Group gap="xs">
            <Badge color="green" variant="light">
              {status}
            </Badge>

            <Tooltip label="Ctrl+Alt+Del">
              <Button
                size="xs"
                variant="subtle"
                leftSection={<Keyboard size={14} />}
                onClick={sendCtrlAltDel}
              >
                Ctrl+Alt+Del
              </Button>
            </Tooltip>

            <Tooltip label="Windows key">
              <Button size="xs" variant="subtle" onClick={sendMetaKey}>
                Meta
              </Button>
            </Tooltip>

            <Button size="xs" variant="subtle" onClick={() => setScale("fit")}>
              Fit
            </Button>
            <Button size="xs" variant="subtle" onClick={() => setScale("real")}>
              Real
            </Button>
            <Button size="xs" variant="subtle" onClick={() => setScale("full")}>
              Full
            </Button>

            <Button
              size="xs"
              variant="subtle"
              leftSection={<Maximize2 size={14} />}
              onClick={() => document.documentElement.requestFullscreen()}
            >
              Fullscreen
            </Button>
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

        <div className="min-h-0 flex-1">
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
