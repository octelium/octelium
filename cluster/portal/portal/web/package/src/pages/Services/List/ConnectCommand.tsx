import { useReducedMotion } from "@mantine/hooks";
import { Check, Copy, SquareTerminal, X } from "lucide-react";
import * as React from "react";
import { match } from "ts-pattern";

import { twMerge } from "@/lib/utils";
import { useCopy } from "@/ui/copy";
import { getServicePrivateFQDN } from "@/utils/octelium";
import { Service, Service_Spec_Type } from "@octelium/apis/main/userv1";

type ConnectInfo = {
  tool: string;
  commands: string[];
};

const buildConnectCommand = (
  svc: Service,
  domain: string,
): ConnectInfo | null => {
  const host =
    svc.status?.primaryHostname || getServicePrivateFQDN(svc, domain);
  const port = svc.spec?.port;
  const tls = svc.spec?.isTLS;

  const portFlag = (flag: string, dflt: number) =>
    port && port !== dflt ? ` ${flag} ${port}` : "";

  const urlPort = port && port !== 80 && port !== 443 ? `:${port}` : "";

  return match(svc.spec?.type)
    .with(Service_Spec_Type.HTTP, () => ({
      tool: "curl",
      commands: [`curl ${tls ? "https" : "http"}://${host}${urlPort}`],
    }))
    .with(Service_Spec_Type.WEB, () => ({
      tool: "curl",
      commands: [`curl ${tls ? "https" : "http"}://${host}${urlPort}`],
    }))
    .with(Service_Spec_Type.POSTGRES, () => ({
      tool: "psql",
      commands: [`psql -h ${host}${portFlag("-p", 5432)}`],
    }))
    .with(Service_Spec_Type.MYSQL, () => ({
      tool: "mysql",
      commands: [`mysql -h ${host}${portFlag("-P", 3306)}`],
    }))
    .with(Service_Spec_Type.SSH, () => ({
      tool: "ssh",
      commands: [`ssh ${host}${portFlag("-p", 22)}`],
    }))
    .with(Service_Spec_Type.KUBERNETES, () => ({
      tool: "kubectl",
      commands: [`octelium cfg ${host}`, `kubectl get pods`],
    }))
    .with(Service_Spec_Type.DNS, () => ({
      tool: "dig",
      commands: [`dig @${host} example.com`],
    }))
    .otherwise(() => null);
};

type TokenKind = "program" | "flag" | "target" | "arg";

const TOKEN_CLASSES: Record<TokenKind, string> = {
  program: "font-semibold text-terminal-bright",
  flag: "text-terminal-flag",
  target: "text-terminal-target",
  arg: "text-terminal-text",
};

const TYPING_DELAY = 240;
const TYPING_DURATION = 720;

const getTokenKind = (text: string, index: number): TokenKind | undefined => {
  if (/^\s+$/.test(text)) {
    return undefined;
  }
  if (index === 0) {
    return "program";
  }
  if (text.startsWith("-")) {
    return "flag";
  }
  return /[.:/@]/.test(text) ? "target" : "arg";
};

const renderTokens = (command: string, limit: number) => {
  let offset = 0;

  return command
    .split(/(\s+)/)
    .filter(Boolean)
    .map((token, index) => {
      const text = token.slice(0, Math.max(limit - offset, 0));
      const kind = getTokenKind(token, index);
      offset += token.length;

      return text ? (
        <span key={index} className={kind && TOKEN_CLASSES[kind]}>
          {text}
        </span>
      ) : null;
    });
};

const useTypedLength = (length: number, enabled: boolean) => {
  const [typed, setTyped] = React.useState(0);

  React.useEffect(() => {
    if (!enabled) {
      return;
    }

    const step = Math.min(Math.max(TYPING_DURATION / length, 14), 32);
    let start: number | undefined;
    let frame = window.requestAnimationFrame(function tick(now) {
      start ??= now;
      const next = Math.min(
        Math.floor(Math.max(now - start - TYPING_DELAY, 0) / step),
        length,
      );
      setTyped(next);
      if (next < length) {
        frame = window.requestAnimationFrame(tick);
      }
    });

    return () => window.cancelAnimationFrame(frame);
  }, [enabled, length]);

  return enabled ? typed : length;
};

const Caret = (props: { blink: boolean }) => (
  <span
    aria-hidden
    className={twMerge(
      "ml-px -mr-[calc(0.55em+1px)] inline-block h-[1.15em] w-[0.55em] rounded-[1px] bg-terminal-text/85 align-[-0.2em]",
      props.blink && "animate-terminal-caret",
    )}
  />
);

const ConnectCommand = (props: {
  service: Service;
  domain: string;
  className?: string;
}) => {
  const { state, copy } = useCopy();
  const reduceMotion = useReducedMotion(undefined, {
    getInitialValueInEffect: false,
  });

  const info = React.useMemo(
    () => buildConnectCommand(props.service, props.domain),
    [props.service, props.domain],
  );

  const total = info?.commands.join("").length ?? 0;
  const typed = useTypedLength(total, !reduceMotion && total > 0);

  if (!info) {
    return null;
  }

  const done = typed >= total;
  const label =
    state === "copied"
      ? "Copied"
      : state === "failed"
        ? "Copy failed"
        : "Copy command";

  const starts = info.commands.map(
    (_, index) => info.commands.slice(0, index).join("").length,
  );

  return (
    <div
      role="group"
      aria-label={`Connect with ${info.tool}`}
      className={twMerge(
        "overflow-hidden rounded-lg border border-terminal-line bg-terminal shadow-[0_1px_2px_rgb(0_0_0/0.06),0_12px_32px_-16px_rgb(0_0_0/0.5)] motion-safe:animate-terminal-enter",
        props.className,
      )}
    >
      <div className="flex h-10 items-center gap-2 border-b border-terminal-line bg-terminal-panel pl-3.5 pr-1.5 shadow-[inset_0_1px_0_rgb(255_255_255/0.04)]">
        <SquareTerminal
          size={14}
          strokeWidth={2}
          className="shrink-0 text-terminal-muted"
          aria-hidden
        />
        <span className="min-w-0 flex-1 truncate text-xs font-medium text-terminal-muted">
          Connect with{" "}
          <span className="font-mono text-terminal-text">{info.tool}</span>
        </span>
        <button
          type="button"
          aria-label={label}
          onClick={(event) => {
            event.stopPropagation();
            copy(info.commands.join("\n"));
          }}
          className={twMerge(
            "flex h-7 shrink-0 items-center gap-1.5 rounded-md px-2 text-xs font-medium outline-none transition-colors hover:bg-terminal-hover focus-visible:ring-2 focus-visible:ring-terminal-muted/60",
            state === "idle"
              ? "text-terminal-muted hover:text-terminal-text"
              : "text-terminal-text",
          )}
        >
          <span
            key={state}
            className="flex motion-safe:animate-terminal-pop"
            aria-hidden
          >
            {state === "copied" ? (
              <Check
                size={14}
                strokeWidth={2.5}
                className="text-terminal-success"
              />
            ) : state === "failed" ? (
              <X size={14} strokeWidth={2.5} className="text-terminal-error" />
            ) : (
              <Copy size={14} strokeWidth={2} />
            )}
          </span>
          <span aria-hidden>
            {state === "copied"
              ? "Copied"
              : state === "failed"
                ? "Failed"
                : "Copy"}
          </span>
        </button>
      </div>
      <pre className="whitespace-pre-wrap px-4 py-3.5 font-mono text-body leading-6 text-terminal-text [overflow-wrap:anywhere]">
        {info.commands.map((command, index) => {
          const start = starts[index];
          const shown = Math.min(Math.max(typed - start, 0), command.length);
          const active = done
            ? index === info.commands.length - 1
            : typed >= start && typed < start + command.length;

          return (
            <div
              key={index}
              className={twMerge(
                "transition-opacity",
                shown === 0 && !active && "opacity-0",
              )}
            >
              <span className="select-none text-terminal-dim">$ </span>
              {renderTokens(command, shown)}
              {active && <Caret blink={done} />}
              {shown < command.length && (
                <span className="opacity-0">{command.slice(shown)}</span>
              )}
            </div>
          );
        })}
      </pre>
    </div>
  );
};

export default ConnectCommand;
