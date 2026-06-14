import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { Check, Copy } from "lucide-react";
import * as React from "react";
import { match } from "ts-pattern";

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
      commands: [`curl https://${host}${urlPort}`],
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

const Cursor = (props: { blink: boolean }) =>
  props.blink ? (
    <motion.span
      className="ml-0.5 inline-block h-[1.05em] w-[0.5ch] translate-y-[0.15em] bg-cyan-300"
      animate={{ opacity: [1, 1, 0, 0] }}
      transition={{
        duration: 1.1,
        repeat: Infinity,
        ease: "linear",
        times: [0, 0.5, 0.5, 1],
      }}
    />
  ) : (
    <span className="ml-0.5 inline-block h-[1.05em] w-[0.5ch] translate-y-[0.15em] bg-cyan-300" />
  );

const ConnectCommand = (props: { service: Service; domain: string }) => {
  const reduced = useReducedMotion();

  const info = React.useMemo(
    () => buildConnectCommand(props.service, props.domain),
    [props.service, props.domain],
  );

  const full = info ? info.commands.join("\n") : "";
  const [typed, setTyped] = React.useState(reduced ? full.length : 0);
  const [copied, setCopied] = React.useState(false);

  React.useEffect(() => {
    if (!info || reduced) {
      setTyped(full.length);
      return;
    }

    setTyped(0);
    let i = 0;
    const id = window.setInterval(() => {
      i += 1;
      setTyped(i);
      if (i >= full.length) {
        window.clearInterval(id);
      }
    }, 20);

    return () => window.clearInterval(id);
  }, [full, info, reduced]);

  React.useEffect(() => {
    if (!copied) {
      return;
    }
    const id = window.setTimeout(() => setCopied(false), 1600);
    return () => window.clearTimeout(id);
  }, [copied]);

  if (!info) {
    return null;
  }

  const done = typed >= full.length;
  const lines = full.slice(0, typed).split("\n");

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(full);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <motion.div
      initial={reduced ? false : { opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: "easeOut" }}
      className="mt-3 overflow-hidden rounded-xl bg-slate-900 shadow-lg shadow-slate-900/10 ring-1 ring-white/10"
    >
      <div className="flex items-center justify-between border-b border-white/5 px-3 py-2">
        <div className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-rose-400/60" />
          <span className="h-2.5 w-2.5 rounded-full bg-amber-400/60" />
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/60" />
        </div>
        <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-slate-500">
          {info.tool}
        </span>
      </div>

      <div className="flex items-start gap-3 px-3.5 py-3">
        <code className="min-w-0 flex-1 font-mono text-sm leading-relaxed text-slate-100">
          <span className="sr-only">{full}</span>
          <span aria-hidden className="flex flex-col gap-1">
            {lines.map((line, idx) => (
              <span key={idx} className="flex items-start">
                <span className="select-none pr-2 text-cyan-300">❯</span>
                <span className="break-all">
                  {line}
                  {idx === lines.length - 1 && !reduced && (
                    <Cursor blink={done} />
                  )}
                </span>
              </span>
            ))}
          </span>
        </code>

        <button
          type="button"
          onClick={onCopy}
          aria-label={copied ? "Copied" : "Copy command"}
          className="-mr-1 flex h-7 w-7 flex-none items-center justify-center rounded-md text-slate-400 transition-colors hover:bg-white/5 hover:text-slate-100"
        >
          <AnimatePresence mode="wait" initial={false}>
            {copied ? (
              <motion.span
                key="check"
                initial={{ opacity: 0, scale: 0.6 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.6 }}
                transition={{ duration: 0.15 }}
              >
                <Check className="h-4 w-4 text-emerald-400" />
              </motion.span>
            ) : (
              <motion.span
                key="copy"
                initial={{ opacity: 0, scale: 0.6 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.6 }}
                transition={{ duration: 0.15 }}
              >
                <Copy className="h-4 w-4" />
              </motion.span>
            )}
          </AnimatePresence>
        </button>
      </div>
    </motion.div>
  );
};

export default ConnectCommand;
