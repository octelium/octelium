import { Service, Service_Spec_Type } from "@octelium/apis/main/userv1";
import {
  AppWindow,
  BrainCircuit,
  Cable,
  Globe2,
  Monitor,
  Network,
  Radio,
  Router,
  Server,
  Terminal,
  Waypoints,
} from "lucide-react";
import { GrMysql } from "react-icons/gr";
import {
  SiKubernetes,
  SiModelcontextprotocol,
  SiPostgresql,
} from "react-icons/si";
import type { ComponentType } from "react";

export type ServiceTypeIcon = ComponentType<{
  size?: number;
  className?: string;
}>;

export type ServiceTypeInfo = {
  key: string;
  type: Service_Spec_Type;
  label: string;
  icon: ServiceTypeIcon;
  tile: string;
  chip: string;
};

const SERVICE_TYPE_TILE = "bg-accent text-accent-fg ring-accent-ring";

export const SERVICE_TYPES: ServiceTypeInfo[] = [
  {
    key: "WEB",
    type: Service_Spec_Type.WEB,
    label: "Web App",
    icon: AppWindow,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-sky-50 text-sky-700 ring-sky-200 dark:bg-sky-500/10 dark:text-sky-300 dark:ring-sky-500/25",
  },
  {
    key: "HTTP",
    type: Service_Spec_Type.HTTP,
    label: "HTTP",
    icon: Globe2,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-500/10 dark:text-blue-300 dark:ring-blue-500/25",
  },
  {
    key: "GRPC",
    type: Service_Spec_Type.GRPC,
    label: "gRPC",
    icon: Network,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-violet-50 text-violet-700 ring-violet-200 dark:bg-violet-500/10 dark:text-violet-300 dark:ring-violet-500/25",
  },
  {
    key: "SSH",
    type: Service_Spec_Type.SSH,
    label: "SSH",
    icon: Terminal,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-slate-100 text-slate-700 ring-slate-200 dark:bg-neutral-800 dark:text-neutral-200 dark:ring-neutral-700",
  },
  {
    key: "KUBERNETES",
    type: Service_Spec_Type.KUBERNETES,
    label: "Kubernetes",
    icon: SiKubernetes,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-indigo-50 text-indigo-700 ring-indigo-200 dark:bg-indigo-500/10 dark:text-indigo-300 dark:ring-indigo-500/25",
  },
  {
    key: "POSTGRES",
    type: Service_Spec_Type.POSTGRES,
    label: "PostgreSQL",
    icon: SiPostgresql,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-cyan-50 text-cyan-700 ring-cyan-200 dark:bg-cyan-500/10 dark:text-cyan-300 dark:ring-cyan-500/25",
  },
  {
    key: "MYSQL",
    type: Service_Spec_Type.MYSQL,
    label: "MySQL",
    icon: GrMysql,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-amber-50 text-amber-700 ring-amber-200 dark:bg-amber-500/10 dark:text-amber-300 dark:ring-amber-500/25",
  },
  {
    key: "TCP",
    type: Service_Spec_Type.TCP,
    label: "TCP",
    icon: Cable,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-teal-50 text-teal-700 ring-teal-200 dark:bg-teal-500/10 dark:text-teal-300 dark:ring-teal-500/25",
  },
  {
    key: "UDP",
    type: Service_Spec_Type.UDP,
    label: "UDP",
    icon: Radio,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-500/25",
  },
  {
    key: "DNS",
    type: Service_Spec_Type.DNS,
    label: "DNS",
    icon: Waypoints,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-green-50 text-green-700 ring-green-200 dark:bg-green-500/10 dark:text-green-300 dark:ring-green-500/25",
  },
  {
    key: "SOCKS5",
    type: Service_Spec_Type.SOCKS5,
    label: "SOCKS5",
    icon: Router,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-200 dark:bg-fuchsia-500/10 dark:text-fuchsia-300 dark:ring-fuchsia-500/25",
  },
  {
    key: "RDP_WEB",
    type: Service_Spec_Type.RDP_WEB,
    label: "RDP Web",
    icon: Monitor,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-rose-50 text-rose-700 ring-rose-200 dark:bg-rose-500/10 dark:text-rose-300 dark:ring-rose-500/25",
  },
  {
    key: "LLM",
    type: Service_Spec_Type.LLM,
    label: "AI / LLM",
    icon: BrainCircuit,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-purple-50 text-purple-700 ring-purple-200 dark:bg-purple-500/10 dark:text-purple-300 dark:ring-purple-500/25",
  },
  {
    key: "MCP",
    type: Service_Spec_Type.MCP,
    label: "MCP",
    icon: SiModelcontextprotocol,
    tile: SERVICE_TYPE_TILE,
    chip:
      "bg-orange-50 text-orange-700 ring-orange-200 dark:bg-orange-500/10 dark:text-orange-300 dark:ring-orange-500/25",
  },
];

export const UNKNOWN_SERVICE_TYPE: ServiceTypeInfo = {
  key: "UNSET",
  type: Service_Spec_Type.UNSET,
  label: "Service",
  icon: Server,
  tile: SERVICE_TYPE_TILE,
  chip:
    "bg-slate-100 text-slate-700 ring-slate-200 dark:bg-neutral-800 dark:text-neutral-200 dark:ring-neutral-700",
};

const byType = new Map<Service_Spec_Type, ServiceTypeInfo>(
  SERVICE_TYPES.map((info) => [info.type, info]),
);

export const getServiceTypeInfo = (service: Service): ServiceTypeInfo =>
  byType.get(service.spec?.type ?? Service_Spec_Type.UNSET) ??
  UNKNOWN_SERVICE_TYPE;

export const getServiceTypeByKey = (
  key?: string | null,
): ServiceTypeInfo | undefined =>
  key ? SERVICE_TYPES.find((info) => info.key === key) : undefined;

export const SERVICE_TYPE_OPTIONS = SERVICE_TYPES.map((info) => ({
  value: info.key,
  label: info.label,
}));
