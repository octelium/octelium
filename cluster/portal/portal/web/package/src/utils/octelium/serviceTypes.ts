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

export const SERVICE_TYPES: ServiceTypeInfo[] = [
  {
    key: "WEB",
    type: Service_Spec_Type.WEB,
    label: "Web App",
    icon: AppWindow,
    tile: "from-sky-50 to-sky-100 text-sky-600 ring-sky-200/70",
    chip: "bg-sky-50 text-sky-700 ring-sky-200",
  },
  {
    key: "HTTP",
    type: Service_Spec_Type.HTTP,
    label: "HTTP",
    icon: Globe2,
    tile: "from-blue-50 to-blue-100 text-blue-600 ring-blue-200/70",
    chip: "bg-blue-50 text-blue-700 ring-blue-200",
  },
  {
    key: "GRPC",
    type: Service_Spec_Type.GRPC,
    label: "gRPC",
    icon: Network,
    tile: "from-violet-50 to-violet-100 text-violet-600 ring-violet-200/70",
    chip: "bg-violet-50 text-violet-700 ring-violet-200",
  },
  {
    key: "SSH",
    type: Service_Spec_Type.SSH,
    label: "SSH",
    icon: Terminal,
    tile: "from-slate-100 to-slate-200 text-slate-700 ring-slate-300/70",
    chip: "bg-slate-100 text-slate-700 ring-slate-200",
  },
  {
    key: "KUBERNETES",
    type: Service_Spec_Type.KUBERNETES,
    label: "Kubernetes",
    icon: SiKubernetes,
    tile: "from-indigo-50 to-indigo-100 text-indigo-600 ring-indigo-200/70",
    chip: "bg-indigo-50 text-indigo-700 ring-indigo-200",
  },
  {
    key: "POSTGRES",
    type: Service_Spec_Type.POSTGRES,
    label: "PostgreSQL",
    icon: SiPostgresql,
    tile: "from-cyan-50 to-cyan-100 text-cyan-700 ring-cyan-200/70",
    chip: "bg-cyan-50 text-cyan-700 ring-cyan-200",
  },
  {
    key: "MYSQL",
    type: Service_Spec_Type.MYSQL,
    label: "MySQL",
    icon: GrMysql,
    tile: "from-amber-50 to-amber-100 text-amber-600 ring-amber-200/70",
    chip: "bg-amber-50 text-amber-700 ring-amber-200",
  },
  {
    key: "TCP",
    type: Service_Spec_Type.TCP,
    label: "TCP",
    icon: Cable,
    tile: "from-teal-50 to-teal-100 text-teal-600 ring-teal-200/70",
    chip: "bg-teal-50 text-teal-700 ring-teal-200",
  },
  {
    key: "UDP",
    type: Service_Spec_Type.UDP,
    label: "UDP",
    icon: Radio,
    tile: "from-emerald-50 to-emerald-100 text-emerald-600 ring-emerald-200/70",
    chip: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  },
  {
    key: "DNS",
    type: Service_Spec_Type.DNS,
    label: "DNS",
    icon: Waypoints,
    tile: "from-green-50 to-green-100 text-green-600 ring-green-200/70",
    chip: "bg-green-50 text-green-700 ring-green-200",
  },
  {
    key: "SOCKS5",
    type: Service_Spec_Type.SOCKS5,
    label: "SOCKS5",
    icon: Router,
    tile: "from-fuchsia-50 to-fuchsia-100 text-fuchsia-600 ring-fuchsia-200/70",
    chip: "bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-200",
  },
  {
    key: "RDP_WEB",
    type: Service_Spec_Type.RDP_WEB,
    label: "RDP Web",
    icon: Monitor,
    tile: "from-rose-50 to-rose-100 text-rose-600 ring-rose-200/70",
    chip: "bg-rose-50 text-rose-700 ring-rose-200",
  },
  {
    key: "LLM",
    type: Service_Spec_Type.LLM,
    label: "AI / LLM",
    icon: BrainCircuit,
    tile: "from-purple-50 to-purple-100 text-purple-600 ring-purple-200/70",
    chip: "bg-purple-50 text-purple-700 ring-purple-200",
  },
  {
    key: "MCP",
    type: Service_Spec_Type.MCP,
    label: "MCP",
    icon: SiModelcontextprotocol,
    tile: "from-orange-50 to-orange-100 text-orange-600 ring-orange-200/70",
    chip: "bg-orange-50 text-orange-700 ring-orange-200",
  },
];

export const UNKNOWN_SERVICE_TYPE: ServiceTypeInfo = {
  key: "UNSET",
  type: Service_Spec_Type.UNSET,
  label: "Service",
  icon: Server,
  tile: "from-slate-100 to-slate-200 text-slate-700 ring-slate-300/70",
  chip: "bg-slate-100 text-slate-700 ring-slate-200",
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
