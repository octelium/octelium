import { Service, Service_Spec_Type } from "@octelium/apis/main/userv1";
import {
  AppWindow,
  Braces,
  BrainCircuit,
  Cable,
  Database,
  Globe2,
  Monitor,
  Plug,
  Radio,
  Router,
  Server,
  ShipWheel,
  SquareTerminal,
  Waypoints,
} from "lucide-react";
import type { ComponentType } from "react";

export type ServiceTypeIcon = ComponentType<{
  size?: number;
  strokeWidth?: number;
  className?: string;
}>;

export type ServiceTypeInfo = {
  key: string;
  type: Service_Spec_Type;
  label: string;
  icon: ServiceTypeIcon;
};

export const SERVICE_TYPES: ServiceTypeInfo[] = [
  { key: "HTTP", type: Service_Spec_Type.HTTP, label: "HTTP", icon: Globe2 },
  { key: "WEB", type: Service_Spec_Type.WEB, label: "Web", icon: AppWindow },
  { key: "GRPC", type: Service_Spec_Type.GRPC, label: "gRPC", icon: Braces },
  {
    key: "SSH",
    type: Service_Spec_Type.SSH,
    label: "SSH",
    icon: SquareTerminal,
  },
  {
    key: "KUBERNETES",
    type: Service_Spec_Type.KUBERNETES,
    label: "Kubernetes",
    icon: ShipWheel,
  },
  {
    key: "POSTGRES",
    type: Service_Spec_Type.POSTGRES,
    label: "PostgreSQL",
    icon: Database,
  },
  {
    key: "MYSQL",
    type: Service_Spec_Type.MYSQL,
    label: "MySQL",
    icon: Database,
  },
  { key: "TCP", type: Service_Spec_Type.TCP, label: "TCP", icon: Cable },
  { key: "UDP", type: Service_Spec_Type.UDP, label: "UDP", icon: Radio },
  { key: "DNS", type: Service_Spec_Type.DNS, label: "DNS", icon: Waypoints },
  {
    key: "SOCKS5",
    type: Service_Spec_Type.SOCKS5,
    label: "SOCKS5",
    icon: Router,
  },
  {
    key: "RDP_WEB",
    type: Service_Spec_Type.RDP_WEB,
    label: "RDP Web",
    icon: Monitor,
  },
  { key: "LLM", type: Service_Spec_Type.LLM, label: "LLM", icon: BrainCircuit },
  {
    key: "MCP",
    type: Service_Spec_Type.MCP,
    label: "MCP",
    icon: Plug,
  },
];

export const UNKNOWN_SERVICE_TYPE: ServiceTypeInfo = {
  key: "UNSET",
  type: Service_Spec_Type.UNSET,
  label: "Service",
  icon: Server,
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
