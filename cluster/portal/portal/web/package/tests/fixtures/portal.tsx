import * as AuthGRPC from "@octelium/apis/main/authv1";
import * as UserGRPC from "@octelium/apis/main/userv1";
import {
  GetStatusResponse_Session_Status_Type,
  GetStatusResponse_User_Spec_Type,
  ListNamespaceOptions,
  ListServiceOptions,
  Namespace,
  NamespaceList,
  Service,
  ServiceList,
  Service_Spec_Type as T,
} from "@octelium/apis/main/userv1";

type FixtureOptions = {
  empty?: boolean;
  failServices?: number;
  slowServices?: boolean;
};

declare global {
  interface Window {
    calls: { method: string; request: unknown }[];
    portalFixture?: FixtureOptions;
  }
}

const options = window.portalFixture ?? {};
const calls: Window["calls"] = [];
window.calls = calls;

const service = (
  name: string,
  namespace: string,
  type: T,
  port: number,
  extra: {
    displayName?: string;
    description?: string;
    isTLS?: boolean;
    isPublic?: boolean;
    addresses?: string[];
  } = {},
) =>
  Service.create({
    metadata: {
      name: `${name}.${namespace}`,
      uid: `${name}-${namespace}`,
      displayName: extra.displayName ?? "",
      description: extra.description ?? "",
    },
    spec: { type, port, isTLS: !!extra.isTLS, isPublic: !!extra.isPublic },
    status: {
      namespace,
      primaryHostname: namespace === "default" ? name : `${name}.${namespace}`,
      addresses: extra.addresses ?? [],
    },
  });

const services = [
  service("api", "default", T.HTTP, 8080, {
    displayName: "Internal API",
    description: "Core REST API used by the internal tooling.",
    addresses: ["fd00:0:1::a", "100.64.0.10"],
  }),
  service("demo-nginx", "default", T.WEB, 80, {
    displayName: "Demo website",
    isPublic: true,
  }),
  service("billing", "production", T.HTTP, 443, {
    displayName: "Billing",
    description: "Payments, invoicing and subscription management.",
    isTLS: true,
  }),
  service("postgres", "production", T.POSTGRES, 5432, {
    displayName: "Primary database",
  }),
  service("mysql-legacy", "production", T.MYSQL, 3306),
  service("k8s", "production", T.KUBERNETES, 443, {
    displayName: "Production cluster",
    isTLS: true,
  }),
  service("ssh-bastion", "staging", T.SSH, 22, {
    description: "Jump host for the staging network.",
  }),
  service("grafana", "staging", T.WEB, 443, {
    displayName: "Grafana",
    isTLS: true,
    isPublic: true,
  }),
  service("clickhouse", "data", T.TCP, 9000),
  service("dns", "data", T.DNS, 53),
  service("socks", "default", T.SOCKS5, 1080),
  service("windows-desktop", "default", T.RDP_WEB, 3389, {
    displayName: "Windows desktop",
    isPublic: true,
  }),
  service("openai", "default", T.LLM, 443, {
    displayName: "OpenAI gateway",
    isTLS: true,
  }),
  service("mcp-github", "default", T.MCP, 443, { displayName: "GitHub MCP" }),
  service("syslog", "data", T.UDP, 514),
  service("orders", "production", T.GRPC, 50051, {
    description: "Order processing gRPC API.",
  }),
].sort((a, b) =>
  a.status!.primaryHostname.localeCompare(b.status!.primaryHostname),
);

const namespaces = [
  ["data", "Data platform", "Analytics, logs and streaming infrastructure."],
  ["default", "", ""],
  ["octelium", "", "System Namespace used by the Cluster."],
  ["production", "Production", "Customer-facing production workloads."],
  ["staging", "Staging", ""],
].map(([name, displayName, description]) =>
  Namespace.create({
    metadata: {
      name,
      uid: `ns-${name}`,
      displayName,
      description,
      isSystem: name === "octelium",
    },
  }),
);

const paginate = <X,>(
  items: X[],
  common?: { page: number; itemsPerPage: number },
) => {
  const itemsPerPage = common?.itemsPerPage || 10;
  const page = common?.page ?? 0;
  return {
    items: items.slice(page * itemsPerPage, (page + 1) * itemsPerPage),
    listResponseMeta: {
      totalCount: items.length,
      page,
      itemsPerPage,
      hasMore: (page + 1) * itemsPerPage < items.length,
    },
  };
};

const user = UserGRPC.MainServiceClient.prototype as unknown as Record<
  string,
  unknown
>;
const auth = AuthGRPC.MainServiceClient.prototype as unknown as Record<
  string,
  unknown
>;

let failures = options.failServices ?? 0;

user.getStatus = async (request: unknown) => {
  calls.push({ method: "getStatus", request });
  return {
    response: {
      domain: "example.com",
      cluster: { metadata: { name: "example", displayName: "Example" } },
      user: {
        metadata: { name: "alice", displayName: "Alice Morgan", picURL: "" },
        spec: {
          email: "alice@example.com",
          type: GetStatusResponse_User_Spec_Type.HUMAN,
        },
      },
      session: {
        metadata: { name: "alice-k2v9xq", picURL: "" },
        status: {
          type: GetStatusResponse_Session_Status_Type.CLIENTLESS,
          isConnected: false,
        },
      },
    },
  };
};

user.listService = async (request: ListServiceOptions) => {
  calls.push({
    method: "listService",
    request: ListServiceOptions.toJson(request),
  });
  if (options.slowServices) {
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  if (failures > 0) {
    failures -= 1;
    throw Object.assign(new Error("permission denied"), {
      code: "PERMISSION_DENIED",
    });
  }
  const items = options.empty
    ? []
    : services.filter(
        (item) =>
          (!request.namespace ||
            item.status?.namespace === request.namespace) &&
          (!request.type || item.spec?.type === request.type),
      );
  return { response: ServiceList.create(paginate(items, request.common)) };
};

user.listNamespace = async (request: ListNamespaceOptions) => {
  calls.push({
    method: "listNamespace",
    request: ListNamespaceOptions.toJson(request),
  });
  return {
    response: NamespaceList.create(
      paginate(options.empty ? [] : namespaces, request.common),
    ),
  };
};

auth.logout = async (request: unknown) => {
  calls.push({ method: "logout", request });
  sessionStorage.setItem(
    "portalFixture.logouts",
    String(Number(sessionStorage.getItem("portalFixture.logouts") ?? 0) + 1),
  );
  return { response: {} };
};

const realFetch = window.fetch.bind(window);
window.fetch = async (input, init) => {
  const url = typeof input === "string" ? input : input.toString();
  if (url.startsWith("https://api.github.com/")) {
    return new Response(
      JSON.stringify({
        tag_name: "v0.24.0",
        html_url: "https://github.com/octelium/octelium/releases/tag/v0.24.0",
        published_at: "2026-10-02T12:00:00Z",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }
  return realFetch(input, init);
};

await import("/src/main.tsx");
