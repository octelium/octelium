import {
  EmptyState,
  ErrorState,
  ResourceListSkeleton,
} from "@/components/AsyncState";
import CopyText from "@/components/CopyText";
import InfoItem from "@/components/InfoItem";
import PageHeader from "@/components/PageHeader";
import PageSizeSelect from "@/components/PageSizeSelect";
import Paginator from "@/components/Paginator";
import {
  ResourceListItem,
  ResourceListLabel,
  ResourceListWrapper,
} from "@/components/ResourceList";
import { getClientUser } from "@/utils/client";
import { useAppSelector } from "@/utils/hooks";
import { getDomain, printResourceNameWithDisplay } from "@/utils";
import { getServicePrivateFQDN, getServicePublicFQDN } from "@/utils/octelium";
import {
  ListNamespaceOptions,
  ListServiceOptions,
  Namespace,
  Service,
  ServiceList,
  Service_Spec_Type,
} from "@octelium/apis/main/userv1";
import { Collapse, Select } from "@mantine/core";
import {
  Cable,
  ChevronDown,
  Database,
  ExternalLink,
  Globe2,
  Monitor,
  Network,
  Radio,
  Router,
  Server,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { SiKubernetes, SiMysql, SiPostgresql } from "react-icons/si";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import ConnectCommand from "./ConnectCommand";

const SERVICE_TYPE_OPTIONS: { value: string; label: string }[] = [
  { value: "WEB", label: "Web App" },
  { value: "HTTP", label: "HTTP" },
  { value: "GRPC", label: "gRPC" },
  { value: "SSH", label: "SSH" },
  { value: "KUBERNETES", label: "Kubernetes" },
  { value: "POSTGRES", label: "PostgreSQL" },
  { value: "MYSQL", label: "MySQL" },
  { value: "TCP", label: "TCP" },
  { value: "UDP", label: "UDP" },
  { value: "DNS", label: "DNS" },
  { value: "SOCKS5", label: "SOCKS5" },
  { value: "RDP_WEB", label: "RDP Web" },
];

const getType = (service: Service): string => {
  const type = service.spec?.type;
  return SERVICE_TYPE_OPTIONS.find((option) => option.value === Service_Spec_Type[type ?? 0])?.label ?? "Unknown";
};

const SERVICE_TYPE_ICONS: Record<string, React.ElementType> = {
  "Web App": Globe2,
  HTTP: Globe2,
  "gRPC": Network,
  SSH: Terminal,
  Kubernetes: SiKubernetes,
  PostgreSQL: SiPostgresql,
  MySQL: SiMysql,
  TCP: Cable,
  UDP: Radio,
  DNS: Network,
  SOCKS5: Router,
  "RDP Web": Monitor,
  Unknown: Server,
};

const getTypeIcon = (service: Service) => {
  const type = getType(service);
  const TypeIcon = SERVICE_TYPE_ICONS[type] ?? Database;

  return (
    <div
      className="flex h-12 w-12 flex-none items-center justify-center rounded-2xl bg-gradient-to-br from-zinc-950 via-zinc-900 to-slate-700 text-white shadow-md ring-1 ring-inset ring-white/10"
      role="img"
      aria-label={`${type} service`}
      title={type}
    >
      <span className="flex h-8 w-8 items-center justify-center rounded-xl border border-white/10 bg-white/10 text-white/95">
        <TypeIcon size={22} aria-hidden />
      </span>
    </div>
  );
};

const ItemDetails = (props: { item: Service; domain: string }) => {
  const { item } = props;
  const metadata = item.metadata;

  return (
    <dl className="mt-4 space-y-2 border-t border-slate-200 pt-4">
      {metadata?.description && (
        <InfoItem title="Description">{metadata.description}</InfoItem>
      )}
      <InfoItem title="Private FQDN">
        <CopyText value={getServicePrivateFQDN(item, props.domain)} />
      </InfoItem>
      {item.spec?.isPublic && (
        <InfoItem title="Public FQDN">
          <CopyText value={getServicePublicFQDN(item, props.domain)} />
        </InfoItem>
      )}
      {item.status?.addresses && item.status.addresses.length > 0 && (
        <InfoItem title="Private addresses">
          <div className="space-y-1">
            {item.status.addresses.map((address) => (
              <div key={address}>
                <CopyText value={address} />
              </div>
            ))}
          </div>
        </InfoItem>
      )}
      <ConnectCommand service={item} domain={props.domain} />
    </dl>
  );
};

const ServiceItem = (props: { item: Service; domain: string }) => {
  const { item } = props;
  const metadata = item.metadata;
  const [expanded, setExpanded] = React.useState(false);
  const name = metadata?.name ?? "Unnamed service";
  const displayName = metadata?.displayName;
  const detailsId = `service-details-${metadata?.uid ?? name}`;
  const canVisit =
    item.spec?.isPublic &&
    (item.spec.type === Service_Spec_Type.WEB ||
      item.spec.type === Service_Spec_Type.RDP_WEB);

  return (
    <ResourceListItem>
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start">
        <div className="flex min-w-0 flex-1 items-start gap-3">
          {getTypeIcon(item)}
          <div className="min-w-0 flex-1">
            <h2 className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-base font-extrabold text-slate-900">
              <CopyText value={name} />
              {displayName && <span className="font-semibold text-slate-500">{displayName}</span>}
            </h2>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs font-bold">
              <ResourceListLabel label="Type">{getType(item)}</ResourceListLabel>
              {item.status?.namespace && (
                <ResourceListLabel label="Namespace">{item.status.namespace}</ResourceListLabel>
              )}
              {item.spec?.port && <ResourceListLabel label="Port">{item.spec.port}</ResourceListLabel>}
              {item.spec?.isTLS && (
                <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-1 text-emerald-700">
                  <ShieldCheck size={13} aria-hidden /> TLS
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 lg:justify-end">
          {canVisit && (
            <a
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-zinc-900 px-3 py-2 text-sm font-bold text-white shadow-md transition-colors hover:bg-black focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
              href={`https://${getServicePublicFQDN(item, props.domain)}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              Visit <ExternalLink size={15} aria-hidden />
            </a>
          )}
          <button
            type="button"
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-300 px-3 py-2 text-sm font-bold text-slate-700 transition-colors hover:border-slate-900 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
            aria-controls={detailsId}
            aria-expanded={expanded}
            onClick={() => setExpanded((value) => !value)}
          >
            {expanded ? "Hide details" : "Details"}
            <ChevronDown
              size={16}
              aria-hidden
              className={`transition-transform ${expanded ? "rotate-180" : ""}`}
            />
          </button>
        </div>
      </div>

      <Collapse id={detailsId} expanded={expanded} transitionDuration={200} keepMounted={false}>
        <ItemDetails item={item} domain={props.domain} />
      </Collapse>
    </ResourceListItem>
  );
};

const ServiceResults = (props: { itemsList: ServiceList; domain: string }) => {
  const items = props.itemsList.items ?? [];

  return (
    <>
      <div className="mb-2 flex items-center justify-between text-xs font-semibold text-slate-500">
        <span>{props.itemsList.listResponseMeta?.totalCount ?? items.length} services</span>
      </div>
      <Paginator meta={props.itemsList.listResponseMeta} />
      {items.length === 0 ? (
        <EmptyState
          title="No services found"
          message="Try changing the namespace or type filter."
        />
      ) : (
        <ResourceListWrapper>
          {items.map((item, index) => (
            <ServiceItem
              item={item}
              domain={props.domain}
              key={item.metadata?.uid || item.metadata?.name || index}
            />
          ))}
        </ResourceListWrapper>
      )}
      <Paginator meta={props.itemsList.listResponseMeta} />
    </>
  );
};

const namespaceOptions = ListNamespaceOptions.create({
  common: { page: 0, itemsPerPage: 500 },
});

const Page = () => {
  const itemsPerPage = useAppSelector((state) => state.settings.itemsPerPage ?? 10);
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const namespace = searchParams.get("namespace") ?? "";
  const typeName = searchParams.get("type");
  const page = Math.max(Number(searchParams.get("common.page") ?? "0") || 0, 0);
  const selectedType = SERVICE_TYPE_OPTIONS.some((option) => option.value === typeName)
    ? Service_Spec_Type[typeName as keyof typeof Service_Spec_Type]
    : Service_Spec_Type.UNSET;
  const options = React.useMemo(
    () =>
      ListServiceOptions.create({
        common: { page, itemsPerPage },
        namespace,
        type: selectedType,
      }),
    [itemsPerPage, namespace, page, selectedType],
  );

  const query = useQuery({
    queryKey: ["user/main.listService", ListServiceOptions.toJsonString(options)],
    queryFn: async () => getClientUser().listService(options),
  });
  const namespacesQuery = useQuery({
    queryKey: ["user/main.listNamespace", ListNamespaceOptions.toJsonString(namespaceOptions)],
    queryFn: async () => getClientUser().listNamespace(namespaceOptions),
    staleTime: 5 * 60 * 1000,
  });

  const updateFilter = (key: string, value: string | null) => {
    const nextParams = new URLSearchParams(searchParams);
    nextParams.delete("common.page");
    if (value) nextParams.set(key, value);
    else nextParams.delete(key);
    navigate(`/services${nextParams.toString() ? `?${nextParams}` : ""}`);
  };

  const namespaceData: { value: string; label: string }[] =
    namespacesQuery.data?.response.items
      .filter((item: Namespace) => item.metadata?.name && item.metadata.name !== "octelium")
      .map((item: Namespace) => ({
        value: item.metadata!.name,
        label: printResourceNameWithDisplay(item.metadata!),
      })) ?? [];

  return (
    <>
      <title>Services - Octelium Portal</title>
      <PageHeader
        title="Services"
        description="Connect to the services available through your Octelium account."
        actions={<PageSizeSelect />}
      />

      <div className="mb-6 grid gap-4 rounded-xl border border-slate-200 bg-white/70 p-4 shadow-sm md:grid-cols-[minmax(0,1fr)_14rem]">
        <Select
          clearable
          searchable
          label="Namespace"
          placeholder="All namespaces"
          data={namespaceData}
          value={namespace || null}
          onChange={(value) => updateFilter("namespace", value)}
        />
        <Select
          clearable
          label="Service type"
          placeholder="All types"
          data={SERVICE_TYPE_OPTIONS}
          value={typeName}
          onChange={(value) => updateFilter("type", value)}
        />
      </div>

      {query.isPending && <ResourceListSkeleton />}
      {query.isError && (
        <ErrorState
          message="We could not load services right now."
          onRetry={() => query.refetch()}
        />
      )}
      {query.isSuccess && <ServiceResults itemsList={query.data.response} domain={getDomain()} />}
    </>
  );
};

export default Page;
