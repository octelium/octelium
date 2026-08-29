import {
  EmptyState,
  ErrorState,
  ResourceListSkeleton,
} from "@/components/AsyncState";
import CopyText from "@/components/CopyText";
import HighlightText from "@/components/HighlightText";
import InfoItem from "@/components/InfoItem";
import PageHeader from "@/components/PageHeader";
import PageSizeSelect from "@/components/PageSizeSelect";
import Paginator from "@/components/Paginator";
import {
  ResourceListItem,
  ResourceListLabel,
  ResourceListWrapper,
} from "@/components/ResourceList";
import ResourceName from "@/components/ResourceName";
import SearchField from "@/components/SearchField";
import {
  getDomain,
  matchesAllTokens,
  printResourceNameWithDisplay,
  tokenizeQuery,
} from "@/utils";
import { getClientUser } from "@/utils/client";
import { useAppSelector, useFilterParams } from "@/utils/hooks";
import {
  getServiceHostname,
  getServicePrivateFQDN,
  getServicePublicFQDN,
} from "@/utils/octelium";
import {
  getServiceTypeByKey,
  getServiceTypeInfo,
  SERVICE_TYPE_OPTIONS,
  type ServiceTypeInfo,
} from "@/utils/octelium/serviceTypes";
import { Button, Collapse, Select } from "@mantine/core";
import {
  CommonListOptions_OrderBy_Mode,
  CommonListOptions_OrderBy_Type,
} from "@octelium/apis/main/metav1";
import {
  ListNamespaceOptions,
  ListServiceOptions,
  Namespace,
  Service,
  Service_Spec_Type,
} from "@octelium/apis/main/userv1";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  ArrowUpRight,
  ChevronDown,
  Globe,
  SearchX,
  ShieldCheck,
  X,
} from "lucide-react";
import * as React from "react";
import { twMerge } from "tailwind-merge";
import ConnectCommand from "./ConnectCommand";

const SEARCH_FETCH_LIMIT = 500;

const ORDER_BY_NAME = {
  type: CommonListOptions_OrderBy_Type.NAME,
  mode: CommonListOptions_OrderBy_Mode.ASC,
};

const namespaceOptions = ListNamespaceOptions.create({
  common: { page: 0, itemsPerPage: 500, orderBy: ORDER_BY_NAME },
});

const Mono = (props: { children?: React.ReactNode }) => (
  <span className="font-mono text-[13px] break-all">{props.children}</span>
);

const ServiceTypeTile = (props: { info: ServiceTypeInfo }) => (
  <div
    className={twMerge(
      "flex h-11 w-11 flex-none items-center justify-center rounded-full",
      "shadow-xs ring-1 transition-transform duration-200",
      "group-hover/item:scale-[1.04]",
      props.info.tile,
    )}
    role="img"
    aria-label={`${props.info.label} service`}
    title={props.info.label}
  >
    <props.info.icon size={22} className="text-white" aria-hidden />
  </div>
);

const ItemDetails = (props: { item: Service; domain: string }) => {
  const { item, domain } = props;
  const metadata = item.metadata;
  const addresses = item.status?.addresses ?? [];

  return (
    <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50/80 p-4">
      {metadata?.description && (
        <p className="mb-4 text-sm font-medium text-slate-600">
          {metadata.description}
        </p>
      )}
      <dl className="grid gap-4 sm:grid-cols-2">
        <InfoItem title="Private FQDN">
          <Mono>
            <CopyText value={getServicePrivateFQDN(item, domain)} />
          </Mono>
        </InfoItem>
        {item.spec?.isPublic && (
          <InfoItem title="Public FQDN">
            <Mono>
              <CopyText value={getServicePublicFQDN(item, domain)} />
            </Mono>
          </InfoItem>
        )}
        <InfoItem title="Resource name">
          <Mono>
            <CopyText value={metadata?.name} />
          </Mono>
        </InfoItem>
        {addresses.length > 0 && (
          <InfoItem title="Private addresses" className="sm:col-span-2">
            <div className="flex flex-wrap gap-x-8 gap-y-1">
              {addresses.map((address) => (
                <Mono key={address}>
                  <CopyText value={address} />
                </Mono>
              ))}
            </div>
          </InfoItem>
        )}
      </dl>
      <ConnectCommand service={item} domain={domain} />
    </div>
  );
};

const ServiceItem = (props: {
  item: Service;
  domain: string;
  tokens: string[];
}) => {
  const { item, domain, tokens } = props;
  const metadata = item.metadata;
  const [expanded, setExpanded] = React.useState(false);
  const typeInfo = getServiceTypeInfo(item);
  const hostname = getServiceHostname(item);
  const subtitle = metadata?.displayName || metadata?.description || "";
  const detailsId = `service-details-${metadata?.uid ?? hostname}`;
  const namespace = item.status?.namespace;
  const privateFQDN = getServicePrivateFQDN(item, domain);
  const canVisit =
    item.spec?.isPublic &&
    (item.spec.type === Service_Spec_Type.WEB ||
      item.spec.type === Service_Spec_Type.RDP_WEB);

  const toggleExpandedFromRow = (event: React.MouseEvent<HTMLElement>) => {
    const target = event.target as HTMLElement;
    if (target.closest("a, button, input, select, textarea, [role='button']")) {
      return;
    }
    setExpanded((value) => !value);
  };

  return (
    <ResourceListItem
      className={
        expanded ? "border-slate-300 shadow-md shadow-slate-900/5" : undefined
      }
    >
      <div
        className="flex cursor-pointer items-start gap-3 sm:gap-4"
        onClick={toggleExpandedFromRow}
      >
        <ServiceTypeTile info={typeInfo} />

        <div className="min-w-0 flex-1">
          <ResourceName
            name={hostname}
            splitNamespace
            copyValue={privateFQDN}
            highlight={tokens}
          />
          {subtitle && (
            <p className="mt-0.5 truncate text-sm font-medium text-slate-500">
              <HighlightText text={subtitle} tokens={tokens} />
            </p>
          )}

          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <ResourceListLabel
              className={typeInfo.chip}
              title={`Service type: ${typeInfo.label}`}
            >
              {typeInfo.label}
            </ResourceListLabel>
            {namespace && (
              <ResourceListLabel
                label="ns"
                to={`/services?namespace=${encodeURIComponent(namespace)}`}
                title={`Show every Service in the ${namespace} Namespace`}
              >
                <HighlightText text={namespace} tokens={tokens} />
              </ResourceListLabel>
            )}
            {item.spec?.port ? (
              <ResourceListLabel label="port" title="Service port">
                {item.spec.port}
              </ResourceListLabel>
            ) : null}
            {item.spec?.isTLS && (
              <ResourceListLabel
                tone="emerald"
                icon={<ShieldCheck size={12} aria-hidden />}
                title="This Service is served over TLS"
              >
                TLS
              </ResourceListLabel>
            )}
            {item.spec?.isPublic && (
              <ResourceListLabel
                tone="sky"
                icon={<Globe size={12} aria-hidden />}
                title="This Service is publicly accessible without the Octelium client"
              >
                Public
              </ResourceListLabel>
            )}
          </div>
        </div>

        <div
          className="hidden max-w-[24rem] min-w-0 flex-none items-center xl:flex"
          title={`Private FQDN: ${privateFQDN}`}
        >
          <span className="truncate rounded-lg bg-slate-50 px-2.5 py-1.5 font-mono text-xs text-slate-500 ring-1 ring-slate-200/70 transition-colors group-hover/item:bg-white group-hover/item:text-slate-600">
            {privateFQDN}
          </span>
        </div>

        <div className="flex flex-none items-center justify-end gap-2 xl:min-w-[7.75rem]">
          {canVisit && (
            <a
              className="inline-flex h-9 items-center justify-center gap-1.5 rounded-lg bg-zinc-900 px-3 text-[13px] font-bold text-white shadow-sm transition-colors hover:bg-black focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
              href={`https://${getServicePublicFQDN(item, domain)}`}
              target="_blank"
              title="Open this Service in a new tab"
            >
              <span className="hidden sm:inline">Open</span>
              <ArrowUpRight size={15} aria-hidden />
            </a>
          )}
          <button
            type="button"
            className="flex h-9 w-9 cursor-pointer items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-500 transition-colors hover:border-slate-300 hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
            aria-controls={detailsId}
            aria-expanded={expanded}
            aria-label={
              expanded ? "Hide service details" : "Show service details"
            }
            title={expanded ? "Hide details" : "Show details"}
            onClick={() => setExpanded((value) => !value)}
          >
            <ChevronDown
              size={18}
              className={twMerge(
                "transition-transform duration-200",
                expanded && "rotate-180",
              )}
              aria-hidden
            />
          </button>
        </div>
      </div>

      <Collapse
        id={detailsId}
        expanded={expanded}
        transitionDuration={200}
        keepMounted={false}
      >
        <ItemDetails item={item} domain={domain} />
      </Collapse>
    </ResourceListItem>
  );
};

const FilterChip = (props: {
  label: string;
  value: string;
  onClear: () => void;
}) => (
  <span className="inline-flex items-center gap-1.5 rounded-md bg-slate-100 py-1 pr-1 pl-2 text-xs font-semibold text-slate-700 ring-1 ring-slate-200">
    <span className="font-medium text-slate-400">{props.label}</span>
    <span className="max-w-[14rem] truncate">{props.value}</span>
    <button
      type="button"
      aria-label={`Clear the ${props.label} filter`}
      className="flex h-4 w-4 cursor-pointer items-center justify-center rounded-full text-slate-400 transition-colors hover:bg-slate-300/60 hover:text-slate-900"
      onClick={props.onClear}
    >
      <X size={12} aria-hidden />
    </button>
  </span>
);

const buildHaystack = (item: Service, domain: string): string =>
  [
    getServiceHostname(item),
    item.metadata?.name,
    item.metadata?.displayName,
    item.metadata?.description,
    item.status?.namespace,
    getServiceTypeInfo(item).label,
    item.spec?.port ? String(item.spec.port) : "",
    getServicePrivateFQDN(item, domain),
    item.spec?.isPublic ? getServicePublicFQDN(item, domain) : "",
    ...(item.status?.addresses ?? []),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

const rankMatch = (item: Service, search: string): number => {
  const hostname = getServiceHostname(item).toLowerCase();

  if (hostname === search) return 0;
  if (hostname.startsWith(search)) return 1;
  if (hostname.includes(search)) return 2;
  return 3;
};

const Page = () => {
  const itemsPerPage = useAppSelector(
    (state) => state.settings.itemsPerPage ?? 10,
  );
  const { searchParams, setParams } = useFilterParams();
  const domain = getDomain();

  const namespace = searchParams.get("namespace") ?? "";
  const typeKey = searchParams.get("type");
  const search = (searchParams.get("q") ?? "").trim();
  const page = Math.max(Number(searchParams.get("common.page") ?? "0") || 0, 0);

  const typeInfo = getServiceTypeByKey(typeKey);
  const isSearching = search !== "";

  const options = React.useMemo(
    () =>
      ListServiceOptions.create({
        common: {
          page: isSearching ? 0 : page,
          itemsPerPage: isSearching ? SEARCH_FETCH_LIMIT : itemsPerPage,
          orderBy: ORDER_BY_NAME,
        },
        namespace,
        type: typeInfo?.type ?? Service_Spec_Type.UNSET,
      }),
    [isSearching, itemsPerPage, namespace, page, typeInfo],
  );

  const query = useQuery({
    queryKey: [
      "user/main.listService",
      ListServiceOptions.toJsonString(options),
    ],
    queryFn: async () => getClientUser().listService(options),
    placeholderData: keepPreviousData,
  });

  const namespacesQuery = useQuery({
    queryKey: [
      "user/main.listNamespace",
      ListNamespaceOptions.toJsonString(namespaceOptions),
    ],
    queryFn: async () => getClientUser().listNamespace(namespaceOptions),
    staleTime: 5 * 60 * 1000,
  });

  const onSearchChange = React.useCallback(
    (value: string) => setParams({ q: value }),
    [setParams],
  );

  const tokens = React.useMemo(() => tokenizeQuery(search), [search]);
  const items = React.useMemo(
    () => query.data?.response.items ?? [],
    [query.data],
  );
  const meta = query.data?.response.listResponseMeta;
  const totalCount = meta?.totalCount ?? items.length;

  const visibleItems = React.useMemo(() => {
    if (!isSearching) {
      return items;
    }
    const needle = search.toLowerCase();

    return items
      .filter((item) => matchesAllTokens(buildHaystack(item, domain), tokens))
      .sort(
        (a, b) =>
          rankMatch(a, needle) - rankMatch(b, needle) ||
          getServiceHostname(a).localeCompare(getServiceHostname(b)),
      );
  }, [items, isSearching, search, tokens, domain]);

  const namespaceData: { value: string; label: string }[] =
    namespacesQuery.data?.response.items
      .filter(
        (item: Namespace) =>
          item.metadata?.name && item.metadata.name !== "octelium",
      )
      .map((item: Namespace) => ({
        value: item.metadata!.name,
        label: printResourceNameWithDisplay(item.metadata!),
      })) ?? [];

  const hasFilters = isSearching || namespace !== "" || typeInfo !== undefined;
  const isTruncatedSearch = isSearching && totalCount > items.length;

  return (
    <>
      <title>Services - Octelium Portal</title>
      <PageHeader
        title="Services"
        description="Discover and connect to the Services available in the Cluster."
        actions={<PageSizeSelect />}
      />

      <div className="mb-4 rounded-xl border border-slate-200 bg-white p-3 shadow-xs sm:p-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-end">
          <SearchField
            className="min-w-0 flex-1"
            label="Search Services"
            placeholder="Search by name, Namespace, type, port or address…"
            value={search}
            onChange={onSearchChange}
          />
          <Select
            className="md:w-56"
            clearable
            searchable
            label="Namespace"
            placeholder="All Namespaces"
            data={namespaceData}
            value={namespace || null}
            onChange={(value) => setParams({ namespace: value })}
          />
          <Select
            className="md:w-48"
            clearable
            label="Type"
            placeholder="All types"
            data={SERVICE_TYPE_OPTIONS}
            value={typeInfo?.key ?? null}
            onChange={(value) => setParams({ type: value })}
          />
        </div>

        {hasFilters && (
          <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-slate-100 pt-3">
            {isSearching && (
              <FilterChip
                label="search"
                value={search}
                onClear={() => setParams({ q: null })}
              />
            )}
            {namespace && (
              <FilterChip
                label="ns"
                value={namespace}
                onClear={() => setParams({ namespace: null })}
              />
            )}
            {typeInfo && (
              <FilterChip
                label="type"
                value={typeInfo.label}
                onClear={() => setParams({ type: null })}
              />
            )}
            <button
              type="button"
              className="ml-auto cursor-pointer text-xs font-bold text-slate-500 underline-offset-4 transition-colors hover:text-slate-900 hover:underline"
              onClick={() =>
                setParams({ q: null, namespace: null, type: null })
              }
            >
              Clear all
            </button>
          </div>
        )}
      </div>

      {query.isPending && <ResourceListSkeleton />}
      {query.isError && (
        <ErrorState
          message="We could not load Services right now."
          onRetry={() => query.refetch()}
        />
      )}
      {query.isSuccess && (
        <div
          className={twMerge(
            "transition-opacity duration-200",
            query.isPlaceholderData && "opacity-60",
          )}
        >
          <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2 px-0.5">
            <p className="text-xs font-bold text-slate-500">
              {isSearching
                ? `${visibleItems.length} of ${totalCount} ${
                    totalCount === 1 ? "Service" : "Services"
                  } ${visibleItems.length === 1 ? "matches" : "match"}`
                : `${totalCount} ${totalCount === 1 ? "Service" : "Services"}`}
            </p>
            {isTruncatedSearch && (
              <p className="text-xs font-semibold text-amber-600">
                Only the first {SEARCH_FETCH_LIMIT} Services are searched
              </p>
            )}
          </div>

          {visibleItems.length === 0 ? (
            isSearching ? (
              <EmptyState
                icon={<SearchX size={22} aria-hidden />}
                title="No Services match your search"
                message={`Nothing matched “${search}”. Try another name, Namespace or type.`}
                action={
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setParams({ q: null })}
                  >
                    Clear search
                  </Button>
                }
              />
            ) : (
              <EmptyState
                title="No Services found"
                message={
                  hasFilters
                    ? "No Service matches the current filters."
                    : "There are no Services available to your account yet."
                }
                action={
                  hasFilters ? (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        setParams({ q: null, namespace: null, type: null })
                      }
                    >
                      Clear filters
                    </Button>
                  ) : undefined
                }
              />
            )
          ) : (
            <ResourceListWrapper>
              {visibleItems.map((item, index) => (
                <ServiceItem
                  item={item}
                  domain={domain}
                  tokens={tokens}
                  key={item.metadata?.uid || item.metadata?.name || index}
                />
              ))}
            </ResourceListWrapper>
          )}

          {!isSearching && <Paginator meta={meta} />}
        </div>
      )}
    </>
  );
};

export default Page;
