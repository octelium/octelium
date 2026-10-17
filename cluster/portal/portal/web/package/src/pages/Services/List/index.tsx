import HighlightText from "@/components/HighlightText";
import PageSizeSelect from "@/components/PageSizeSelect";
import Paginator from "@/components/Paginator";
import {
  ResourceListLabel,
  ResourceListLabelWrap,
} from "@/components/ResourceList";
import SearchField from "@/components/SearchField";
import { twMerge } from "@/lib/utils";
import {
  Card,
  CopyButton,
  CopyValue,
  CountPill,
  DocumentTitle,
  EmptyState,
  ErrorState,
  IconTile,
  InfoGrid,
  KeyValue,
  Note,
  PageHeader,
  RefreshButton,
  SkeletonRows,
} from "@/ui";
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
  getServicePublicURL,
} from "@/utils/octelium";
import {
  getServiceTypeByKey,
  getServiceTypeInfo,
  SERVICE_TYPE_OPTIONS,
} from "@/utils/octelium/serviceTypes";
import { ActionIcon, Button, Collapse, Select } from "@mantine/core";
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
  AlertTriangle,
  ArrowUpRight,
  ChevronDown,
  FilterX,
  Globe,
  Lock,
  PanelTop,
  SearchX,
  X,
} from "lucide-react";
import * as React from "react";
import ConnectCommand from "./ConnectCommand";

const SEARCH_FETCH_LIMIT = 500;

const ORDER_BY_NAME = {
  type: CommonListOptions_OrderBy_Type.NAME,
  mode: CommonListOptions_OrderBy_Mode.ASC,
};

const namespaceOptions = ListNamespaceOptions.create({
  common: { page: 0, itemsPerPage: 500, orderBy: ORDER_BY_NAME },
});

const typeOptionIcons = new Map(
  SERVICE_TYPE_OPTIONS.map((option) => [
    option.value,
    getServiceTypeByKey(option.value)!.icon,
  ]),
);

const ServiceDetails = (props: { item: Service; domain: string }) => {
  const { item, domain } = props;
  const addresses = item.status?.addresses ?? [];
  const publicURL = item.spec?.isPublic
    ? getServicePublicURL(item, domain)
    : undefined;

  return (
    <div className="@container border-t border-slate-100 px-4 pb-4 pt-3.5 sm:pl-16">
      <InfoGrid>
        <KeyValue label="Private hostname">
          <CopyValue
            value={getServicePrivateFQDN(item, domain)}
            copyLabel="Copy private hostname"
          />
        </KeyValue>
        {publicURL && (
          <KeyValue label="Public URL">
            <span className="inline-flex min-w-0 items-center gap-1">
              <a
                href={publicURL}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded font-mono text-xs font-medium text-blue-700 underline-offset-2 outline-none [overflow-wrap:anywhere] hover:underline focus-visible:ring-2 focus-visible:ring-blue-500/40"
              >
                {publicURL}
              </a>
              <CopyButton value={publicURL} label="Copy public URL" />
            </span>
          </KeyValue>
        )}
        <KeyValue label="Resource name">
          <CopyValue
            value={item.metadata?.name ?? ""}
            copyLabel="Copy resource name"
          />
        </KeyValue>
        {addresses.length > 0 && (
          <KeyValue label="Private addresses" full>
            {addresses.map((address) => (
              <CopyValue
                key={address}
                value={address}
                copyLabel={`Copy ${address}`}
              />
            ))}
          </KeyValue>
        )}
      </InfoGrid>
      <ConnectCommand service={item} domain={domain} className="mt-4" />
    </div>
  );
};

const ServiceRow = (props: {
  item: Service;
  domain: string;
  tokens: string[];
  namespaceFilter: string;
  typeFilter?: string;
  buildURL: (updates: Record<string, string | null>) => string;
}) => {
  const { item, domain, tokens } = props;
  const metadata = item.metadata;
  const [expanded, setExpanded] = React.useState(false);
  const detailsId = React.useId();
  const typeInfo = getServiceTypeInfo(item);
  const hostname = getServiceHostname(item);
  const separatorIndex = hostname.indexOf(".");
  const name =
    separatorIndex > 0 ? hostname.slice(0, separatorIndex) : hostname;
  const suffix = separatorIndex > 0 ? hostname.slice(separatorIndex) : "";
  const displayName = metadata?.displayName;
  const description = metadata?.description;
  const namespace = item.status?.namespace;
  const canVisit =
    item.spec?.isPublic &&
    (item.spec.type === Service_Spec_Type.WEB ||
      item.spec.type === Service_Spec_Type.RDP_WEB);

  const toggleFromRow = (event: React.MouseEvent<HTMLElement>) => {
    const target = event.target as HTMLElement;
    if (
      target.closest("a, button, input, select, textarea, [role='button']") ||
      window.getSelection()?.toString()
    ) {
      return;
    }
    setExpanded((value) => !value);
  };

  return (
    <li>
      <Card
        interactive
        className={twMerge(
          "group/row",
          expanded && "border-slate-300 shadow-raised",
        )}
      >
        <div
          className="grid cursor-pointer grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-x-3 px-4 py-3.5"
          onClick={toggleFromRow}
        >
          <IconTile className="sm:row-span-2">
            <typeInfo.icon size={16} strokeWidth={1.9} aria-hidden />
          </IconTile>

          <div className="min-w-0">
            <div className="flex min-w-0 items-center gap-1.5">
              <span className="min-w-0 truncate text-sm font-semibold text-slate-900">
                <HighlightText text={name} tokens={tokens} />
                {suffix && (
                  <span className="font-normal text-slate-400">
                    <HighlightText text={suffix} tokens={tokens} />
                  </span>
                )}
              </span>
              <CopyButton
                value={getServicePrivateFQDN(item, domain)}
                label="Copy private hostname"
                className="shrink-0"
              />
              {displayName && (
                <span className="hidden min-w-0 truncate text-sm font-normal text-slate-500 sm:inline">
                  <HighlightText text={displayName} tokens={tokens} />
                </span>
              )}
            </div>

            {(description || displayName) && (
              <p
                className={twMerge(
                  "truncate text-xs font-normal leading-5 text-slate-500",
                  !description && "sm:hidden",
                )}
              >
                {displayName && (
                  <span className="sm:hidden">
                    <HighlightText text={displayName} tokens={tokens} />
                    {description && (
                      <span aria-hidden className="mx-1.5 text-slate-300">
                        ·
                      </span>
                    )}
                  </span>
                )}
                {description && (
                  <HighlightText text={description} tokens={tokens} />
                )}
              </p>
            )}
          </div>

          <div className="flex shrink-0 items-center gap-1 sm:row-span-2">
            {canVisit && (
              <Button
                component="a"
                href={`https://${getServicePublicFQDN(item, domain)}`}
                target="_blank"
                rel="noopener noreferrer"
                variant="default"
                size="xs"
                rightSection={<ArrowUpRight size={13} strokeWidth={2.25} />}
                aria-label={`Open ${hostname} in a new tab`}
              >
                Open
              </Button>
            )}
            <ActionIcon
              variant="subtle"
              color="gray"
              size={30}
              aria-controls={detailsId}
              aria-expanded={expanded}
              aria-label={`${expanded ? "Hide" : "Show"} details of ${hostname}`}
              onClick={() => setExpanded((value) => !value)}
            >
              <ChevronDown
                size={16}
                strokeWidth={2.25}
                className={twMerge(
                  "text-slate-500 transition-transform duration-200",
                  expanded && "rotate-180",
                )}
                aria-hidden
              />
            </ActionIcon>
          </div>

          <ResourceListLabelWrap className="col-span-3 mt-2 sm:col-span-1 sm:col-start-2">
            {typeInfo.key !== "UNSET" && (
              <ResourceListLabel
                label="Type"
                title={`Show only ${typeInfo.label} Services`}
                to={
                  props.typeFilter === typeInfo.key
                    ? undefined
                    : props.buildURL({ type: typeInfo.key })
                }
              >
                <HighlightText text={typeInfo.label} tokens={tokens} />
              </ResourceListLabel>
            )}
            {namespace && (
              <ResourceListLabel
                label="Namespace"
                title={`Show only the Services of the ${namespace} Namespace`}
                to={
                  props.namespaceFilter === namespace
                    ? undefined
                    : props.buildURL({ namespace })
                }
              >
                <HighlightText text={namespace} tokens={tokens} />
              </ResourceListLabel>
            )}
            {item.spec?.port ? (
              <ResourceListLabel label="Port">
                <span className="tabular-nums">{item.spec.port}</span>
              </ResourceListLabel>
            ) : null}
            {item.spec?.isTLS && (
              <ResourceListLabel
                icon={<Lock aria-hidden />}
                title="This Service is served over TLS"
              >
                TLS
              </ResourceListLabel>
            )}
            {item.spec?.isPublic && (
              <ResourceListLabel
                icon={<Globe aria-hidden />}
                title="This Service is publicly accessible without the Octelium client"
              >
                Public
              </ResourceListLabel>
            )}
          </ResourceListLabelWrap>
        </div>

        <Collapse
          id={detailsId}
          expanded={expanded}
          transitionDuration={200}
          keepMounted={false}
        >
          <ServiceDetails item={item} domain={domain} />
        </Collapse>
      </Card>
    </li>
  );
};

const FilterChip = (props: {
  label: string;
  value: string;
  onClear: () => void;
}) => (
  <span className="inline-flex max-w-full items-center gap-1 rounded-md border border-slate-200 bg-white py-0.5 pl-2 pr-0.5 text-micro font-medium leading-4 text-slate-600 shadow-card">
    <span className="shrink-0 font-semibold text-slate-500">
      {props.label}:
    </span>
    <span className="min-w-0 truncate">{props.value}</span>
    <button
      type="button"
      aria-label={`Remove the ${props.label} filter`}
      title={`Remove the ${props.label} filter`}
      className="flex h-4 w-4 shrink-0 items-center justify-center rounded text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-400"
      onClick={props.onClear}
    >
      <X size={10} strokeWidth={2.5} aria-hidden />
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
  const { searchParams, setParams, buildURL } = useFilterParams();
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
    (value: string) => setParams({ q: value }, { replace: true }),
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

  if (namespace && !namespaceData.some((item) => item.value === namespace)) {
    namespaceData.unshift({ value: namespace, label: namespace });
  }

  const hasFilters = isSearching || namespace !== "" || typeInfo !== undefined;
  const isTruncatedSearch = isSearching && totalCount > items.length;
  const clearFilters = () =>
    setParams({ q: null, namespace: null, type: null });

  return (
    <div className="w-full">
      <DocumentTitle title="Services" />
      <PageHeader
        title="Services"
        addon={
          query.isSuccess ? (
            <CountPill count={totalCount} label="Services" />
          ) : undefined
        }
        description="Discover the Services available to you and how to connect to them."
        actions={
          <RefreshButton
            label="Refresh Services"
            onClick={() => query.refetch()}
            loading={query.isFetching && !query.isPending}
          />
        }
      />

      <div className="z-20 -mx-1 mb-4 flex flex-col gap-2.5 border-b border-slate-200 bg-canvas px-1 pb-3 sm:sticky sm:top-[60px] sm:pt-3 sm:supports-[backdrop-filter]:bg-canvas/85 sm:supports-[backdrop-filter]:backdrop-blur">
        <div className="flex flex-col gap-2 lg:flex-row lg:items-center">
          <SearchField
            className="min-w-0 flex-1"
            label="Search Services"
            placeholder="Search by name, Namespace, type, port or address"
            value={search}
            onChange={onSearchChange}
          />
          <div className="grid grid-cols-2 gap-2 lg:flex lg:shrink-0">
            <Select
              className="min-w-0 lg:w-52"
              aria-label="Filter by Namespace"
              placeholder="All Namespaces"
              searchable
              clearable
              clearSectionMode="clear"
              nothingFoundMessage="No matching Namespaces"
              data={namespaceData}
              value={namespace || null}
              onChange={(value) => setParams({ namespace: value })}
            />
            <Select
              className="min-w-0 lg:w-44"
              aria-label="Filter by type"
              placeholder="All types"
              clearable
              clearSectionMode="clear"
              data={SERVICE_TYPE_OPTIONS}
              value={typeInfo?.key ?? null}
              onChange={(value) => setParams({ type: value })}
              renderOption={({ option }) => {
                const Icon = typeOptionIcons.get(option.value);
                return (
                  <span className="flex items-center gap-2">
                    {Icon && (
                      <Icon
                        size={14}
                        strokeWidth={2}
                        className="shrink-0 opacity-70"
                      />
                    )}
                    {option.label}
                  </span>
                );
              }}
            />
          </div>
        </div>

        {hasFilters && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-0.5 text-micro font-semibold uppercase tracking-[0.06em] text-slate-500">
              Filters
            </span>
            {isSearching && (
              <FilterChip
                label="Search"
                value={search}
                onClear={() => setParams({ q: null })}
              />
            )}
            {namespace && (
              <FilterChip
                label="Namespace"
                value={namespace}
                onClear={() => setParams({ namespace: null })}
              />
            )}
            {typeInfo && (
              <FilterChip
                label="Type"
                value={typeInfo.label}
                onClear={() => setParams({ type: null })}
              />
            )}
            <button
              type="button"
              className="ml-1.5 rounded text-xs font-semibold text-slate-600 transition-colors hover:text-slate-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-400"
              onClick={clearFilters}
            >
              Clear filters
            </button>
          </div>
        )}
      </div>

      {query.isError && query.data && (
        <Note
          tone="amber"
          icon={<AlertTriangle size={14} aria-hidden />}
          className="mb-3"
        >
          <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
            <span role="alert">
              Refreshing failed. Showing the last loaded Services.
            </span>
            <button
              type="button"
              className="rounded font-semibold underline-offset-2 hover:underline"
              onClick={() => query.refetch()}
            >
              Retry
            </button>
          </div>
        </Note>
      )}

      {isTruncatedSearch && (
        <Note icon={<AlertTriangle size={14} aria-hidden />} className="mb-3">
          Search covers the first {SEARCH_FETCH_LIMIT.toLocaleString()} of{" "}
          {totalCount.toLocaleString()} Services. Narrow it down with the
          Namespace or type filters.
        </Note>
      )}

      {query.isPending ? (
        <SkeletonRows rows={6} label="Loading Services" />
      ) : query.isError && !query.data ? (
        <ErrorState
          title="Could not load Services"
          error={query.error}
          onRetry={() => query.refetch()}
        />
      ) : (
        <div
          className={twMerge(
            "transition-opacity duration-200",
            query.isPlaceholderData && "opacity-60",
          )}
          aria-busy={query.isPlaceholderData || undefined}
        >
          {visibleItems.length === 0 ? (
            <Card>
              <EmptyState
                icon={
                  hasFilters ? (
                    isSearching ? (
                      <SearchX size={18} strokeWidth={2} />
                    ) : (
                      <FilterX size={18} strokeWidth={2} />
                    )
                  ) : (
                    <PanelTop size={18} strokeWidth={2} />
                  )
                }
                title={
                  hasFilters ? "No matching Services" : "No Services available"
                }
                description={
                  isSearching
                    ? `Nothing matched “${search}”. Try another name, Namespace or type.`
                    : hasFilters
                      ? "No Service matches the current filters."
                      : "There are no Services available to your account yet."
                }
                action={
                  hasFilters ? (
                    <Button
                      variant="default"
                      leftSection={<FilterX size={14} strokeWidth={2.25} />}
                      onClick={clearFilters}
                    >
                      Clear filters
                    </Button>
                  ) : undefined
                }
              />
            </Card>
          ) : (
            <ul aria-label="Services" className="flex flex-col gap-2">
              {visibleItems.map((item, index) => (
                <ServiceRow
                  item={item}
                  domain={domain}
                  tokens={tokens}
                  namespaceFilter={namespace}
                  typeFilter={typeInfo?.key}
                  buildURL={buildURL}
                  key={item.metadata?.uid || item.metadata?.name || index}
                />
              ))}
            </ul>
          )}

          {isSearching ? (
            visibleItems.length > 0 && (
              <p className="mt-5 text-xs font-normal tabular-nums text-slate-600">
                {visibleItems.length.toLocaleString()} of{" "}
                {items.length.toLocaleString()}{" "}
                {items.length === 1 ? "Service" : "Services"}{" "}
                {visibleItems.length === 1 ? "matches" : "match"}
              </p>
            )
          ) : (
            <Paginator meta={meta}>
              <PageSizeSelect />
            </Paginator>
          )}
        </div>
      )}
    </div>
  );
};

export default Page;
