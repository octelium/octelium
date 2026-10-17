import HighlightText from "@/components/HighlightText";
import PageSizeSelect from "@/components/PageSizeSelect";
import Paginator from "@/components/Paginator";
import SearchField from "@/components/SearchField";
import { twMerge } from "@/lib/utils";
import {
  Badge,
  Card,
  CountPill,
  DocumentTitle,
  EmptyState,
  ErrorState,
  IconTile,
  PageHeader,
  RefreshButton,
} from "@/ui";
import { matchesAllTokens, tokenizeQuery } from "@/utils";
import { getClientUser } from "@/utils/client";
import { useAppSelector, useFilterParams } from "@/utils/hooks";
import { Button } from "@mantine/core";
import {
  CommonListOptions_OrderBy_Mode,
  CommonListOptions_OrderBy_Type,
} from "@octelium/apis/main/metav1";
import {
  ListNamespaceOptions,
  ListServiceOptions,
  Namespace,
} from "@octelium/apis/main/userv1";
import { keepPreviousData, useQueries, useQuery } from "@tanstack/react-query";
import { Boxes, ChevronRight, PanelTop, SearchX } from "lucide-react";
import * as React from "react";
import { Link } from "react-router-dom";

const SEARCH_FETCH_LIMIT = 500;

const ORDER_BY_NAME = {
  type: CommonListOptions_OrderBy_Type.NAME,
  mode: CommonListOptions_OrderBy_Mode.ASC,
};

const NamespaceCard = (props: {
  item: Namespace;
  serviceCount?: number;
  tokens: string[];
}) => {
  const { item, serviceCount, tokens } = props;
  const metadata = item.metadata;
  const name = metadata?.name ?? "";

  return (
    <li className="flex">
      <Link
        to={`/services?namespace=${encodeURIComponent(name)}`}
        aria-label={`${name}: show its Services`}
        className="group/card flex w-full flex-col rounded-xl border border-slate-200 bg-white outline-none transition-[border-color,box-shadow] duration-150 hover:border-slate-300 hover:shadow-raised focus-visible:ring-2 focus-visible:ring-slate-400"
      >
        <div className="flex items-start gap-3 px-4 pt-3.5">
          <IconTile>
            <Boxes size={16} strokeWidth={1.9} aria-hidden />
          </IconTile>
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 items-center gap-2">
              <span className="truncate text-sm font-semibold text-slate-900">
                <HighlightText text={name} tokens={tokens} />
              </span>
              {metadata?.isSystem && <Badge tone="blue">System</Badge>}
            </div>
            {metadata?.displayName && (
              <p className="truncate text-xs font-normal leading-5 text-slate-500">
                <HighlightText text={metadata.displayName} tokens={tokens} />
              </p>
            )}
          </div>
          <ChevronRight
            size={16}
            className="mt-2 shrink-0 text-slate-400 transition-[color,transform] duration-150 group-hover/card:translate-x-0.5 group-hover/card:text-slate-700"
            aria-hidden
          />
        </div>

        {metadata?.description && (
          <p className="mt-2.5 line-clamp-2 px-4 text-xs font-normal leading-5 text-slate-600">
            <HighlightText text={metadata.description} tokens={tokens} />
          </p>
        )}

        <div className="mt-auto pt-3.5">
          <div className="flex items-center justify-between gap-2 border-t border-slate-100 px-4 py-2.5">
            {serviceCount === undefined ? (
              <span
                className="block h-4 w-20 rounded bg-slate-100 motion-safe:animate-pulse"
                aria-hidden
              />
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs font-normal text-slate-600">
                <PanelTop size={13} strokeWidth={2} aria-hidden />
                <span>
                  <span className="tabular-nums">
                    {serviceCount.toLocaleString()}
                  </span>{" "}
                  {serviceCount === 1 ? "Service" : "Services"}
                </span>
              </span>
            )}
            <span className="text-xs font-semibold text-slate-500 transition-colors group-hover/card:text-slate-900">
              View Services
            </span>
          </div>
        </div>
      </Link>
    </li>
  );
};

const NamespaceGridSkeleton = () => (
  <div
    role="status"
    aria-label="Loading Namespaces"
    className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3"
  >
    {Array.from({ length: 6 }).map((_, index) => (
      <div
        key={index}
        className="h-[132px] rounded-xl border border-slate-200 bg-white px-4 pt-3.5"
      >
        <div className="flex items-start gap-3">
          <div className="h-9 w-9 rounded-lg bg-slate-100 motion-safe:animate-pulse" />
          <div className="flex-1 space-y-2 pt-1">
            <div className="h-3 w-1/3 rounded bg-slate-100 motion-safe:animate-pulse" />
            <div className="h-2.5 w-1/2 rounded bg-slate-50 motion-safe:animate-pulse" />
          </div>
        </div>
      </div>
    ))}
  </div>
);

const Page = () => {
  const itemsPerPage = useAppSelector(
    (state) => state.settings.itemsPerPage ?? 10,
  );
  const { searchParams, setParams } = useFilterParams();
  const search = (searchParams.get("q") ?? "").trim();
  const page = Math.max(Number(searchParams.get("common.page") ?? "0") || 0, 0);
  const isSearching = search !== "";

  const options = React.useMemo(
    () =>
      ListNamespaceOptions.create({
        common: {
          page: isSearching ? 0 : page,
          itemsPerPage: isSearching ? SEARCH_FETCH_LIMIT : itemsPerPage,
          orderBy: ORDER_BY_NAME,
        },
      }),
    [isSearching, itemsPerPage, page],
  );

  const query = useQuery({
    queryKey: [
      "user/main.listNamespace",
      ListNamespaceOptions.toJsonString(options),
    ],
    queryFn: async () => getClientUser().listNamespace(options),
    placeholderData: keepPreviousData,
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
    return items.filter((item) =>
      matchesAllTokens(
        [
          item.metadata?.name,
          item.metadata?.displayName,
          item.metadata?.description,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase(),
        tokens,
      ),
    );
  }, [items, isSearching, tokens]);

  const serviceCounts = useQueries({
    queries: visibleItems.map((item) => {
      const name = item.metadata?.name ?? "";
      return {
        queryKey: ["user/main.listService.count", name],
        queryFn: async () => {
          const { response } = await getClientUser().listService(
            ListServiceOptions.create({
              common: { page: 0, itemsPerPage: 1 },
              namespace: name,
            }),
          );
          return response.listResponseMeta?.totalCount ?? 0;
        },
        enabled: name !== "",
        retry: false,
        staleTime: 60 * 1000,
      };
    }),
  });

  return (
    <div className="w-full">
      <DocumentTitle title="Namespaces" />
      <PageHeader
        title="Namespaces"
        addon={
          query.isSuccess ? (
            <CountPill count={totalCount} label="Namespaces" />
          ) : undefined
        }
        description="Browse the Namespaces that group your Services."
        actions={
          <RefreshButton
            label="Refresh Namespaces"
            onClick={() => query.refetch()}
            loading={query.isFetching && !query.isPending}
          />
        }
      />

      <div className="z-20 -mx-1 mb-4 border-b border-slate-200 bg-canvas px-1 pb-3 sm:sticky sm:top-[60px] sm:pt-3 sm:supports-[backdrop-filter]:bg-canvas/85 sm:supports-[backdrop-filter]:backdrop-blur">
        <SearchField
          label="Search Namespaces"
          placeholder="Search by name or description"
          value={search}
          onChange={onSearchChange}
        />
      </div>

      {query.isPending ? (
        <NamespaceGridSkeleton />
      ) : query.isError && !query.data ? (
        <ErrorState
          title="Could not load Namespaces"
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
                  isSearching ? (
                    <SearchX size={18} strokeWidth={2} />
                  ) : (
                    <Boxes size={18} strokeWidth={2} />
                  )
                }
                title={
                  isSearching
                    ? "No matching Namespaces"
                    : "No Namespaces available"
                }
                description={
                  isSearching
                    ? `Nothing matched “${search}”.`
                    : "There are no Namespaces available to your account yet."
                }
                action={
                  isSearching ? (
                    <Button
                      variant="default"
                      onClick={() => setParams({ q: null })}
                    >
                      Clear search
                    </Button>
                  ) : undefined
                }
              />
            </Card>
          ) : (
            <ul
              aria-label="Namespaces"
              className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3"
            >
              {visibleItems.map((item, index) => (
                <NamespaceCard
                  item={item}
                  serviceCount={serviceCounts[index]?.data}
                  tokens={tokens}
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
                {items.length === 1 ? "Namespace" : "Namespaces"}{" "}
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
