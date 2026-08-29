import {
  EmptyState,
  ErrorState,
  ResourceListSkeleton,
} from "@/components/AsyncState";
import HighlightText from "@/components/HighlightText";
import Label from "@/components/Label";
import PageHeader from "@/components/PageHeader";
import PageSizeSelect from "@/components/PageSizeSelect";
import Paginator from "@/components/Paginator";
import SearchField from "@/components/SearchField";
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
import { ArrowRight, Boxes, PanelTop, SearchX } from "lucide-react";
import * as React from "react";
import { Link } from "react-router-dom";
import { twMerge } from "tailwind-merge";

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
  const name = metadata?.name ?? "Unnamed namespace";

  return (
    <Link
      to={`/services?namespace=${encodeURIComponent(name)}`}
      title={`Show every Service in the ${name} Namespace`}
      className={twMerge(
        "group/item flex h-full flex-col gap-3 rounded-xl border border-slate-200 bg-white p-4",
        "shadow-xs transition-all duration-500",
        "hover:border-slate-300 hover:bg-slate-50/70 hover:shadow-md hover:shadow-slate-900/5",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900",
      )}
    >
      <div className="flex items-start gap-3">
        <div className="flex h-11 w-11 flex-none items-center justify-center rounded-xl bg-gradient-to-br from-slate-700 to-zinc-900 text-white shadow-sm ring-1 ring-slate-900/10 transition-transform duration-200 group-hover/item:scale-[1.04]">
          <Boxes size={21} aria-hidden />
        </div>
        <div className="min-w-0 flex-1">
          <h2 className="truncate text-[15px] font-bold tracking-tight text-slate-900 sm:text-base">
            <HighlightText text={name} tokens={tokens} />
          </h2>
          {metadata?.displayName && (
            <p className="mt-0.5 truncate text-sm font-medium text-slate-500">
              <HighlightText text={metadata.displayName} tokens={tokens} />
            </p>
          )}
        </div>
        <ArrowRight
          size={16}
          className="mt-1 flex-none text-slate-300 transition-all duration-200 group-hover/item:translate-x-0.5 group-hover/item:text-slate-900"
          aria-hidden
        />
      </div>

      {metadata?.description && (
        <p className="line-clamp-2 text-sm font-medium text-slate-500">
          {metadata.description}
        </p>
      )}

      <div className="mt-auto flex items-center justify-between gap-2 border-t border-slate-100 pt-3">
        {serviceCount === undefined ? (
          <span
            className="block h-[22px] w-24 animate-pulse rounded-md bg-slate-100"
            aria-hidden
          />
        ) : (
          <Label tone="slate">
            <PanelTop size={12} className="opacity-70" aria-hidden />
            {serviceCount} {serviceCount === 1 ? "Service" : "Services"}
          </Label>
        )}
        <span className="text-xs font-bold text-slate-400 transition-colors group-hover/item:text-slate-900">
          Browse
        </span>
      </div>
    </Link>
  );
};

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
    <>
      <title>Namespaces - Octelium Portal</title>
      <PageHeader
        title="Namespaces"
        description="Browse the Namespaces and jump into their Services."
        actions={<PageSizeSelect />}
      />

      <div className="mb-4 rounded-xl border border-slate-200 bg-white p-3 shadow-xs sm:p-4">
        <SearchField
          label="Search Namespaces"
          placeholder="Search by name or description…"
          value={search}
          onChange={onSearchChange}
        />
      </div>

      {query.isPending && <ResourceListSkeleton count={4} />}
      {query.isError && (
        <ErrorState
          message="We could not load Namespaces right now."
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
          <div className="mb-3 px-0.5">
            <p className="text-xs font-bold text-slate-500">
              {isSearching
                ? `${visibleItems.length} of ${totalCount} ${
                    totalCount === 1 ? "Namespace" : "Namespaces"
                  } ${visibleItems.length === 1 ? "matches" : "match"}`
                : `${totalCount} ${
                    totalCount === 1 ? "Namespace" : "Namespaces"
                  }`}
            </p>
          </div>

          {visibleItems.length === 0 ? (
            <EmptyState
              icon={isSearching ? <SearchX size={22} aria-hidden /> : undefined}
              title={
                isSearching
                  ? "No Namespaces match your search"
                  : "No Namespaces found"
              }
              message={
                isSearching
                  ? `Nothing matched “${search}”.`
                  : "There are no Namespaces available to your account."
              }
              action={
                isSearching ? (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setParams({ q: null })}
                  >
                    Clear search
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <div className="grid w-full gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {visibleItems.map((item, index) => (
                <NamespaceCard
                  item={item}
                  serviceCount={serviceCounts[index]?.data}
                  tokens={tokens}
                  key={item.metadata?.uid || item.metadata?.name || index}
                />
              ))}
            </div>
          )}

          {!isSearching && <Paginator meta={meta} />}
        </div>
      )}
    </>
  );
};

export default Page;
