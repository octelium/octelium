import {
  EmptyState,
  ErrorState,
  ResourceListSkeleton,
} from "@/components/AsyncState";
import CopyText from "@/components/CopyText";
import PageHeader from "@/components/PageHeader";
import PageSizeSelect from "@/components/PageSizeSelect";
import Paginator from "@/components/Paginator";
import {
  ResourceListItem,
  ResourceListWrapper,
} from "@/components/ResourceList";
import { getClientUser } from "@/utils/client";
import { useAppSelector } from "@/utils/hooks";
import {
  ListNamespaceOptions,
  Namespace,
  NamespaceList,
} from "@octelium/apis/main/userv1";
import { ArrowRight, Boxes } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";

const NamespaceItem = (props: { item: Namespace }) => {
  const metadata = props.item.metadata;
  const name = metadata?.name ?? "Unnamed namespace";
  const displayName = metadata?.displayName;

  return (
    <ResourceListItem>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-11 w-11 flex-none items-center justify-center rounded-xl bg-zinc-900 text-white shadow-md">
            <Boxes size={20} aria-hidden />
          </div>
          <div className="min-w-0">
            <h2 className="flex min-w-0 flex-wrap items-center gap-x-2 text-base font-extrabold text-slate-900">
              <CopyText value={name} />
              {displayName && (
                <span className="font-semibold text-slate-500">{displayName}</span>
              )}
            </h2>
            <p className="mt-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
              Namespace
            </p>
          </div>
        </div>

        <Link
          className="inline-flex items-center justify-center gap-2 self-start rounded-lg border border-slate-300 px-3 py-2 text-sm font-bold text-slate-700 transition-colors hover:border-slate-900 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 sm:self-auto"
          to={`/services?namespace=${encodeURIComponent(name)}`}
        >
          View services
          <ArrowRight size={16} aria-hidden />
        </Link>
      </div>
    </ResourceListItem>
  );
};

const NamespaceResults = (props: { itemsList: NamespaceList }) => {
  const items = props.itemsList.items ?? [];

  return (
    <>
      <Paginator meta={props.itemsList.listResponseMeta} />
      {items.length === 0 ? (
        <EmptyState
          title="No namespaces found"
          message="There are no namespaces available for your account."
        />
      ) : (
        <ResourceListWrapper>
          {items.map((item, index) => (
            <NamespaceItem
              item={item}
              key={item.metadata?.uid || item.metadata?.name || index}
            />
          ))}
        </ResourceListWrapper>
      )}
      <Paginator meta={props.itemsList.listResponseMeta} />
    </>
  );
};

const Page = () => {
  const itemsPerPage = useAppSelector(
    (state) => state.settings.itemsPerPage ?? 10,
  );
  const [searchParams] = useSearchParams();
  const page = Math.max(Number(searchParams.get("common.page") ?? "1") || 1, 1);
  const options = ListNamespaceOptions.create({
    common: { page: page - 1, itemsPerPage },
  });

  const query = useQuery({
    queryKey: [
      "user/main.listNamespaces",
      ListNamespaceOptions.toJsonString(options),
    ],
    queryFn: async () => getClientUser().listNamespace(options),
  });

  return (
    <>
      <title>Namespaces - Octelium Portal</title>
      <PageHeader
        title="Namespaces"
        description="Browse the namespaces available to your account and jump to their services."
        actions={<PageSizeSelect />}
      />
      {query.isPending && <ResourceListSkeleton />}
      {query.isError && (
        <ErrorState
          message="We could not load namespaces right now."
          onRetry={() => query.refetch()}
        />
      )}
      {query.isSuccess && <NamespaceResults itemsList={query.data.response} />}
    </>
  );
};

export default Page;
