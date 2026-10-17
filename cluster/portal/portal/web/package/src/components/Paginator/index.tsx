import { Pagination } from "@mantine/core";
import type { ListResponseMeta } from "@octelium/apis/main/metav1";
import type * as React from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";

const Paginator = (props: {
  meta?: ListResponseMeta;
  children?: React.ReactNode;
}) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const meta = props.meta;

  if (!meta || meta.totalCount <= 0) {
    return null;
  }

  const itemsPerPage = Math.max(meta.itemsPerPage, 1);
  const totalPages = Math.max(1, Math.ceil(meta.totalCount / itemsPerPage));
  const currentPage = Math.min(Math.max(meta.page + 1, 1), totalPages);
  const first = (currentPage - 1) * itemsPerPage + 1;
  const last = Math.min(meta.totalCount, currentPage * itemsPerPage);

  return (
    <div className="mt-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <span className="text-xs font-normal tabular-nums text-slate-600">
          {totalPages > 1
            ? `${first.toLocaleString()}–${last.toLocaleString()} of ${meta.totalCount.toLocaleString()}`
            : `${meta.totalCount.toLocaleString()} ${meta.totalCount === 1 ? "item" : "items"}`}
        </span>
        {props.children}
      </div>

      {totalPages > 1 && (
        <nav aria-label="Pagination">
          <Pagination
            total={totalPages}
            value={currentPage}
            onChange={(value) => {
              const nextParams = new URLSearchParams(searchParams);
              nextParams.set("common.page", String(value - 1));
              navigate(`${location.pathname}?${nextParams.toString()}`);
            }}
            size="sm"
            radius="md"
            color="ink"
            withEdges
          />
        </nav>
      )}
    </div>
  );
};

export default Paginator;
