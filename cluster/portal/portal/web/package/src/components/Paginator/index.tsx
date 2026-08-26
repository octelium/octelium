import { Pagination } from "@mantine/core";
import type { ListResponseMeta } from "@octelium/apis/main/metav1";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";

const Paginator = (props: { meta?: ListResponseMeta }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const meta = props.meta;

  if (!meta || meta.itemsPerPage <= 0) {
    return null;
  }

  const totalPages = Math.ceil(meta.totalCount / meta.itemsPerPage);
  if (totalPages <= 1) {
    return null;
  }

  const currentPage = Math.min(Math.max(meta.page + 1, 1), totalPages);

  return (
    <div className="flex w-full justify-center py-4">
      <Pagination
        aria-label="Pagination"
        total={totalPages}
        value={currentPage}
        onChange={(value) => {
          const nextParams = new URLSearchParams(searchParams);
          nextParams.set("common.page", String(value - 1));
          navigate(`${location.pathname}?${nextParams.toString()}`);
        }}
        size="sm"
        radius="xl"
        withEdges
        color="#111"
      />
    </div>
  );
};

export default Paginator;
