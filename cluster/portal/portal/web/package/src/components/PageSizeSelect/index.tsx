import { setItemsPerPage } from "@/features/settings/slice";
import { useAppDispatch, useAppSelector } from "@/utils/hooks";
import { Select } from "@mantine/core";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";

const PageSizeSelect = () => {
  const dispatch = useAppDispatch();
  const value = useAppSelector((state) => state.settings.itemsPerPage ?? 10);
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  return (
    <Select
      aria-label="Items per page"
      className="w-full sm:w-40"
      data={["10", "20", "50", "100"]}
      label="Items per page"
      onChange={(nextValue) => {
        const next = Number(nextValue);
        if (Number.isFinite(next) && next > 0) {
          dispatch(setItemsPerPage({ itemsPerPage: next }));
          const nextParams = new URLSearchParams(searchParams);
          nextParams.delete("common.page");
          navigate(`${location.pathname}${nextParams.toString() ? `?${nextParams}` : ""}`);
        }
      }}
      value={String(value)}
    />
  );
};

export default PageSizeSelect;
