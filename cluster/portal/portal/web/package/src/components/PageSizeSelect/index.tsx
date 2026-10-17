import { setItemsPerPage } from "@/features/settings/slice";
import { useAppDispatch, useAppSelector } from "@/utils/hooks";
import {
  DEFAULT_ITEMS_PER_PAGE,
  ITEMS_PER_PAGE_OPTIONS,
  isValidItemsPerPage,
} from "@/utils/preferences";
import { Select } from "@mantine/core";
import { useId } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";

const PageSizeSelect = () => {
  const id = useId();
  const dispatch = useAppDispatch();
  const value = useAppSelector(
    (state) => state.settings.itemsPerPage ?? DEFAULT_ITEMS_PER_PAGE,
  );
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  return (
    <div className="flex items-center gap-1.5">
      <label htmlFor={id} className="text-xs font-normal text-slate-600">
        Per page
      </label>
      <Select
        id={id}
        size="xs"
        w={78}
        allowDeselect={false}
        styles={{ input: { minHeight: 30 } }}
        data={ITEMS_PER_PAGE_OPTIONS.map(String)}
        value={String(value)}
        onChange={(nextValue) => {
          const next = Number(nextValue);
          if (!isValidItemsPerPage(next)) {
            return;
          }
          dispatch(setItemsPerPage({ itemsPerPage: next }));
          const nextParams = new URLSearchParams(searchParams);
          nextParams.delete("common.page");
          const query = nextParams.toString();
          navigate(`${location.pathname}${query ? `?${query}` : ""}`, {
            preventScrollReset: true,
          });
        }}
      />
    </div>
  );
};

export default PageSizeSelect;
