import { TypedUseSelectorHook, useDispatch, useSelector } from "react-redux";
import { useCallback } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import type { RootState, AppDispatch } from "../../store";

export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;

export const useFilterParams = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const setParams = useCallback(
    (updates: Record<string, string | null>) => {
      const nextParams = new URLSearchParams(searchParams);
      nextParams.delete("common.page");

      for (const [key, value] of Object.entries(updates)) {
        if (value) {
          nextParams.set(key, value);
        } else {
          nextParams.delete(key);
        }
      }

      const query = nextParams.toString();
      navigate(`${location.pathname}${query ? `?${query}` : ""}`);
    },
    [location.pathname, navigate, searchParams],
  );

  return { searchParams, setParams };
};
