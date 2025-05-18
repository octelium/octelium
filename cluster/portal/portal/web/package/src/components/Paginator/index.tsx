import { ListResponseMeta } from "@/apis/metav1/metav1";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import * as React from "react";
import { twMerge } from "tailwind-merge";

import { ActionIcon, Pagination, TextInput } from "@mantine/core";

const Paginator = (props: { meta: ListResponseMeta; path: string }) => {
  const { meta } = props;
  const navigate = useNavigate();
  const totalPages = Math.ceil(meta.totalCount / meta.itemsPerPage);
  const loc = useLocation();
  let [searchParams, _] = useSearchParams();

  if (meta.page == 0 && meta.totalCount <= meta.itemsPerPage) {
    return <React.Fragment></React.Fragment>;
  }

  return (
    <div className="flex items-center w-full justify-center my-4">
       <Pagination
          total={totalPages}
          radius={"xl"}
          value={meta.page + 1}
          withEdges
          color="#111"
          onChange={(v) => {
            let page = v;
            searchParams.set("common.page", `${page}`);
            navigate(`${loc.pathname}?${searchParams.toString()}`);
            /*
            const i = v;
            if (props.onPageChange) {
              props.onPageChange(i);
            } else if (props.path) {
              navigate(
                `${props.path}${props.path.includes("?") ? "&" : "?"}page=${
                  i - 1
                }`
              );
            }
            */
          }}
        />
      {/*
      <Pagination
        variant="outlined"
        count={totalPages}
        page={meta.page}
        onChange={(i, x) => {
          navigate(
            `${props.path}${props.path.includes("?") ? "&" : "?"}page=${x}`
          );
        }}
      />
      */}
    </div>
  );

  return (
    <div className="w-full flex items-center justify-center">
      <div className="w-full flex items-center justify-center flex-wrap">
        {[...Array(totalPages)].map((e, i) => {
          return (
            <button
              key={i}
              className={twMerge(
                `flex items-center text-center justify-center`,
                "mx-2 my-2  text-white font-bold py-1 px-2 rounded-md shadow-2xl",
                meta.page === i
                  ? `bg-slate-900 border-[1px] border-slate-900`
                  : `bg-transparent border-[1px] border-slate-900 text-slate-700`
              )}
              onClick={() => {
                navigate(
                  `${props.path}${
                    props.path.includes("?") ? "&" : "?"
                  }page=${i}`
                );
              }}
            >
              {i + 1}
            </button>
          );
        })}
      </div>
    </div>
  );
};
export default Paginator;
