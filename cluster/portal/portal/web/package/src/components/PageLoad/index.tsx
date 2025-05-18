import { LoadingStatus } from "@/utils/types";
import React from "react";
import Loading from "../Loading";

const PageLoad = (props: {
  loadingStatus: LoadingStatus;
  children?: React.ReactNode;
}) => {
  return (
    <div>
      {props.loadingStatus == LoadingStatus.LOADING && <Loading />}
      {props.loadingStatus == LoadingStatus.SUCCESS && (
        <div>{props.children}</div>
      )}
    </div>
  );
};

export default PageLoad;
