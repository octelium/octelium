import { useAppSelector } from "@/utils/hooks";
import { Navigate } from "react-router-dom";

export default () => {
  return <Navigate to={`/services`} />;
};
