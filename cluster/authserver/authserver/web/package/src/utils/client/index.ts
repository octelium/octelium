import * as grpcWeb from "@protobuf-ts/grpcweb-transport";
import * as UserGRPC from "../../apis/userv1/userv1.client";
import * as AuthGRPC from "../../apis/authv1/authv1.client";
import { getDomain, isDev } from "..";

export const getTransport = () => {
  const domain = getDomain();
  const scheme = location.protocol === "https:" ? "https" : "http";

  let baseUrl = `${scheme}://octelium-api.${domain}`;

  if (isDev()) {
    baseUrl = `https://${window.location.host}`;
  }

  return new grpcWeb.GrpcWebFetchTransport({
    baseUrl,

    fetchInit: {
      credentials: "include",
    },
  });
};

export const getClientUser = (): UserGRPC.MainServiceClient => {
  return new UserGRPC.MainServiceClient(getTransport());
};


export const getClientAuth = (): AuthGRPC.MainServiceClient => {
  return new AuthGRPC.MainServiceClient(getTransport());
};
