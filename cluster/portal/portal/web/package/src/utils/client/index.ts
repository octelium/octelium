import * as AuthGRPC from "@octelium/apis/main/authv1";
import * as UserGRPC from "@octelium/apis/main/userv1";
import * as grpcWeb from "@protobuf-ts/grpcweb-transport";
import { getDomain, isDev } from "..";

export const getTransport = () => {
  if (transport) return transport;

  const domain = getDomain();
  const scheme = location.protocol === "https:" ? "https" : "http";

  let baseUrl = `${scheme}://octelium-api.${domain}`;

  if (isDev()) {
    baseUrl = `${scheme}://${window.location.host}`;
  }

  transport = new grpcWeb.GrpcWebFetchTransport({
    baseUrl,

    fetchInit: {
      credentials: "include",
    },
  });

  return transport;
};

let transport: grpcWeb.GrpcWebFetchTransport | undefined;

export const getClientUser = (): UserGRPC.MainServiceClient => {
  return new UserGRPC.MainServiceClient(getTransport());
};

export const getClientAuth = (): AuthGRPC.MainServiceClient => {
  return new AuthGRPC.MainServiceClient(getTransport());
};
