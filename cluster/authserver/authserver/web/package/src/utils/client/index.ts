import * as AuthGRPC from "@octelium/apis/main/authv1";
import * as grpcWeb from "@protobuf-ts/grpcweb-transport";
import { getDomain, isDev } from "..";

export const getTransport = () => {
  const domain = getDomain();
  const scheme = location.protocol === "https:" ? "https" : "http";

  if (!isDev() && !domain) {
    throw new Error("The Octelium domain is not configured.");
  }

  const baseUrl = isDev()
    ? window.location.origin
    : `${scheme}://octelium-api.${domain}`;

  return new grpcWeb.GrpcWebFetchTransport({
    baseUrl,

    fetchInit: {
      credentials: "include",
    },
  });
};

let client: AuthGRPC.MainServiceClient | undefined;

export const getClientAuth = (): AuthGRPC.MainServiceClient => {
  client ??= new AuthGRPC.MainServiceClient(getTransport());
  return client;
};
