import { getServiceHostname, getServicePrivateFQDN } from "@/utils/octelium";
import { Service, Service_Spec_Type } from "@octelium/apis/main/userv1";
import { match } from "ts-pattern";

const portFlag = (flag: string, port: number | undefined, dflt: number) =>
  port && port !== dflt ? ` ${flag} ${port}` : "";

const hostPort = (host: string, port?: number) =>
  port ? `${host}:${port}` : host;

const getHTTPURL = (host: string, port: number | undefined, tls: boolean) =>
  `${tls ? "https" : "http"}://${port === (tls ? 443 : 80) ? host : hostPort(host, port)}`;

export const getServiceCommands = (svc: Service, domain: string): string[] => {
  const fqdn = getServicePrivateFQDN(svc, domain);
  const port = svc.spec?.port || undefined;
  const tls = !!svc.spec?.isTLS;
  const host =
    tls || !svc.status?.primaryHostname ? fqdn : getServiceHostname(svc);
  const url = getHTTPURL(host, port, tls);

  return match(svc.spec?.type)
    .with(Service_Spec_Type.HTTP, () => [`curl -i ${url}/`])
    .with(Service_Spec_Type.WEB, () => [`curl -sI ${url}/`])
    .with(Service_Spec_Type.LLM, () => [`curl -s ${url}/v1/models`])
    .with(Service_Spec_Type.POSTGRES, () => [
      `psql -h ${host}${portFlag("-p", port, 5432)}`,
    ])
    .with(Service_Spec_Type.MYSQL, () => [
      `mysql -h ${host}${portFlag("-P", port, 3306)}`,
    ])
    .with(Service_Spec_Type.SSH, () => [
      `ssh ${host}${portFlag("-p", port, 22)}`,
    ])
    .with(Service_Spec_Type.KUBERNETES, () => [
      `octelium config ${svc.metadata?.name}`,
      `KUBECONFIG=~/.kube/${svc.status?.primaryHostname}.${domain} kubectl get pods`,
    ])
    .with(Service_Spec_Type.GRPC, () => [
      `grpcurl${tls ? "" : " -plaintext"} ${hostPort(host, port ?? (tls ? 443 : 80))} list`,
    ])
    .with(Service_Spec_Type.DNS, () => [
      `dig @${host}${portFlag("-p", port, 53)} example.com`,
    ])
    .with(Service_Spec_Type.SOCKS5, () => [
      `curl --socks5-hostname ${hostPort(host, port)} -I https://example.com`,
    ])
    .otherwise(() => []);
};
