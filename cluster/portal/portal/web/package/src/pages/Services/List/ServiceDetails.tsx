import { Badge, DetailList, DetailRow, DetailValue } from "@/ui";
import { getServicePrivateFQDN, getServicePublicURL } from "@/utils/octelium";
import { Service } from "@octelium/apis/main/userv1";
import ConnectCommand from "./ConnectCommand";

const getAddressFamily = (address: string) =>
  address.includes(":") ? "IPv6" : "IPv4";

const ServiceDetails = (props: { item: Service; domain: string }) => {
  const { item, domain } = props;
  const addresses = item.status?.addresses ?? [];
  const publicURL = item.spec?.isPublic
    ? getServicePublicURL(item, domain)
    : undefined;

  return (
    <div className="@container rounded-b-[11px] border-t border-slate-100 bg-canvas/60 p-3 sm:p-4">
      <div className="flex flex-col gap-3 @4xl:flex-row">
        <DetailList className="@4xl:flex-1">
          {publicURL && (
            <DetailRow label="Public URL">
              <DetailValue
                value={publicURL}
                href={publicURL}
                copyLabel="Copy public URL"
              />
            </DetailRow>
          )}
          <DetailRow label="Private hostname">
            <DetailValue
              value={getServicePrivateFQDN(item, domain)}
              copyLabel="Copy private hostname"
            />
          </DetailRow>
          {addresses.length > 0 && (
            <DetailRow label="Private addresses">
              {addresses.map((address) => (
                <DetailValue
                  key={address}
                  value={address}
                  copyLabel={`Copy ${address}`}
                  addon={<Badge>{getAddressFamily(address)}</Badge>}
                />
              ))}
            </DetailRow>
          )}
          <DetailRow label="Resource name">
            <DetailValue
              value={item.metadata?.name ?? ""}
              copyLabel="Copy resource name"
            />
          </DetailRow>
        </DetailList>
        <ConnectCommand
          service={item}
          domain={domain}
          className="min-w-0 @4xl:flex-1"
        />
      </div>
    </div>
  );
};

export default ServiceDetails;
