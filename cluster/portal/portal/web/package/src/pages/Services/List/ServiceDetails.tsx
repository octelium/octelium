import { Badge, DetailList, DetailRow, DetailValue } from "@/ui";
import { getServicePrivateFQDN, getServicePublicURL } from "@/utils/octelium";
import { Service } from "@octelium/apis/main/userv1";
import { getServiceCommands } from "./commands";

const getAddressFamily = (address: string) =>
  address.includes(":") ? "IPv6" : "IPv4";

const ServiceDetails = (props: { item: Service; domain: string }) => {
  const { item, domain } = props;
  const addresses = item.status?.addresses ?? [];
  const publicURL = item.spec?.isPublic
    ? getServicePublicURL(item, domain)
    : undefined;
  const commands = getServiceCommands(item, domain);

  return (
    <div className="rounded-b-[11px] border-t border-slate-100 bg-canvas/60 p-3 sm:p-4">
      <DetailList>
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
        {commands.length > 0 && (
          <DetailRow label="Command">
            {commands.map((command, index) => (
              <DetailValue
                key={command}
                value={command}
                copyLabel={
                  commands.length > 1
                    ? `Copy command ${index + 1}`
                    : "Copy command"
                }
              />
            ))}
          </DetailRow>
        )}
      </DetailList>
      <p className="mt-2.5 px-1 text-xs font-normal leading-5 text-slate-500">
        Private hostnames, addresses and commands work on a device running{" "}
        <code className="font-mono text-body text-slate-700">
          octelium connect
        </code>
        .
      </p>
    </div>
  );
};

export default ServiceDetails;
