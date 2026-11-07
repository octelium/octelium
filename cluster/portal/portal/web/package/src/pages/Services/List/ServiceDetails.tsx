import { DetailList, DetailRow, DetailValue } from "@/ui";
import { getServicePrivateFQDN, getServicePublicURL } from "@/utils/octelium";
import { Service } from "@octelium/apis/main/userv1";
import { getServiceCommands } from "./commands";

const ServiceDetails = (props: { item: Service; domain: string }) => {
  const { item, domain } = props;
  const addresses = item.status?.addresses ?? [];
  const publicURL = item.spec?.isPublic
    ? getServicePublicURL(item, domain)
    : undefined;
  const commands = getServiceCommands(item, domain);
  const hasAddresses = addresses.length > 0;

  return (
    <div className="rounded-b-[11px] border-t border-slate-100 bg-canvas/60 p-3 sm:p-4">
      <DetailList>
        <DetailRow label="Private FQDN">
          <DetailValue
            value={getServicePrivateFQDN(item, domain)}
            copyLabel="Copy private FQDN"
          />
        </DetailRow>
        <DetailRow label="Full name">
          <DetailValue
            value={item.metadata?.name ?? ""}
            copyLabel="Copy full name"
          />
        </DetailRow>
        {publicURL && (
          <DetailRow label="Public URL" full={!hasAddresses}>
            <DetailValue
              value={publicURL}
              href={publicURL}
              copyLabel="Copy public URL"
            />
          </DetailRow>
        )}
        {hasAddresses && (
          <DetailRow label="Private addresses" full={!publicURL}>
            <div className="flex min-w-0 flex-wrap gap-x-5">
              {addresses.map((address) => (
                <DetailValue
                  key={address}
                  value={address}
                  copyLabel={`Copy ${address}`}
                />
              ))}
            </div>
          </DetailRow>
        )}
        {commands.length > 0 && (
          <DetailRow label="Command" full>
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
        Private FQDNs, addresses and commands work on a device running{" "}
        <code className="font-mono text-body text-slate-700">
          octelium connect
        </code>
        .
      </p>
    </div>
  );
};

export default ServiceDetails;
