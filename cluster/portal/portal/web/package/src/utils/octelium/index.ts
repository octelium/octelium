import * as UserPB from "@octelium/apis/main/userv1";

export const CORDIUM_SERVICE_NAME = "default.cordium";

export const getServicePrivateFQDN = (
  arg: UserPB.Service,
  domain: string,
): string => {
  return arg.status!.primaryHostname !== ""
    ? `${arg.status!.primaryHostname}.local.${domain}`
    : `local.${domain}`;
};

export const getServicePublicFQDN = (
  arg: UserPB.Service,
  domain: string,
): string => {
  return arg.status!.primaryHostname !== ""
    ? `${arg.status!.primaryHostname}.${domain}`
    : `${domain}`;
};

export const getServicePublicURL = (
  arg: UserPB.Service,
  domain: string,
): string => {
  return `https://${getServicePublicFQDN(arg, domain)}`;
};

export const getServiceHostname = (arg: UserPB.Service): string =>
  arg.status?.primaryHostname || arg.metadata?.name || "";

export const hasCordiumConnect = (arg: UserPB.Service): boolean => {
  switch (arg.spec?.type) {
    case undefined:
    case UserPB.Service_Spec_Type.UNSET:
    case UserPB.Service_Spec_Type.RDP:
    case UserPB.Service_Spec_Type.RDP_WEB:
      return false;
    default:
      return true;
  }
};

export const getCordiumConnectURL = (
  cordium: UserPB.Service,
  arg: UserPB.Service,
  domain: string,
): string => {
  return `${getServicePublicURL(cordium, domain)}/services/${encodeURIComponent(arg.metadata!.name)}/connect`;
};
