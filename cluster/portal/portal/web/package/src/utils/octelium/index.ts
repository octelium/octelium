import * as UserPB from "../../apis/userv1/userv1";

export const getServicePrivateFQDN = (
  arg: UserPB.Service,
  domain: string
): string => {
  return arg.status!.primaryHostname !== ""
    ? `${arg.status!.primaryHostname}.local.${domain}`
    : `local.${domain}`;
};

export const getServicePublicFQDN = (
  arg: UserPB.Service,
  domain: string
): string => {
  return arg.status!.primaryHostname !== ""
    ? `${arg.status!.primaryHostname}.${domain}`
    : `${domain}`;
};

export const getServicePublicURL = (
  arg: UserPB.Service,
  domain: string
): string => {
  return `https://${getServicePublicFQDN(arg, domain)}`;
};
