import * as AuthPB from "@octelium/apis/main/authv1/authv1";
import * as MetaPB from "@octelium/apis/main/metav1/metav1";

export type ResourceAuth = AuthPB.Authenticator;
export type Resource = ResourceAuth;

export const getResourceRef = (arg: Resource): MetaPB.ObjectReference => {
  return MetaPB.ObjectReference.create({
    apiVersion: arg.apiVersion,
    kind: arg.kind,
    uid: arg.metadata?.uid,
    name: arg.metadata?.name,
  });
};
