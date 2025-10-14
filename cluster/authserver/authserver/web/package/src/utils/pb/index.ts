import * as MetaPB from "@/apis/metav1/metav1";
import * as AuthPB from "@/apis/authv1/authv1";

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
