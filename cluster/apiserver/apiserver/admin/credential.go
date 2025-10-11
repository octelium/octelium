/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/common"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/jwkctl"
	"github.com/octelium/octelium/cluster/common/sessionc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
)

func (s *Server) CreateCredential(ctx context.Context, req *corev1.Credential) (*corev1.Credential, error) {

	if err := s.validateCredential(ctx, req); err != nil {
		return nil, err
	}

	_, err := s.octeliumC.CoreC().GetCredential(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
	if err == nil {
		return nil, grpcutils.AlreadyExists("The Credential %s already exists", req.Metadata.Name)
	}

	if !grpcerr.IsNotFound(err) {
		return nil, serr.K8sInternal(err)
	}

	item := &corev1.Credential{
		Metadata: common.MetadataFrom(req.Metadata),
		Spec:     req.Spec,
		Status: &corev1.Credential_Status{
			UserRef: req.Status.UserRef,
			Id:      fmt.Sprintf("%s-%s", utilrand.GetRandomStringCanonical(4), utilrand.GetRandomStringLowercase(4)),
		},
	}

	item, err = s.octeliumC.CoreC().CreateCredential(ctx, item)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return item, nil
}

func (s *Server) DeleteCredential(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, nil); err != nil {
		return nil, err
	}

	tkn, err := s.octeliumC.CoreC().GetCredential(ctx, &rmetav1.GetOptions{Name: req.Name, Uid: req.Uid})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(tkn); err != nil {
		return nil, err
	}

	_, err = s.octeliumC.CoreC().DeleteCredential(ctx, &rmetav1.DeleteOptions{Uid: tkn.Metadata.Uid})
	if err != nil {
		return nil, err
	}

	return &metav1.OperationResult{}, nil
}

func (s *Server) ListCredential(ctx context.Context, req *corev1.ListCredentialOptions) (*corev1.CredentialList, error) {

	var listOpts []*rmetav1.ListOptions_Filter

	if req.UserRef != nil {
		if err := apivalidation.CheckObjectRef(req.UserRef, &apivalidation.CheckGetOptionsOpts{}); err != nil {
			return nil, err
		}
		usr, err := s.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
			Uid:  req.UserRef.Uid,
			Name: req.UserRef.Name,
		})
		if err != nil {
			return nil, err
		}
		listOpts = append(listOpts, urscsrv.FilterStatusUserUID(usr.Metadata.Uid))
	}

	itemList, err := s.octeliumC.CoreC().ListCredential(ctx, urscsrv.GetPublicListOptions(req, listOpts...))
	if err != nil {
		return nil, err
	}

	return itemList, nil
}

func (s *Server) GetCredential(ctx context.Context, req *metav1.GetOptions) (*corev1.Credential, error) {
	if err := apivalidation.CheckGetOptions(req, nil); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetCredential(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	return ret, nil
}

func (s *Server) GenerateCredentialToken(ctx context.Context, req *corev1.GenerateCredentialTokenRequest) (*corev1.CredentialToken, error) {
	if err := apivalidation.CheckObjectRef(req.CredentialRef, nil); err != nil {
		return nil, err
	}

	cred, err := s.octeliumC.CoreC().GetCredential(ctx, &rmetav1.GetOptions{
		Uid:  req.CredentialRef.Uid,
		Name: req.CredentialRef.Name,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	cred.Status.TokenID = vutils.UUIDv4()
	cred.Status.LastRotationAt = pbutils.Now()
	cred.Status.TotalRotations = cred.Status.TotalRotations + 1

	cred, err = s.octeliumC.CoreC().UpdateCredential(ctx, cred)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	jwkCtl, err := jwkctl.NewJWKController(ctx, s.octeliumC)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	tknStr, err := jwkCtl.CreateCredential(cred)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	switch cred.Spec.Type {
	case corev1.Credential_Spec_AUTH_TOKEN:

		return &corev1.CredentialToken{
			Type: &corev1.CredentialToken_AuthenticationToken_{
				AuthenticationToken: &corev1.CredentialToken_AuthenticationToken{
					AuthenticationToken: tknStr,
				},
			},
		}, nil
	case corev1.Credential_Spec_OAUTH2:

		return &corev1.CredentialToken{
			Type: &corev1.CredentialToken_Oauth2Credentials{
				Oauth2Credentials: &corev1.CredentialToken_OAuth2Credentials{
					ClientID:     cred.Status.Id,
					ClientSecret: tknStr,
				},
			},
		}, nil
	case corev1.Credential_Spec_ACCESS_TOKEN:
		sessList, err := s.octeliumC.CoreC().ListSession(ctx, &rmetav1.ListOptions{
			Filters: []*rmetav1.ListOptions_Filter{
				urscsrv.FilterFieldEQValStr("status.credentialRef.uid", cred.Metadata.Uid),
			},
		})
		if err != nil {
			return nil, serr.InternalWithErr(err)
		}
		usr, err := s.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
			Uid: cred.Status.UserRef.Uid,
		})
		if err != nil {
			return nil, grpcutils.K8sNotFoundOrInternalWithErr(err)
		}

		if len(sessList.Items) > 0 {
			sess := sessList.Items[0]

			sessionc.SetCurrAuthentication(&sessionc.SetCurrAuthenticationOpts{
				Session:       sess,
				ClusterConfig: cc,
				AuthInfo: &corev1.Session_Status_Authentication_Info{
					Type: corev1.Session_Status_Authentication_Info_CREDENTIAL,
					Details: &corev1.Session_Status_Authentication_Info_Credential_{
						Credential: &corev1.Session_Status_Authentication_Info_Credential{
							CredentialRef: umetav1.GetObjectReference(cred),
							Type:          cred.Spec.Type,
							TokenID:       cred.Status.TokenID,
						},
					},
				},
			})

			_, err = s.octeliumC.CoreC().UpdateSession(ctx, sess)
			if err != nil {
				return nil, serr.InternalWithErr(err)
			}

			accessTkn, err := jwkCtl.CreateAccessToken(sess)
			if err != nil {
				return nil, grpcutils.InternalWithErr(err)
			}

			return &corev1.CredentialToken{
				Type: &corev1.CredentialToken_AccessToken_{
					AccessToken: &corev1.CredentialToken_AccessToken{
						AccessToken: accessTkn,
					},
				},
			}, nil
		} else {
			sess, err := sessionc.CreateSession(ctx, &sessionc.CreateSessionOpts{
				OcteliumC:         s.octeliumC,
				ClusterConfig:     cc,
				CheckPerUserLimit: true,
				Usr:               usr,
				SessType: func() corev1.Session_Status_Type {
					if cred.Spec.SessionType != corev1.Session_Status_TYPE_UNKNOWN {
						return cred.Spec.SessionType
					}
					return corev1.Session_Status_CLIENTLESS
				}(),

				Authorization: func() *corev1.Session_Spec_Authorization {
					if cred.Spec.Authorization == nil {
						return nil
					}
					return &corev1.Session_Spec_Authorization{
						Policies:       cred.Spec.Authorization.Policies,
						InlinePolicies: cred.Spec.Authorization.InlinePolicies,
					}
				}(),
				AuthenticationInfo: &corev1.Session_Status_Authentication_Info{
					Type: corev1.Session_Status_Authentication_Info_CREDENTIAL,
					Details: &corev1.Session_Status_Authentication_Info_Credential_{
						Credential: &corev1.Session_Status_Authentication_Info_Credential{
							CredentialRef: umetav1.GetObjectReference(cred),
							Type:          cred.Spec.Type,
							TokenID:       cred.Status.TokenID,
						},
					},
				},
				CredentialRef: umetav1.GetObjectReference(cred),
			})
			if err != nil {
				return nil, grpcutils.InternalWithErr(err)
			}

			accessTkn, err := jwkCtl.CreateAccessToken(sess)
			if err != nil {
				return nil, grpcutils.InternalWithErr(err)
			}

			return &corev1.CredentialToken{
				Type: &corev1.CredentialToken_AccessToken_{
					AccessToken: &corev1.CredentialToken_AccessToken{
						AccessToken: accessTkn,
					},
				},
			}, nil
		}

	default:
		return nil, serr.Internal("Invalid Credential type")
	}
}

func (s *Server) validateCredential(ctx context.Context, req *corev1.Credential) error {
	if err := apivalidation.ValidateCommon(req, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{
			RequireName: true,
		},
	}); err != nil {
		return err
	}

	if req.Spec == nil {
		return grpcutils.InvalidArg("Nil spec")
	}

	switch req.Spec.Type {
	case corev1.Credential_Spec_TYPE_UNKNOWN:
		return grpcutils.InvalidArg("Credential type must be set")
	}

	req.Status = &corev1.Credential_Status{}

	if req.Spec.ExpiresAt.IsValid() {
		if time.Now().After(req.Spec.ExpiresAt.AsTime()) {
			return grpcutils.InvalidArg("Credential expiry time exceeded")
		}
	}

	if req.Spec.User == "" {
		return serr.InvalidArg("User must be specified")
	}

	usr, err := s.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
		Name: req.Spec.User,
	})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return serr.InvalidArg("The User of this Credential does not exist")
		}
		return serr.InternalWithErr(err)
	}

	if req.Spec.Type == corev1.Credential_Spec_OAUTH2 && usr.Spec.Type != corev1.User_Spec_WORKLOAD {
		return grpcutils.InvalidArg("OAUTH2 Credentials can only be used with WORKLOAD Users")
	}

	if req.Spec.Type == corev1.Credential_Spec_ACCESS_TOKEN && usr.Spec.Type != corev1.User_Spec_WORKLOAD {
		return grpcutils.InvalidArg("ACCESS_TOKEN Credentials can only be used with WORKLOAD Users")
	}

	req.Status.UserRef = umetav1.GetObjectReference(usr)

	if err := s.validatePolicyOwner(ctx, req.Spec.Authorization); err != nil {
		return err
	}

	return nil
}

func (s *Server) UpdateCredential(ctx context.Context, req *corev1.Credential) (*corev1.Credential, error) {

	if err := s.validateCredential(ctx, req); err != nil {
		return nil, err
	}

	item, err := s.octeliumC.CoreC().GetCredential(ctx, &rmetav1.GetOptions{
		Name: req.Metadata.Name,
		Uid:  req.Metadata.Uid,
	})
	if err != nil {
		return nil, err
	}

	if err := apivalidation.CheckIsSystem(item); err != nil {
		return nil, err
	}

	common.MetadataUpdate(item.Metadata, req.Metadata)
	item.Spec = req.Spec
	item.Status.UserRef = req.Status.UserRef

	item, err = s.octeliumC.CoreC().UpdateCredential(ctx, item)
	if err != nil {
		return nil, err
	}

	return item, nil
}
