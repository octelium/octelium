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

package sessionc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/httputils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"google.golang.org/protobuf/types/known/structpb"
)

type CreateSessionOpts struct {
	Usr           *corev1.User
	Device        *corev1.Device
	OcteliumC     octeliumc.ClientInterface
	ClusterConfig *corev1.ClusterConfig

	SessType           corev1.Session_Status_Type
	IsBrowser          bool
	Scopes             []*corev1.Scope
	ParentScopes       []*corev1.Scope
	AuthenticationInfo *corev1.Session_Status_Authentication_Info

	Authorization *corev1.Session_Spec_Authorization
	CredentialRef *metav1.ObjectReference

	ExpiresAt time.Time

	UserAgent string
	XFF       string

	Ext map[string]*structpb.Struct

	CheckPerUserLimit        bool
	AuthenticatorAction      corev1.Session_Status_AuthenticatorAction
	RequiredAuthenticatorRef *metav1.ObjectReference
}

func NewSession(ctx context.Context,
	o *CreateSessionOpts,
) (*corev1.Session, error) {

	usr := o.Usr
	device := o.Device
	sessType := o.SessType

	var err error

	sessionName := fmt.Sprintf("%s-%s", usr.Metadata.Name, utilrand.GetRandomStringLowercase(6))

	clusterCfg := o.ClusterConfig
	if clusterCfg == nil {
		clusterCfg, err = o.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		if err != nil {
			return nil, serr.InternalWithErr(err)
		}
	}

	ccDuration := func() time.Duration {
		if clusterCfg.Spec.Session == nil {
			return 0
		}

		switch o.Usr.Spec.Type {
		case corev1.User_Spec_HUMAN:
			switch o.SessType {
			case corev1.Session_Status_CLIENTLESS:
				if clusterCfg.Spec.Session.Human != nil {
					return umetav1.ToDuration(clusterCfg.Spec.Session.Human.ClientlessDuration).ToGo()
				}
			case corev1.Session_Status_CLIENT:
				if clusterCfg.Spec.Session.Human != nil {
					return umetav1.ToDuration(clusterCfg.Spec.Session.Human.ClientDuration).ToGo()
				}
			}
		case corev1.User_Spec_WORKLOAD:
			switch o.SessType {
			case corev1.Session_Status_CLIENTLESS:
				if clusterCfg.Spec.Session.Workload != nil {
					return umetav1.ToDuration(clusterCfg.Spec.Session.Workload.ClientlessDuration).ToGo()
				}
			case corev1.Session_Status_CLIENT:
				if clusterCfg.Spec.Session.Workload != nil {
					return umetav1.ToDuration(clusterCfg.Spec.Session.Workload.ClientDuration).ToGo()
				}
			}
		default:
			return 0
		}
		return 0
	}()

	usrDuration := func() time.Duration {
		switch o.SessType {
		case corev1.Session_Status_CLIENTLESS:
			if o.Usr.Spec.Session != nil {
				return umetav1.ToDuration(usr.Spec.Session.ClientlessDuration).ToGo()
			}
		case corev1.Session_Status_CLIENT:
			if usr.Spec.Session != nil {
				return umetav1.ToDuration(usr.Spec.Session.ClientDuration).ToGo()
			}
		default:
			return 0
		}
		return 0
	}()

	defaultDuration := func() time.Duration {
		switch o.Usr.Spec.Type {
		case corev1.User_Spec_HUMAN:
			switch o.SessType {
			case corev1.Session_Status_CLIENTLESS:
				return time.Hour * 16
			case corev1.Session_Status_CLIENT:
				return time.Hour * 16
			}
		case corev1.User_Spec_WORKLOAD:
			switch sessType {
			case corev1.Session_Status_CLIENTLESS:
				return time.Hour * 2
			case corev1.Session_Status_CLIENT:
				return time.Hour * 24 * 30 * 3
			}
		default:
			return 0
		}
		return time.Hour
	}()

	sessDuration := usrDuration
	if sessDuration == 0 {
		sessDuration = ccDuration
		if sessDuration == 0 {
			sessDuration = defaultDuration
		}
	}

	var state corev1.Session_Spec_State
	if usr.Spec.Session != nil && usr.Spec.Session.DefaultState != corev1.Session_Spec_STATE_UNKNOWN {
		state = usr.Spec.Session.DefaultState
	} else {
		switch usr.Spec.Type {
		case corev1.User_Spec_HUMAN:
			if clusterCfg.Spec.Session != nil && clusterCfg.Spec.Session.Human != nil &&
				clusterCfg.Spec.Session.Human.DefaultState != corev1.Session_Spec_STATE_UNKNOWN {
				state = clusterCfg.Spec.Session.Human.DefaultState
			}
		case corev1.User_Spec_WORKLOAD:
			if clusterCfg.Spec.Session != nil && clusterCfg.Spec.Session.Workload != nil &&
				clusterCfg.Spec.Session.Workload.DefaultState != corev1.Session_Spec_STATE_UNKNOWN {
				state = clusterCfg.Spec.Session.Workload.DefaultState
			}
		}
	}

	if state == corev1.Session_Spec_STATE_UNKNOWN {
		state = corev1.Session_Spec_ACTIVE
	}

	var expiresAt time.Time

	if !o.ExpiresAt.IsZero() {
		if time.Now().Before(o.ExpiresAt) {
			expiresAt = o.ExpiresAt
		}
	}

	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(sessDuration)
	}

	sess := &corev1.Session{
		Metadata: &metav1.Metadata{
			Name: sessionName,
		},
		Spec: &corev1.Session_Spec{
			State:         state,
			ExpiresAt:     pbutils.Timestamp(expiresAt),
			Authorization: o.Authorization,
		},
		Status: &corev1.Session_Status{
			TotalAuthentications: 1,
			Type:                 sessType,
			IsBrowser:            o.IsBrowser,
			Scopes:               o.Scopes,
			UserRef:              umetav1.GetObjectReference(usr),
			DeviceRef:            umetav1.GetObjectReference(device),
			CredentialRef:        o.CredentialRef,
			Ext:                  o.Ext,
			Authentication: &corev1.Session_Status_Authentication{
				SetAt:   pbutils.Now(),
				TokenID: vutils.UUIDv4(),
				Info:    o.AuthenticationInfo,
			},
			AuthenticatorAction:      o.AuthenticatorAction,
			RequiredAuthenticatorRef: o.RequiredAuthenticatorRef,
		},
	}

	if o.Usr.Spec.Session != nil {
		if o.Usr.Spec.Session.AccessTokenDuration != nil &&
			umetav1.ToDuration(o.Usr.Spec.Session.AccessTokenDuration).ToGo() >= 30*time.Minute {
			sess.Status.Authentication.AccessTokenDuration = o.Usr.Spec.Session.AccessTokenDuration
		}

		if o.Usr.Spec.Session.RefreshTokenDuration != nil &&
			umetav1.ToDuration(o.Usr.Spec.Session.RefreshTokenDuration).ToGo() >= 30*time.Minute {
			sess.Status.Authentication.RefreshTokenDuration = o.Usr.Spec.Session.RefreshTokenDuration
		}
	}

	if sess.Status.Authentication.AccessTokenDuration == nil {
		switch usr.Spec.Type {
		case corev1.User_Spec_HUMAN:
			if clusterCfg.Spec.Session != nil && clusterCfg.Spec.Session.Human != nil &&
				clusterCfg.Spec.Session.Human.AccessTokenDuration != nil &&
				umetav1.ToDuration(clusterCfg.Spec.Session.Human.AccessTokenDuration).ToGo() >= 30*time.Minute {
				sess.Status.Authentication.AccessTokenDuration = clusterCfg.Spec.Session.Human.AccessTokenDuration
			}
		case corev1.User_Spec_WORKLOAD:
			if clusterCfg.Spec.Session != nil && clusterCfg.Spec.Session.Workload != nil &&
				clusterCfg.Spec.Session.Workload.AccessTokenDuration != nil &&
				umetav1.ToDuration(clusterCfg.Spec.Session.Workload.AccessTokenDuration).ToGo() >= 30*time.Minute {
				sess.Status.Authentication.AccessTokenDuration = clusterCfg.Spec.Session.Workload.AccessTokenDuration
			}
		}
	}

	if sess.Status.Authentication.RefreshTokenDuration == nil {
		switch usr.Spec.Type {
		case corev1.User_Spec_HUMAN:
			if clusterCfg.Spec.Session != nil && clusterCfg.Spec.Session.Human != nil &&
				clusterCfg.Spec.Session.Human.RefreshTokenDuration != nil &&
				umetav1.ToDuration(clusterCfg.Spec.Session.Human.RefreshTokenDuration).ToGo() >= 30*time.Minute {
				sess.Status.Authentication.RefreshTokenDuration = clusterCfg.Spec.Session.Human.RefreshTokenDuration
			}
		case corev1.User_Spec_WORKLOAD:
			if clusterCfg.Spec.Session != nil && clusterCfg.Spec.Session.Workload != nil &&
				clusterCfg.Spec.Session.Workload.RefreshTokenDuration != nil &&
				umetav1.ToDuration(clusterCfg.Spec.Session.Workload.RefreshTokenDuration).ToGo() >= 30*time.Minute {
				sess.Status.Authentication.RefreshTokenDuration = clusterCfg.Spec.Session.Workload.RefreshTokenDuration
			}
		}
	}

	if sess.Status.Authentication.AccessTokenDuration == nil {
		sess.Status.Authentication.AccessTokenDuration = &metav1.Duration{
			Type: &metav1.Duration_Hours{
				Hours: 4,
			},
		}
	}

	if sess.Status.Authentication.RefreshTokenDuration == nil {
		switch usr.Spec.Type {
		case corev1.User_Spec_HUMAN:
			sess.Status.Authentication.RefreshTokenDuration = &metav1.Duration{
				Type: &metav1.Duration_Hours{
					Hours: 18,
				},
			}
		case corev1.User_Spec_WORKLOAD:
			sess.Status.Authentication.RefreshTokenDuration = &metav1.Duration{
				Type: &metav1.Duration_Days{
					Days: 14,
				},
			}
		}
	}

	if umetav1.ToDuration(sess.Status.Authentication.RefreshTokenDuration).ToGo() <
		umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToGo() {
		sess.Status.Authentication.RefreshTokenDuration = sess.Status.Authentication.AccessTokenDuration
	}

	if sess.Status.Authentication.Info != nil {
		sess.Status.Authentication.Info.Downstream = &corev1.Session_Status_Authentication_Info_Downstream{}

		if o.XFF != "" && clusterCfg.Spec.Ingress != nil && clusterCfg.Spec.Ingress.UseForwardedForHeader {
			if ipAddr := httputils.GetDownstreamPublicIPFromXFFHeader(o.XFF); ipAddr != "" {
				sess.Status.Authentication.Info.Downstream.IpAddress = ipAddr
			}
		}

		if o.UserAgent != "" && len(o.UserAgent) < 220 {
			sess.Status.Authentication.Info.Downstream.UserAgent = o.UserAgent
			uaParts := strings.Split(o.UserAgent, " ")
			if len(uaParts) > 0 && strings.HasPrefix(uaParts[0], "octelium-cli/") {
				if args := strings.Split(uaParts[0], "/"); len(args) == 2 {
					sess.Status.Authentication.Info.Downstream.ClientVersion = args[1]
				}
			}
		}

	}

	sess.Status.InitialAuthentication = sess.Status.Authentication

	if o.AuthenticationInfo != nil &&
		o.AuthenticationInfo.GetIdentityProvider() != nil &&
		o.AuthenticationInfo.GetIdentityProvider().PicURL != "" {
		sess.Metadata.PicURL = o.AuthenticationInfo.GetIdentityProvider().PicURL
	}

	return sess, nil
}

func CreateSession(ctx context.Context,
	o *CreateSessionOpts,
) (*corev1.Session, error) {
	octeliumC := o.OcteliumC
	var err error
	if o.ClusterConfig == nil {
		o.ClusterConfig, err = o.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		if err != nil {
			return nil, serr.InternalWithErr(err)
		}
	}

	if o.CheckPerUserLimit {
		if err := checkMaxSessionsPerUser(ctx, octeliumC, o.Usr, o.ClusterConfig); err != nil {
			return nil, err
		}
	}

	sess, err := NewSession(ctx, o)
	if err != nil {
		return nil, err
	}

	sess, err = octeliumC.CoreC().CreateSession(ctx, sess)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return sess, nil
}

func checkMaxSessionsPerUser(ctx context.Context, octeliumC octeliumc.ClientInterface, usr *corev1.User, cc *corev1.ClusterConfig) error {
	var maxSess uint32
	if usr.Spec.Session != nil && usr.Spec.Session.MaxPerUser > 0 {
		maxSess = usr.Spec.Session.MaxPerUser
	} else {
		switch usr.Spec.Type {
		case corev1.User_Spec_HUMAN:
			if cc.Spec.Session != nil && cc.Spec.Session.Human != nil && cc.Spec.Session.Human.MaxPerUser > 0 {
				maxSess = cc.Spec.Session.Human.MaxPerUser
			} else {
				maxSess = 16
			}
		case corev1.User_Spec_WORKLOAD, corev1.User_Spec_TYPE_UNKNOWN:
			if cc.Spec.Session != nil && cc.Spec.Session.Workload != nil && cc.Spec.Session.Workload.MaxPerUser > 0 {
				maxSess = cc.Spec.Session.Workload.MaxPerUser
			} else {
				maxSess = 128
			}
		}
	}

	if maxSess > 10000 {
		maxSess = 10000
	}

	sessList, err := octeliumC.CoreC().ListSession(ctx, urscsrv.FilterByUser(usr))
	if err != nil {
		return grpcutils.InternalWithErr(err)
	}

	if uint32(len(sessList.Items)) >= maxSess {
		return grpcutils.Unauthorized("Session per User limit exceeded")
	}

	return nil
}

type SetCurrAuthenticationOpts struct {
	Session       *corev1.Session
	AuthInfo      *corev1.Session_Status_Authentication_Info
	UserAgent     string
	ClusterConfig *corev1.ClusterConfig
	XFF           string
}

func SetCurrAuthentication(o *SetCurrAuthenticationOpts) {
	sess := o.Session
	cc := o.ClusterConfig
	xff := o.XFF
	userAgent := o.UserAgent

	resp := &corev1.Session_Status_Authentication{
		TokenID:              vutils.UUIDv4(),
		SetAt:                pbutils.Now(),
		AccessTokenDuration:  sess.Status.InitialAuthentication.AccessTokenDuration,
		RefreshTokenDuration: sess.Status.InitialAuthentication.RefreshTokenDuration,

		Info: o.AuthInfo,
	}

	prependAuthenticationToLastArray(sess)

	sess.Status.Authentication = resp
	sess.Status.TotalAuthentications = sess.Status.TotalAuthentications + 1

	if resp.Info != nil {
		resp.Info.Downstream = &corev1.Session_Status_Authentication_Info_Downstream{}

		if xff != "" && cc.Spec.Ingress != nil && cc.Spec.Ingress.UseForwardedForHeader {
			if ipAddr := httputils.GetDownstreamPublicIPFromXFFHeader(xff); ipAddr != "" {
				sess.Status.Authentication.Info.Downstream.IpAddress = ipAddr
			}
		}
		if userAgent != "" && len(userAgent) < 220 {
			sess.Status.Authentication.Info.Downstream.UserAgent = userAgent
		}
	}

}

func prependAuthenticationToLastArray(sess *corev1.Session) {
	if sess.Status.Authentication == nil {
		return
	}

	maxLen := 100

	if len(sess.Status.LastAuthentications) >= maxLen {
		sess.Status.LastAuthentications = sess.Status.LastAuthentications[:maxLen-2]
	}

	sess.Status.LastAuthentications = append([]*corev1.Session_Status_Authentication{
		sess.Status.Authentication,
	}, sess.Status.LastAuthentications...)
}
