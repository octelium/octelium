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

package tstuser

import (
	"context"
	"fmt"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/jwkctl"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/sessionc"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type User struct {
	Usr     *corev1.User
	Device  *corev1.Device
	Session *corev1.Session

	octeliumC octeliumc.ClientInterface

	admSrv corev1.MainServiceServer
	usrSrv userv1.MainServiceServer

	at *authv1.SessionToken
}

func WithUser(
	octeliumC octeliumc.ClientInterface,
	admSrv corev1.MainServiceServer,
	usrSrv userv1.MainServiceServer, usr *corev1.User, sessType corev1.Session_Status_Type) (*User, error) {
	var err error

	ret := &User{
		octeliumC: octeliumC,
		admSrv:    admSrv,
		usrSrv:    usrSrv,
		Usr:       usr,
	}

	ctx := context.Background()

	if usr.Spec.Type == corev1.User_Spec_HUMAN {
		ret.Device, err = octeliumC.CoreC().CreateDevice(ctx, &corev1.Device{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s-%s", usr.Metadata.Name, utilrand.GetRandomStringLowercase(8)),
			},
			Spec: &corev1.Device_Spec{
				State: corev1.Device_Spec_ACTIVE,
			},
			Status: &corev1.Device_Status{
				UserRef: umetav1.GetObjectReference(usr),

				OsType: corev1.Device_Status_LINUX,
			},
		})
		if err != nil {
			return nil, err
		}
	}

	jwkCtl, err := jwkctl.NewJWKController(ctx, octeliumC)
	if err != nil {
		return nil, err
	}

	sess, err := sessionc.CreateSession(ctx, &sessionc.CreateSessionOpts{
		OcteliumC: octeliumC,
		Usr:       ret.Usr,
		Device:    ret.Device,
		SessType:  sessType,
	})
	if err != nil {
		return nil, err
	}

	ret.Session = sess

	accessToken, err := jwkCtl.CreateAccessToken(sess)
	if err != nil {
		return nil, err
	}

	refreshToken, err := jwkCtl.CreateRefreshToken(sess)
	if err != nil {
		return nil, err
	}

	ret.at = &authv1.SessionToken{
		ExpiresIn:    umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToSeconds(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	return ret, nil
}

func NewUser(
	octeliumC octeliumc.ClientInterface,
	admSrv corev1.MainServiceServer,
	usrSrv userv1.MainServiceServer, groups []string) (*User, error) {

	ctx := context.Background()
	usrA, err := admSrv.CreateUser(ctx, GenUser(groups))
	if err != nil {
		return nil, err
	}

	usr, err := octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Uid: usrA.Metadata.Uid})
	if err != nil {
		return nil, err
	}

	return WithUser(octeliumC, admSrv, usrSrv, usr, corev1.Session_Status_CLIENT)
}

func NewUserWithSessType(
	octeliumC octeliumc.ClientInterface,
	admSrv corev1.MainServiceServer,
	usrSrv userv1.MainServiceServer, groups []string, sessType corev1.Session_Status_Type) (*User, error) {

	ctx := context.Background()
	usrA, err := admSrv.CreateUser(ctx, GenUser(groups))
	if err != nil {
		return nil, err
	}

	usr, err := octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Uid: usrA.Metadata.Uid})
	if err != nil {
		return nil, err
	}

	return WithUser(octeliumC, admSrv, usrSrv, usr, sessType)
}

func NewUserWorkloadClientless(octeliumC octeliumc.ClientInterface,
	admSrv corev1.MainServiceServer,
	usrSrv userv1.MainServiceServer, groups []string) (*User, error) {
	ctx := context.Background()
	usrSpec := GenUser(groups)
	usrSpec.Spec.Type = corev1.User_Spec_WORKLOAD

	usrA, err := admSrv.CreateUser(ctx, usrSpec)
	if err != nil {
		return nil, err
	}

	usr, err := octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Uid: usrA.Metadata.Uid})
	if err != nil {
		return nil, err
	}

	return WithUser(octeliumC, admSrv, usrSrv, usr, corev1.Session_Status_CLIENTLESS)
}

func NewUserWithType(
	octeliumC octeliumc.ClientInterface,
	admSrv corev1.MainServiceServer,
	usrSrv userv1.MainServiceServer, groups []string,
	usrType corev1.User_Spec_Type, sessType corev1.Session_Status_Type) (*User, error) {

	ctx := context.Background()

	var usrSpec *corev1.User
	if usrType == corev1.User_Spec_HUMAN {
		usrSpec = GenUserHuman(groups)
	} else {
		usrSpec = GenUser(groups)
	}
	usrA, err := admSrv.CreateUser(ctx, usrSpec)
	if err != nil {
		return nil, err
	}

	usr, err := octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Uid: usrA.Metadata.Uid})
	if err != nil {
		return nil, err
	}

	return WithUser(octeliumC, admSrv, usrSrv, usr, sessType)
}

func NewUserWeb(
	octeliumC octeliumc.ClientInterface,
	admSrv corev1.MainServiceServer,
	usrSrv userv1.MainServiceServer, groups []string) (*User, error) {

	ctx := context.Background()

	usrA, err := admSrv.CreateUser(ctx, GenUserHuman(groups))
	if err != nil {
		return nil, err
	}

	usr, err := octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Uid: usrA.Metadata.Uid})
	if err != nil {
		return nil, err
	}

	ret, err := WithUser(octeliumC, admSrv, usrSrv, usr, corev1.Session_Status_CLIENTLESS)
	if err != nil {
		return nil, err
	}

	ret.Session.Status.IsBrowser = true

	ret.Session, err = octeliumC.CoreC().UpdateSession(ctx, ret.Session)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (u *User) Connect() error {
	return u.ConnectWithReq(u.Ctx(), false, false)
}

func (u *User) ConnectQUIC0() error {
	return u.ConnectWithReq(u.Ctx(), false, true)
}

func (u *User) ConnectWithServeAll() error {
	return u.ConnectWithReq(u.Ctx(), true, false)
}

func (u *User) GetGroups(ctx context.Context) ([]*corev1.Group, error) {
	var ret []*corev1.Group
	for _, g := range u.Usr.Spec.Groups {
		grp, err := u.octeliumC.CoreC().GetGroup(ctx, &rmetav1.GetOptions{Name: g})
		if err != nil {
			return nil, err
		}
		ret = append(ret, grp)
	}
	return ret, nil
}

func (u *User) MustGetGroups(ctx context.Context) []*corev1.Group {
	ret, err := u.GetGroups(ctx)
	if err != nil {
		panic(err)
	}
	return ret
}

func (u *User) ConnectWithReq(ctx context.Context, isServeAll bool, isQUIC bool) error {

	sess, err := u.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: u.Session.Metadata.Uid})
	if err != nil {
		return err
	}

	cc, err := u.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return serr.InternalWithErr(err)
	}

	sess.Status.IsConnected = true
	pubKey := privateKey.PublicKey()
	sess.Status.Connection = &corev1.Session_Status_Connection{
		StartedAt: pbutils.Now(),
		Type: func() corev1.Session_Status_Connection_Type {
			if isQUIC {
				return corev1.Session_Status_Connection_QUICV0
			}
			return corev1.Session_Status_Connection_WIREGUARD
		}(),

		X25519PublicKey: pubKey[:],

		L3Mode: func() corev1.Session_Status_Connection_L3Mode {
			var ret corev1.Session_Status_Connection_L3Mode
			switch ucorev1.ToClusterConfig(cc).GetNetworkMode() {
			case corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK:
				ret = corev1.Session_Status_Connection_BOTH
			case corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY:
				ret = corev1.Session_Status_Connection_V4
			case corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY:
				ret = corev1.Session_Status_Connection_V6
			}

			return ret
		}(),

		ServiceOptions: func() *corev1.Session_Status_Connection_ServiceOptions {

			if !isServeAll {
				return nil
			}

			return &corev1.Session_Status_Connection_ServiceOptions{
				ServeAll: isServeAll,

				PortStart: func() int32 {

					return 23000
				}(),
			}
		}(),
	}

	if err := upstream.AddAddressToConnection(ctx, u.octeliumC, sess); err != nil {
		return serr.InternalWithErr(err)
	}

	if isServeAll {

		svcs, err := u.octeliumC.CoreC().ListService(ctx, &rmetav1.ListOptions{
			SpecLabels: map[string]string{
				fmt.Sprintf("host-user-%s", u.Usr.Metadata.Name): u.Usr.Metadata.Uid,
			},
		})
		if err != nil {
			return serr.InternalWithErr(err)
		}
		zap.S().Debugf("Found %d candidate Services to serve for user %s", len(svcs.Items), u.Usr.Metadata.Name)

		for _, svc := range svcs.Items {
			if upstream.ServeService(svc, sess) {
				if err := upstream.SetConnectionUpstreams(ctx, u.octeliumC, sess, svc); err != nil {
					return serr.InternalWithErr(err)
				}
			}
		}

	}

	u.Session, err = u.octeliumC.CoreC().UpdateSession(context.Background(), sess)
	if err != nil {
		return err
	}

	return nil
}

func (u *User) Disconnect() error {
	_, err := u.usrSrv.Disconnect(u.Ctx(), &userv1.DisconnectRequest{})
	if err != nil {
		return err
	}
	u.Session, err = u.octeliumC.CoreC().GetSession(context.Background(), &rmetav1.GetOptions{Uid: u.Session.Metadata.Uid})
	if err != nil {
		return err
	}

	return nil
}

func (u *User) Ctx() context.Context {
	ret, _ := u.getUserCtx(nil)
	return ret
}

func (u *User) NewSessionCtx() context.Context {
	sess, _ := u.NewSession()
	ret, _ := u.getUserCtx(sess)
	return ret
}

func (u *User) Resync() {
	u.Usr, _ = u.octeliumC.CoreC().GetUser(context.Background(), &rmetav1.GetOptions{Uid: u.Usr.Metadata.Uid})
	u.Session, _ = u.octeliumC.CoreC().GetSession(context.Background(), &rmetav1.GetOptions{Uid: u.Session.Metadata.Uid})
	if u.Session.Status.DeviceRef != nil {
		u.Device, _ = u.octeliumC.CoreC().GetDevice(context.Background(),
			&rmetav1.GetOptions{Uid: u.Session.Status.DeviceRef.Uid})
	}
}

func (u *User) GetAccessToken() *authv1.SessionToken {
	return u.at
}

func (u *User) SetSessionToken(arg *authv1.SessionToken) {
	u.at = arg
}

func (u *User) GetUserCtx(sess *corev1.Session) (context.Context, error) {
	return u.getUserCtx(sess)
}

func (u *User) getUserCtx(sess *corev1.Session) (context.Context, error) {

	groupsK8s, err := GetK8sGroupsFromUser(context.Background(), u.octeliumC, u.Usr)
	if err != nil {
		return nil, err
	}

	userCtx := &userctx.UserCtx{
		User:   u.Usr,
		Groups: groupsK8s,
		Device: u.Device,
	}

	if sess != nil {
		userCtx.Session = sess
	} else {
		userCtx.Session = u.Session
	}

	newCtx := context.WithValue(context.Background(), "octelium-user-ctx", userCtx)

	return newCtx, nil
}

func (u *User) NewSession() (*corev1.Session, error) {
	ctx := context.Background()

	return sessionc.CreateSession(ctx, &sessionc.CreateSessionOpts{
		OcteliumC: u.octeliumC,
		Usr:       u.Usr,
		Device:    u.Device,
		SessType:  corev1.Session_Status_CLIENT,
	})
}

func (u *User) NewSessionWithType(typ corev1.Session_Status_Type) (*corev1.Session, error) {
	ctx := context.Background()

	return sessionc.CreateSession(ctx, &sessionc.CreateSessionOpts{
		OcteliumC: u.octeliumC,
		Usr:       u.Usr,
		Device:    u.Device,
		SessType:  typ,
	})
}

func GenUser(groups []string) *corev1.User {
	ret := &corev1.User{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("usr-%s", utilrand.GetRandomStringLowercase(6)),
		},
		Spec: &corev1.User_Spec{
			Type:   corev1.User_Spec_WORKLOAD,
			Groups: groups,
		},
	}

	return ret
}

func GenUserHuman(groups []string) *corev1.User {
	ret := &corev1.User{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("usr-%s", utilrand.GetRandomStringLowercase(6)),
		},
		Spec: &corev1.User_Spec{
			Type:   corev1.User_Spec_HUMAN,
			Groups: groups,
		},
	}

	return ret
}

func GetK8sGroupsFromUser(ctx context.Context, octeliumC octeliumc.ClientInterface, usr *corev1.User) ([]*corev1.Group, error) {
	ret := []*corev1.Group{}

	for _, g := range usr.Spec.Groups {
		grp, err := octeliumC.CoreC().GetGroup(ctx, &rmetav1.GetOptions{Name: g})
		if err != nil {
			return nil, err
		}
		ret = append(ret, grp)
	}

	return ret, nil
}
