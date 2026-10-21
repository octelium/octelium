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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/geoipctl"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/sessionc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewSessionDefaults(t *testing.T) {
	ctx := context.Background()
	for _, userType := range []corev1.User_Spec_Type{corev1.User_Spec_HUMAN, corev1.User_Spec_WORKLOAD} {
		for _, sessionType := range []corev1.Session_Status_Type{corev1.Session_Status_CLIENT, corev1.Session_Status_CLIENTLESS} {
			t.Run(userType.String()+"/"+sessionType.String(), func(t *testing.T) {
				usr := &corev1.User{Metadata: &metav1.Metadata{Name: "user", Uid: vutils.UUIDv4()}, Spec: &corev1.User_Spec{Type: userType}}
				cc := &corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{}}
				opts := &sessionc.CreateSessionOpts{Usr: usr, ClusterConfig: cc, SessType: sessionType}
				startedAt := time.Now()
				sess, err := sessionc.NewSession(ctx, opts)
				assert.Nil(t, err)
				wantDuration, wantRefresh := 21*time.Hour, 21*time.Hour
				if userType == corev1.User_Spec_WORKLOAD {
					wantDuration, wantRefresh = 90*24*time.Hour, 14*24*time.Hour
				}
				assert.WithinDuration(t, startedAt.Add(wantDuration), sess.Spec.ExpiresAt.AsTime(), time.Second)
				assert.Equal(t, corev1.Session_Spec_ACTIVE, sess.Spec.State)
				assert.Equal(t, sessionType, sess.Status.Type)
				assert.Equal(t, usr.Metadata.Uid, sess.Status.UserRef.Uid)
				assert.Nil(t, sess.Status.DeviceRef)
				assert.Equal(t, 4*time.Hour, umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToGo())
				assert.Equal(t, wantRefresh, umetav1.ToDuration(sess.Status.Authentication.RefreshTokenDuration).ToGo())
				assert.NotEmpty(t, sess.Status.Authentication.TokenID)
				assert.Same(t, sess.Status.Authentication, sess.Status.InitialAuthentication)

				cc.Spec.Session = &corev1.ClusterConfig_Spec_Session{
					Human: &corev1.ClusterConfig_Spec_Session_Human{
						ClientDuration:       &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 8}},
						ClientlessDuration:   &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 12}},
						AccessTokenDuration:  &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 1}},
						RefreshTokenDuration: &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 2}}, DefaultState: corev1.Session_Spec_PENDING,
					},
					Workload: &corev1.ClusterConfig_Spec_Session_Workload{
						ClientDuration:       &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 8}},
						ClientlessDuration:   &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 12}},
						AccessTokenDuration:  &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 1}},
						RefreshTokenDuration: &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 2}}, DefaultState: corev1.Session_Spec_PENDING,
					},
				}
				sess, err = sessionc.NewSession(ctx, opts)
				assert.Nil(t, err)
				wantDuration = 8 * time.Hour
				if sessionType == corev1.Session_Status_CLIENTLESS {
					wantDuration = 12 * time.Hour
				}
				assert.WithinDuration(t, startedAt.Add(wantDuration), sess.Spec.ExpiresAt.AsTime(), time.Second)
				assert.Equal(t, corev1.Session_Spec_PENDING, sess.Spec.State)
				assert.Equal(t, time.Hour, umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToGo())
				assert.Equal(t, 2*time.Hour, umetav1.ToDuration(sess.Status.Authentication.RefreshTokenDuration).ToGo())

				usr.Spec.Session = &corev1.User_Spec_Session{
					ClientDuration:       &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 3}},
					ClientlessDuration:   &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 3}},
					AccessTokenDuration:  &metav1.Duration{Type: &metav1.Duration_Minutes{Minutes: 45}},
					RefreshTokenDuration: &metav1.Duration{Type: &metav1.Duration_Minutes{Minutes: 30}}, DefaultState: corev1.Session_Spec_REJECTED,
				}
				sess, err = sessionc.NewSession(ctx, opts)
				assert.Nil(t, err)
				assert.WithinDuration(t, startedAt.Add(3*time.Hour), sess.Spec.ExpiresAt.AsTime(), time.Second)
				assert.Equal(t, corev1.Session_Spec_REJECTED, sess.Spec.State)
				assert.Equal(t, 45*time.Minute, umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToGo())
				assert.Equal(t, 45*time.Minute, umetav1.ToDuration(sess.Status.Authentication.RefreshTokenDuration).ToGo())
				usr.Spec.Session.AccessTokenDuration = &metav1.Duration{Type: &metav1.Duration_Minutes{Minutes: 29}}
				usr.Spec.Session.RefreshTokenDuration = &metav1.Duration{Type: &metav1.Duration_Minutes{Minutes: 29}}
				sess, err = sessionc.NewSession(ctx, opts)
				assert.Nil(t, err)
				assert.Equal(t, time.Hour, umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToGo())
				assert.Equal(t, 2*time.Hour, umetav1.ToDuration(sess.Status.Authentication.RefreshTokenDuration).ToGo())
			})
		}
	}
}

func TestSessionAuthenticationHistory(t *testing.T) {
	ctx := context.Background()
	usr := &corev1.User{Metadata: &metav1.Metadata{Name: "user", Uid: vutils.UUIDv4()}, Spec: &corev1.User_Spec{Type: corev1.User_Spec_HUMAN}}
	cc := &corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{Ingress: &corev1.ClusterConfig_Spec_Ingress{UseForwardedForHeader: true}}}
	expiresAt := time.Now().Add(time.Hour)
	device := &corev1.Device{Metadata: &metav1.Metadata{Name: "device", Uid: vutils.UUIDv4()}}
	sess, err := sessionc.NewSession(ctx, &sessionc.CreateSessionOpts{
		Usr: usr, Device: device, ClusterConfig: cc, SessType: corev1.Session_Status_CLIENT,
		ExpiresAt: expiresAt, ClientAddr: "8.8.8.8", UserAgent: "octelium-cli/1.2.3 linux",
		IsBrowser: true, CredentialRef: &metav1.ObjectReference{Uid: "credential"},
		Authorization: &corev1.Session_Spec_Authorization{Policies: []string{"policy"}},
	})
	assert.Nil(t, err)
	assert.Equal(t, expiresAt.UnixNano(), sess.Spec.ExpiresAt.AsTime().UnixNano())
	assert.True(t, sess.Status.IsBrowser)
	assert.Equal(t, device.Metadata.Uid, sess.Status.DeviceRef.Uid)
	assert.Equal(t, "credential", sess.Status.CredentialRef.Uid)
	assert.Equal(t, []string{"policy"}, sess.Spec.Authorization.Policies)
	initial := pbutils.Clone(sess.Status.Authentication).(*corev1.Session_Status_Authentication)
	assert.Equal(t, "8.8.8.8", initial.Info.Downstream.IpAddress)
	assert.Equal(t, "1.2.3", initial.Info.Downstream.ClientVersion)
	for i := range 105 {
		previous := sess.Status.Authentication.TokenID
		sessionc.SetCurrAuthentication(&sessionc.SetCurrAuthenticationOpts{
			Session: sess, ClusterConfig: cc, ClientAddr: "2606:4700::1111", UserAgent: fmt.Sprintf("octelium-cli/2.%d.0 linux", i),
		})
		assert.NotEqual(t, previous, sess.Status.Authentication.TokenID)
		assert.Equal(t, previous, sess.Status.LastAuthentications[0].TokenID)
		assert.NotSame(t, sess.Status.LastAuthentications[0], sess.Status.Authentication)
		assert.Equal(t, "2606:4700::1111", sess.Status.Authentication.Info.Downstream.IpAddress)
		assert.Equal(t, fmt.Sprintf("2.%d.0", i), sess.Status.Authentication.Info.Downstream.ClientVersion)
		assert.True(t, pbutils.IsEqual(initial, sess.Status.InitialAuthentication))
	}
	assert.Len(t, sess.Status.LastAuthentications, 100)
	assert.EqualValues(t, 106, sess.Status.TotalAuthentications)
	cc.Spec.Ingress.UseForwardedForHeader = false
	sessionc.SetCurrAuthentication(&sessionc.SetCurrAuthenticationOpts{Session: sess, ClusterConfig: cc, ClientAddr: "8.8.8.8", UserAgent: strings.Repeat("a", 220)})
	assert.Nil(t, sess.Status.Authentication.Info)
	cc.Spec.Ingress.UseForwardedForHeader = true
	sessionc.SetCurrAuthentication(&sessionc.SetCurrAuthenticationOpts{Session: sess, ClusterConfig: cc, ClientAddr: "invalid"})
	assert.Nil(t, sess.Status.Authentication.Info)
}

type sessionCoreC struct {
	rcorev1.ResourceServiceClient
	count     uint32
	listErr   error
	createErr error
	created   int
	listOpts  *rmetav1.ListOptions
}

func (c *sessionCoreC) ListSession(ctx context.Context, req *rmetav1.ListOptions, opts ...grpc.CallOption) (*corev1.SessionList, error) {
	c.listOpts = req
	return &corev1.SessionList{ListResponseMeta: &metav1.ListResponseMeta{TotalCount: c.count}}, c.listErr
}

func (c *sessionCoreC) CreateSession(ctx context.Context, req *corev1.Session, opts ...grpc.CallOption) (*corev1.Session, error) {
	c.created++
	return req, c.createErr
}

type sessionOcteliumC struct {
	octeliumc.ClientInterface
	c *sessionCoreC
}

func (c *sessionOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.c
}

func TestSessionLimits(t *testing.T) {
	ctx := context.Background()
	for _, userType := range []corev1.User_Spec_Type{corev1.User_Spec_HUMAN, corev1.User_Spec_WORKLOAD, corev1.User_Spec_TYPE_UNKNOWN} {
		for _, limitType := range []string{"Default", "Cluster", "User", "Maximum"} {
			t.Run(userType.String()+"/"+limitType, func(t *testing.T) {
				usr := &corev1.User{Metadata: &metav1.Metadata{Name: "user", Uid: vutils.UUIDv4()}, Spec: &corev1.User_Spec{Type: userType}}
				cc := &corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{}}
				limit := uint32(128)
				if userType == corev1.User_Spec_HUMAN {
					limit = 16
				}
				if limitType == "Cluster" {
					limit = 3
					cc.Spec.Session = &corev1.ClusterConfig_Spec_Session{Human: &corev1.ClusterConfig_Spec_Session_Human{MaxPerUser: limit}, Workload: &corev1.ClusterConfig_Spec_Session_Workload{MaxPerUser: limit}}
				}
				if limitType == "User" || limitType == "Maximum" {
					limit = 2
					usr.Spec.Session = &corev1.User_Spec_Session{MaxPerUser: limit}
					if limitType == "Maximum" {
						usr.Spec.Session.MaxPerUser = 20000
						limit = 10000
					}
				}
				c := &sessionCoreC{count: limit}
				opts := &sessionc.CreateSessionOpts{Usr: usr, ClusterConfig: cc, SessType: corev1.Session_Status_CLIENT, CheckPerUserLimit: true, OcteliumC: &sessionOcteliumC{c: c}}
				res, err := sessionc.CreateSession(ctx, opts)
				assert.Equal(t, codes.PermissionDenied, status.Code(err))
				assert.Nil(t, res)
				assert.Zero(t, c.created)
				assert.NotNil(t, c.listOpts)
				c.count--
				res, err = sessionc.CreateSession(ctx, opts)
				assert.Nil(t, err)
				assert.NotNil(t, res)
				assert.Equal(t, 1, c.created)
				c.listErr = status.Error(codes.Unavailable, "unavailable")
				res, err = sessionc.CreateSession(ctx, opts)
				assert.Equal(t, codes.Internal, status.Code(err))
				assert.Nil(t, res)
				c.listErr = nil
				c.createErr = status.Error(codes.Unavailable, "unavailable")
				res, err = sessionc.CreateSession(ctx, opts)
				assert.Equal(t, codes.Internal, status.Code(err))
				assert.Nil(t, res)
			})
		}
	}
	_, err := sessionc.NewSession(ctx, nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = sessionc.CreateSession(ctx, nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestCreateSession(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	ccSpecs := []*corev1.ClusterConfig_Spec{
		{},
		{
			Session: &corev1.ClusterConfig_Spec_Session{
				Human: &corev1.ClusterConfig_Spec_Session_Human{
					ClientDuration: &metav1.Duration{
						Type: &metav1.Duration_Days{
							Days: 1,
						},
					},
				},
			},
		},
	}

	for _, ccSpec := range ccSpecs {
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)
		cc.Spec = ccSpec
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)

		{
			sess, err := sessionc.CreateSession(ctx, &sessionc.CreateSessionOpts{
				OcteliumC: fakeC.OcteliumC,
				Usr:       usr.Usr,
				Device:    usr.Device,
				SessType:  corev1.Session_Status_CLIENT,
			})
			assert.Nil(t, err)

			assert.True(t, sess.Spec.ExpiresAt.IsValid())
			assert.True(t, sess.Spec.ExpiresAt.AsTime().After(time.Now()))
		}

	}

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Spec.Ingress = &corev1.ClusterConfig_Spec_Ingress{
			UseForwardedForHeader: true,
		}
		cc, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)

		geoipCtl, err := geoipctl.New(ctx, &geoipctl.Opts{
			OcteliumC: fakeC.OcteliumC,
		})
		assert.Nil(t, err)
		const prefixURL = `https://raw.githubusercontent.com/maxmind/MaxMind-DB/refs/heads/main/test-data`
		err = geoipCtl.Set(ctx, &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB{
			Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_{
				Upstream: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream{
					Url: fmt.Sprintf("%s/GeoIP2-City-Test.mmdb", prefixURL),
				},
			},
		})
		assert.Nil(t, err)
		assert.Nil(t, err)
		sess, err := sessionc.NewSession(ctx, &sessionc.CreateSessionOpts{
			OcteliumC:  fakeC.OcteliumC,
			Usr:        usr.Usr,
			Device:     usr.Device,
			SessType:   corev1.Session_Status_CLIENT,
			ClientAddr: "214.78.120.1",
			GeoIPCtl:   geoipCtl,
		})
		assert.Nil(t, err)

		assert.NotNil(t, sess.Status.Authentication.Info)
		assert.Equal(t, "214.78.120.1", sess.Status.Authentication.Info.Downstream.IpAddress)
		assert.Equal(t, "US", sess.Status.Authentication.Info.Geoip.Country.Code)
	}

}
