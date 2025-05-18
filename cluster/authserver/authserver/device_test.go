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

package authserver

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func testInvalidateAccessToken(t *testing.T, octeliumC octeliumc.ClientInterface, sess *corev1.Session) {
	var err error

	sess.Status.Authentication.SetAt = pbutils.Timestamp(time.Now().Add(-10 * time.Hour))
	_, err = octeliumC.CoreC().UpdateSession(context.Background(), sess)
	assert.Nil(t, err, "%+v", err)
}

func TestCanCreateDevice(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		req := &authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{
				Id:           utilrand.GetRandomString(12),
				SerialNumber: utilrand.GetRandomString(12),
				Hostname:     utilrand.GetRandomString(6),
				OsType:       authv1.RegisterDeviceBeginRequest_Info_LINUX,
			},
		}

		err = srv.checkCanCreateDevice(ctx, cc, usr.Usr, usr.Session, req)
		assert.Nil(t, err)

		dev, err := srv.doBuildDevice(ctx, cc, req, usr.Usr)
		assert.Nil(t, err)
		dev, err = srv.octeliumC.CoreC().CreateDevice(ctx, dev)
		assert.Nil(t, err)
		assert.Equal(t, usr.Usr.Metadata.Uid, dev.Status.UserRef.Uid)
		assert.Equal(t, corev1.Device_Spec_ACTIVE, dev.Spec.State)
		assert.Equal(t, req.Info.Id, dev.Status.Id)
		assert.Equal(t, req.Info.Hostname, dev.Status.Hostname)
		assert.Equal(t, req.Info.SerialNumber, dev.Status.SerialNumber)

		err = srv.checkCanCreateDevice(ctx, cc, usr.Usr, usr.Session, req)
		assert.NotNil(t, err)

		req.Info.Id = utilrand.GetRandomString(12)
		err = srv.checkCanCreateDevice(ctx, cc, usr.Usr, usr.Session, req)
		assert.NotNil(t, err)

		req.Info.SerialNumber = utilrand.GetRandomString(12)
		err = srv.checkCanCreateDevice(ctx, cc, usr.Usr, usr.Session, req)
		assert.Nil(t, err)

	}

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		for i := 0; i < defaultMaxDevicePerUser; i++ {
			req := &authv1.RegisterDeviceBeginRequest{
				Info: &authv1.RegisterDeviceBeginRequest_Info{
					Id:           utilrand.GetRandomString(12),
					SerialNumber: utilrand.GetRandomString(12),
					Hostname:     utilrand.GetRandomString(6),
					OsType:       authv1.RegisterDeviceBeginRequest_Info_LINUX,
				},
			}

			err = srv.checkCanCreateDevice(ctx, cc, usr.Usr, usr.Session, req)
			assert.Nil(t, err)

			dev, err := srv.doBuildDevice(ctx, cc, req, usr.Usr)
			assert.Nil(t, err)

			dev, err = srv.octeliumC.CoreC().CreateDevice(ctx, dev)
			assert.Nil(t, err)
		}

		req := &authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{
				Id:           utilrand.GetRandomString(12),
				SerialNumber: utilrand.GetRandomString(12),
				Hostname:     utilrand.GetRandomString(6),
				OsType:       authv1.RegisterDeviceBeginRequest_Info_LINUX,
			},
		}
		err = srv.checkCanCreateDevice(ctx, cc, usr.Usr, usr.Session, req)
		assert.NotNil(t, err)
	}
}

func getCtxRT(usrT *tstuser.User) context.Context {
	return getCtxRTSessTkn(usrT.GetAccessToken())
}
func getCtxRTSessTkn(s *authv1.SessionToken) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.New(map[string]string{
		"x-octelium-refresh-token": s.RefreshToken,
	}))
}

func TestDeviceRegister(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{

		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		usrT.Session.Status.DeviceRef = nil
		usrT.Device = nil

		usrT.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
		assert.Nil(t, err)

		usrT.Resync()

		id := fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32))))
		resp, err := srv.doRegisterDeviceBegin(getCtxRT(usrT), &authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{
				Id:           id,
				SerialNumber: utilrand.GetRandomString(12),
				Hostname:     utilrand.GetRandomString(6),
				OsType:       authv1.RegisterDeviceBeginRequest_Info_WINDOWS,
			},
		})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.doRegisterDeviceFinish(getCtxRT(usrT), &authv1.RegisterDeviceFinishRequest{
			Uid: resp.Uid,
		})
		assert.Nil(t, err, "%+v", err)

		sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: usrT.Session.Metadata.Uid,
		})
		assert.Nil(t, err)

		dev, err := srv.octeliumC.CoreC().GetDevice(ctx, &rmetav1.GetOptions{
			Uid: sess.Status.DeviceRef.Uid,
		})
		assert.Nil(t, err)

		assert.Equal(t, usrT.Usr.Metadata.Uid, dev.Status.UserRef.Uid)
	}

}

func TestValidateRegisterDeviceRequest(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	{
		err := srv.validateRegisterDeviceBeginRequest(nil)
		assert.NotNil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{})
		assert.NotNil(t, err)
	}

	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{},
		})
		assert.NotNil(t, err)
	}

	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{},
		})
		assert.NotNil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{
				Id: utilrand.GetRandomString(16),
			},
		})
		assert.NotNil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{
				Id: utilrand.GetRandomString(32),
			},
		})
		assert.NotNil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{
				Id: fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
			},
		})
		assert.NotNil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{
				Id:     fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
				OsType: authv1.RegisterDeviceBeginRequest_Info_LINUX,
			},
		})
		assert.Nil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{
				Id:       fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
				OsType:   authv1.RegisterDeviceBeginRequest_Info_LINUX,
				Hostname: utilrand.GetRandomString(20),
			},
		})
		assert.Nil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{
				Id:           fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
				OsType:       authv1.RegisterDeviceBeginRequest_Info_LINUX,
				Hostname:     utilrand.GetRandomString(20),
				SerialNumber: utilrand.GetRandomString(20),
			},
		})
		assert.Nil(t, err)
	}
}

/*
func TestValidateAuthenticateDeviceBeginRequest(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc, redisutils.NewClient())
	assert.Nil(t, err)

	{
		err := srv.validateAuthenticateDeviceBeginRequest(nil)
		assert.NotNil(t, err)
	}
	{
		err := srv.validateAuthenticateDeviceBeginRequest(&authv1.AuthenticateDeviceBeginRequest{})
		assert.NotNil(t, err)
	}

	{
		err := srv.validateAuthenticateDeviceBeginRequest(&authv1.AuthenticateDeviceBeginRequest{})
		assert.NotNil(t, err)
	}

	{
		err := srv.validateAuthenticateDeviceBeginRequest(&authv1.AuthenticateDeviceBeginRequest{})
		assert.NotNil(t, err)
	}
	{
		err := srv.validateAuthenticateDeviceBeginRequest(&authv1.AuthenticateDeviceBeginRequest{
			Id: utilrand.GetRandomString(64),
		})
		assert.NotNil(t, err)
	}
	{
		err := srv.validateAuthenticateDeviceBeginRequest(&authv1.AuthenticateDeviceBeginRequest{
			Id: fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
		})
		assert.Nil(t, err)
	}
}
*/

/*
func TestHandleDeviceAuthenticate(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc, redisutils.NewClient())
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		assert.Nil(t, usr.Session.Status.DeviceRef)

		registerReq := &authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceBeginRequest_Info{
				Id:           fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
				SerialNumber: utilrand.GetRandomString(12),
				Hostname:     utilrand.GetRandomString(6),
				OsType:       authv1.RegisterDeviceBeginRequest_Info_LINUX,
			},
		}

		resp, err := srv.doRegisterDevice(getCtxRT(usr), registerReq)
		assert.Nil(t, err)
		assert.Equal(t, 32, len(resp.AuthenticationRequest.Challenge))

		respFinish, err := srv.doRegisterDeviceFinish(getCtxRT(usr), &authv1.RegisterDeviceFinishRequest{
			AuthenticationResponse: &authv1.DeviceAuthenticationResponse{
				Challenge: resp.AuthenticationRequest.Challenge,

				Type: &authv1.DeviceAuthenticationResponse_None_{
					None: &authv1.DeviceAuthenticationResponse_None{},
				},
			},
		})
		assert.Nil(t, err)

		sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: usr.Session.Metadata.Uid,
		})
		assert.Nil(t, err)

		assert.Equal(t, respFinish.DeviceRef.Uid, sess.Status.DeviceRef.Uid)

		authResp, err := srv.doAuthenticateDeviceBegin(getCtxRT(usr), &authv1.AuthenticateDeviceBeginRequest{
			Id: registerReq.Info.Id,
		})
		assert.Nil(t, err)
		assert.NotNil(t, authResp)
		assert.Equal(t, 32, len(authResp.AuthenticationRequest.Challenge))
		assert.NotNil(t, authResp.AuthenticationRequest.GetNone())

		res, err := srv.doAuthenticateWithDevice(getCtxRT(usr), &authv1.AuthenticateWithDeviceRequest{
			Response: &authv1.DeviceAuthenticationResponse{
				Challenge: authResp.AuthenticationRequest.Challenge,
				Type: &authv1.DeviceAuthenticationResponse_None_{
					None: &authv1.DeviceAuthenticationResponse_None{},
				},
			},
		})
		assert.Nil(t, err)
		assert.NotNil(t, res)

		claims, err := srv.jwkCtl.VerifyAccessToken(res.AccessToken)
		assert.Nil(t, err)

		sess, err = srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: sess.Metadata.Uid,
		})
		assert.Nil(t, err)

		assert.Equal(t, claims.TokenID, sess.Status.Authentication.TokenID)

	}
}
*/
