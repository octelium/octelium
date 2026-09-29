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
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
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

	var firstReq *authv1.RegisterDeviceBeginRequest

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		req := &authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id:           utilrand.GetRandomString(12),
				SerialNumber: utilrand.GetRandomString(12),
				Hostname:     utilrand.GetRandomString(6),
				OsType:       authv1.RegisterDeviceRequest_Info_LINUX,
				MacAddresses: []string{"02:42:AC:11:00:02"},
			},
		}

		existing, err := srv.checkCanCreateDevice(ctx, cc, usr.Usr, req.Info)
		assert.Nil(t, err)
		assert.Nil(t, existing)

		dev, err := srv.doBuildDevice(ctx, cc, req.Info, usr.Usr)
		assert.Nil(t, err)
		dev, err = srv.octeliumC.CoreC().CreateDevice(ctx, dev)
		assert.Nil(t, err)
		assert.Equal(t, usr.Usr.Metadata.Uid, dev.Status.UserRef.Uid)
		assert.Equal(t, corev1.Device_Spec_ACTIVE, dev.Spec.State)
		assert.Equal(t, req.Info.Id, dev.Status.Id)
		assert.Equal(t, req.Info.Hostname, dev.Status.Hostname)
		assert.Equal(t, req.Info.SerialNumber, dev.Status.SerialNumber)
		assert.Equal(t, []string{"02:42:ac:11:00:02"}, dev.Status.MacAddresses)

		existing, err = srv.checkCanCreateDevice(ctx, cc, usr.Usr, req.Info)
		assert.Nil(t, err)
		assert.Equal(t, dev.Metadata.Uid, existing.Metadata.Uid)

		req.Info.Id = utilrand.GetRandomString(12)
		existing, err = srv.checkCanCreateDevice(ctx, cc, usr.Usr, req.Info)
		assert.Nil(t, err)
		assert.Equal(t, dev.Metadata.Uid, existing.Metadata.Uid)

		req.Info.SerialNumber = utilrand.GetRandomString(12)
		existing, err = srv.checkCanCreateDevice(ctx, cc, usr.Usr, req.Info)
		assert.Nil(t, err)
		assert.Nil(t, existing)

		firstReq = &authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id:           dev.Status.Id,
				SerialNumber: dev.Status.SerialNumber,
				OsType:       authv1.RegisterDeviceRequest_Info_LINUX,
			},
		}
	}

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		existing, err := srv.checkCanCreateDevice(ctx, cc, usr.Usr, &authv1.RegisterDeviceRequest_Info{
			Id:           utilrand.GetRandomString(12),
			SerialNumber: firstReq.Info.SerialNumber,
			OsType:       authv1.RegisterDeviceRequest_Info_LINUX,
		})
		assert.Nil(t, err, "a serial number of another User's Device must not block the registration")
		assert.Nil(t, existing)

		_, err = srv.checkCanCreateDevice(ctx, cc, usr.Usr, firstReq.Info)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		for i := 0; i < defaultMaxDevicePerUser; i++ {
			req := &authv1.RegisterDeviceBeginRequest{
				Info: &authv1.RegisterDeviceRequest_Info{
					Id:           utilrand.GetRandomString(12),
					SerialNumber: utilrand.GetRandomString(12),
					Hostname:     utilrand.GetRandomString(6),
					OsType:       authv1.RegisterDeviceRequest_Info_LINUX,
				},
			}

			existing, err := srv.checkCanCreateDevice(ctx, cc, usr.Usr, req.Info)
			assert.Nil(t, err)
			assert.Nil(t, existing)

			dev, err := srv.doBuildDevice(ctx, cc, req.Info, usr.Usr)
			assert.Nil(t, err)

			dev, err = srv.octeliumC.CoreC().CreateDevice(ctx, dev)
			assert.Nil(t, err)
		}

		req := &authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id:           utilrand.GetRandomString(12),
				SerialNumber: utilrand.GetRandomString(12),
				Hostname:     utilrand.GetRandomString(6),
				OsType:       authv1.RegisterDeviceRequest_Info_LINUX,
			},
		}
		_, err = srv.checkCanCreateDevice(ctx, cc, usr.Usr, req.Info)
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

	usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	detachSession := func(usrT *tstuser.User) {
		sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: usrT.Session.Metadata.Uid,
		})
		assert.Nil(t, err)
		sess.Status.DeviceRef = nil
		usrT.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)
	}

	getSessionDeviceUID := func(usrT *tstuser.User) string {
		sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: usrT.Session.Metadata.Uid,
		})
		assert.Nil(t, err)
		return sess.Status.DeviceRef.GetUid()
	}

	detachSession(usrT)
	usrT.Device = nil
	usrT.Resync()

	req := &authv1.RegisterDeviceBeginRequest{
		Info: &authv1.RegisterDeviceRequest_Info{
			Id:           fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
			SerialNumber: utilrand.GetRandomString(12),
			Hostname:     utilrand.GetRandomString(6),
			OsType:       authv1.RegisterDeviceRequest_Info_WINDOWS,
			MacAddresses: []string{"00:1A:2B:3C:4D:5E"},
		},
	}

	var devUID string

	{
		_, err = srv.doRegisterDeviceFinish(getCtxRT(usrT), &authv1.RegisterDeviceFinishRequest{
			Uid: utilrand.GetRandomStringCanonical(10),
		})
		assert.NotNil(t, err)
		assert.Equal(t, "", getSessionDeviceUID(usrT))

		resp, err := srv.doRegisterDeviceBegin(getCtxRT(usrT), req)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "", getSessionDeviceUID(usrT))

		_, err = srv.doRegisterDeviceFinish(getCtxRT(usrT), &authv1.RegisterDeviceFinishRequest{
			Uid: resp.Uid,
		})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.doRegisterDeviceFinish(getCtxRT(usrT), &authv1.RegisterDeviceFinishRequest{
			Uid: resp.Uid,
		})
		assert.NotNil(t, err)

		devUID = getSessionDeviceUID(usrT)
		assert.NotEqual(t, "", devUID)

		dev, err := srv.octeliumC.CoreC().GetDevice(ctx, &rmetav1.GetOptions{
			Uid: devUID,
		})
		assert.Nil(t, err)

		assert.Equal(t, usrT.Usr.Metadata.Uid, dev.Status.UserRef.Uid)
		assert.Equal(t, corev1.Device_Status_WINDOWS, dev.Status.OsType)
		assert.Equal(t, req.Info.Id, dev.Status.Id)
		assert.Equal(t, req.Info.SerialNumber, dev.Status.SerialNumber)
		assert.Equal(t, req.Info.Hostname, dev.Status.Hostname)
		assert.Equal(t, []string{"00:1a:2b:3c:4d:5e"}, dev.Status.MacAddresses)
	}

	{
		_, err := srv.doRegisterDeviceBegin(getCtxRT(usrT), req)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err))
		assert.Equal(t, devUID, getSessionDeviceUID(usrT))
	}

	{
		dev, err := srv.octeliumC.CoreC().GetDevice(ctx, &rmetav1.GetOptions{Uid: devUID})
		assert.Nil(t, err)
		dev.Status.Binding = &corev1.Device_Status_Binding{
			Uid:      "binding",
			OwnerRef: &metav1.ObjectReference{Uid: "dm1", Name: "dm1"},
			State:    corev1.Device_Status_Binding_ACCEPTED,
			Validity: corev1.Device_Status_Binding_VALID,
		}
		dev.Status.Posture = &corev1.Device_Status_Posture{
			ThreatFree: corev1.Device_Status_Posture_PASS,
		}
		_, err = srv.octeliumC.CoreC().UpdateDevice(ctx, dev)
		assert.Nil(t, err)

		detachSession(usrT)

		_, err = srv.doRegisterDeviceBegin(getCtxRT(usrT), req)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err))
		assert.Equal(t, devUID, getSessionDeviceUID(usrT))

		dev, err = srv.octeliumC.CoreC().GetDevice(ctx, &rmetav1.GetOptions{Uid: devUID})
		assert.Nil(t, err)
		assert.Equal(t, "binding", dev.Status.Binding.Uid)
		assert.Equal(t, corev1.Device_Status_Posture_PASS, dev.Status.Posture.ThreatFree)
	}

	{
		detachSession(usrT)

		serialReq := pbutils.Clone(req).(*authv1.RegisterDeviceBeginRequest)
		serialReq.Info.Id = fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32))))

		_, err := srv.doRegisterDeviceBegin(getCtxRT(usrT), serialReq)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err))
		assert.Equal(t, devUID, getSessionDeviceUID(usrT))
	}

	{
		otherT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		detachSession(otherT)

		_, err = srv.doRegisterDeviceBegin(getCtxRT(otherT), req)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
		assert.Equal(t, "", getSessionDeviceUID(otherT))

		otherReq := pbutils.Clone(req).(*authv1.RegisterDeviceBeginRequest)
		otherReq.Info.Id = fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32))))

		resp, err := srv.doRegisterDeviceBegin(getCtxRT(otherT), otherReq)
		assert.Nil(t, err, "%+v", err)

		_, err = srv.doRegisterDeviceFinish(getCtxRT(usrT), &authv1.RegisterDeviceFinishRequest{
			Uid: resp.Uid,
		})
		assert.NotNil(t, err, "a registration must not be finished by another Session")

		resp, err = srv.doRegisterDeviceBegin(getCtxRT(otherT), otherReq)
		assert.Nil(t, err, "%+v", err)

		_, err = srv.doRegisterDeviceFinish(getCtxRT(otherT), &authv1.RegisterDeviceFinishRequest{
			Uid: resp.Uid,
		})
		assert.Nil(t, err, "%+v", err)

		otherDevUID := getSessionDeviceUID(otherT)
		assert.NotEqual(t, "", otherDevUID)
		assert.NotEqual(t, devUID, otherDevUID)
	}
}

func TestRegisterDevice(t *testing.T) {
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

	usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	newSession := func(usrT *tstuser.User) *tstuser.User {
		ret, err := tstuser.WithUser(srv.octeliumC, adminSrv, nil, usrT.Usr, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: ret.Session.Metadata.Uid,
		})
		assert.Nil(t, err)
		sess.Status.DeviceRef = nil
		ret.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		_, err = srv.octeliumC.CoreC().DeleteDevice(ctx, &rmetav1.DeleteOptions{
			Uid: ret.Device.Metadata.Uid,
		})
		assert.Nil(t, err)
		ret.Device = nil

		return ret
	}

	getSessionDeviceUID := func(usrT *tstuser.User) string {
		sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: usrT.Session.Metadata.Uid,
		})
		assert.Nil(t, err)
		return sess.Status.DeviceRef.GetUid()
	}

	getDevicesByID := func(id string) []*corev1.Device {
		devList, err := srv.octeliumC.CoreC().ListDevice(ctx, &rmetav1.ListOptions{
			Filters: []*rmetav1.ListOptions_Filter{
				urscsrv.FilterFieldEQValStr("status.id", id),
			},
		})
		assert.Nil(t, err)
		return devList.Items
	}

	getInfo := func() *authv1.RegisterDeviceRequest_Info {
		return &authv1.RegisterDeviceRequest_Info{
			Id:           fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
			SerialNumber: utilrand.GetRandomString(12),
			Hostname:     utilrand.GetRandomString(6),
			OsType:       authv1.RegisterDeviceRequest_Info_MAC,
			MacAddresses: []string{"00:1A:2B:3C:4D:5E"},
		}
	}

	info := getInfo()

	var devUID string

	{
		sessT := newSession(usrT)

		for _, req := range []*authv1.RegisterDeviceRequest{
			nil,
			{},
			{
				Info: &authv1.RegisterDeviceRequest_Info{
					Id:     "invalid",
					OsType: authv1.RegisterDeviceRequest_Info_LINUX,
				},
			},
		} {
			_, err := srv.doRegisterDevice(getCtxRT(sessT), req)
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsInvalidArg(err))
		}
		assert.Equal(t, "", getSessionDeviceUID(sessT))

		_, err := srv.doRegisterDevice(getCtxRT(sessT), &authv1.RegisterDeviceRequest{
			Info: info,
		})
		assert.Nil(t, err, "%+v", err)

		devUID = getSessionDeviceUID(sessT)
		assert.NotEqual(t, "", devUID)

		devs := getDevicesByID(info.Id)
		assert.Equal(t, 1, len(devs))
		dev := devs[0]
		assert.Equal(t, devUID, dev.Metadata.Uid)
		assert.Equal(t, usrT.Usr.Metadata.Uid, dev.Status.UserRef.Uid)
		assert.Equal(t, corev1.Device_Status_MAC, dev.Status.OsType)
		assert.Equal(t, info.Hostname, dev.Status.Hostname)
		assert.Equal(t, info.SerialNumber, dev.Status.SerialNumber)
		assert.Equal(t, []string{"00:1a:2b:3c:4d:5e"}, dev.Status.MacAddresses)
		assert.Equal(t, corev1.Device_Spec_ACTIVE, dev.Spec.State)

		_, err = srv.doRegisterDevice(getCtxRT(sessT), &authv1.RegisterDeviceRequest{
			Info: info,
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err), "a Session that is already bound to a Device must be reported")
		assert.Equal(t, devUID, getSessionDeviceUID(sessT))
		assert.Equal(t, 1, len(getDevicesByID(info.Id)))
	}

	{
		dev, err := srv.octeliumC.CoreC().GetDevice(ctx, &rmetav1.GetOptions{Uid: devUID})
		assert.Nil(t, err)
		dev.Status.Binding = &corev1.Device_Status_Binding{
			Uid:      "binding",
			OwnerRef: &metav1.ObjectReference{Uid: "dm1", Name: "dm1"},
			State:    corev1.Device_Status_Binding_ACCEPTED,
			Validity: corev1.Device_Status_Binding_VALID,
		}
		_, err = srv.octeliumC.CoreC().UpdateDevice(ctx, dev)
		assert.Nil(t, err)

		sessT := newSession(usrT)

		_, err = srv.doRegisterDevice(getCtxRT(sessT), &authv1.RegisterDeviceRequest{
			Info: info,
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, devUID, getSessionDeviceUID(sessT), "a new Session must be bound to the existing Device")
		assert.Equal(t, 1, len(getDevicesByID(info.Id)))

		dev, err = srv.octeliumC.CoreC().GetDevice(ctx, &rmetav1.GetOptions{Uid: devUID})
		assert.Nil(t, err)
		assert.Equal(t, "binding", dev.Status.Binding.Uid)
	}

	{
		sessT := newSession(usrT)

		serialInfo := getInfo()
		serialInfo.SerialNumber = info.SerialNumber

		_, err := srv.doRegisterDevice(getCtxRT(sessT), &authv1.RegisterDeviceRequest{
			Info: serialInfo,
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, devUID, getSessionDeviceUID(sessT))
		assert.Equal(t, 0, len(getDevicesByID(serialInfo.Id)))
	}

	{
		sessT := newSession(usrT)

		_, err := srv.doRegisterDeviceBegin(getCtxRT(sessT), &authv1.RegisterDeviceBeginRequest{
			Info: info,
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err),
			"a legacy client must be bound to a Device that is registered by RegisterDevice")
		assert.Equal(t, devUID, getSessionDeviceUID(sessT))
	}

	{
		legacyInfo := getInfo()

		sessT := newSession(usrT)

		resp, err := srv.doRegisterDeviceBegin(getCtxRT(sessT), &authv1.RegisterDeviceBeginRequest{
			Info: legacyInfo,
		})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.doRegisterDeviceFinish(getCtxRT(sessT), &authv1.RegisterDeviceFinishRequest{
			Uid: resp.Uid,
		})
		assert.Nil(t, err, "%+v", err)

		legacyDevUID := getSessionDeviceUID(sessT)
		assert.NotEqual(t, "", legacyDevUID)
		assert.NotEqual(t, devUID, legacyDevUID)

		otherSessT := newSession(usrT)

		_, err = srv.doRegisterDevice(getCtxRT(otherSessT), &authv1.RegisterDeviceRequest{
			Info: legacyInfo,
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, legacyDevUID, getSessionDeviceUID(otherSessT),
			"RegisterDevice must bind to a Device that is registered by a legacy client")
		assert.Equal(t, 1, len(getDevicesByID(legacyInfo.Id)))
	}

	{
		otherT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		sessT := newSession(otherT)

		_, err = srv.doRegisterDevice(getCtxRT(sessT), &authv1.RegisterDeviceRequest{
			Info: info,
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "the Device of another User must not be claimed")
		assert.Equal(t, "", getSessionDeviceUID(sessT))
	}

	{
		clientlessT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		_, err = srv.doRegisterDevice(getCtxRT(clientlessT), &authv1.RegisterDeviceRequest{
			Info: getInfo(),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err))
	}

	{
		limitT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		for range defaultMaxDevicePerUser - 1 {
			sessT := newSession(limitT)
			_, err := srv.doRegisterDevice(getCtxRT(sessT), &authv1.RegisterDeviceRequest{
				Info: getInfo(),
			})
			assert.Nil(t, err, "%+v", err)
		}

		sessT := newSession(limitT)
		_, err = srv.doRegisterDevice(getCtxRT(sessT), &authv1.RegisterDeviceRequest{
			Info: getInfo(),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err))
		assert.Equal(t, "", getSessionDeviceUID(sessT))
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
		assert.NotNil(t, srv.validateRegisterDeviceRequest(nil))
		assert.NotNil(t, srv.validateRegisterDeviceRequest(&authv1.RegisterDeviceRequest{}))
		assert.NotNil(t, srv.validateRegisterDeviceRequest(&authv1.RegisterDeviceRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id: fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
			},
		}))
		assert.NotNil(t, srv.validateRegisterDeviceRequest(&authv1.RegisterDeviceRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id:           fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
				OsType:       authv1.RegisterDeviceRequest_Info_LINUX,
				MacAddresses: []string{"invalid"},
			},
		}))
		assert.Nil(t, srv.validateRegisterDeviceRequest(&authv1.RegisterDeviceRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id:           fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
				OsType:       authv1.RegisterDeviceRequest_Info_LINUX,
				SerialNumber: utilrand.GetRandomString(12),
				MacAddresses: []string{"00:1a:2b:3c:4d:5e"},
			},
		}))
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{})
		assert.NotNil(t, err)
	}

	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{},
		})
		assert.NotNil(t, err)
	}

	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{},
		})
		assert.NotNil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id: utilrand.GetRandomString(16),
			},
		})
		assert.NotNil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id: utilrand.GetRandomString(32),
			},
		})
		assert.NotNil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id: fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
			},
		})
		assert.NotNil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id:     fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
				OsType: authv1.RegisterDeviceRequest_Info_LINUX,
			},
		})
		assert.Nil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id:     fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
				OsType: authv1.RegisterDeviceRequest_Info_CHROMEOS,
			},
		})
		assert.Nil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id:     fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
				OsType: authv1.RegisterDeviceRequest_Info_OSType(100),
			},
		})
		assert.NotNil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id:       fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
				OsType:   authv1.RegisterDeviceRequest_Info_LINUX,
				Hostname: utilrand.GetRandomString(20),
			},
		})
		assert.Nil(t, err)
	}
	{
		err := srv.validateRegisterDeviceBeginRequest(&authv1.RegisterDeviceBeginRequest{
			Info: &authv1.RegisterDeviceRequest_Info{
				Id:           fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
				OsType:       authv1.RegisterDeviceRequest_Info_LINUX,
				Hostname:     utilrand.GetRandomString(20),
				SerialNumber: utilrand.GetRandomString(20),
			},
		})
		assert.Nil(t, err)
	}

	{
		assert.NotNil(t, srv.validateRegisterDeviceFinishRequest(nil))
		assert.NotNil(t, srv.validateRegisterDeviceFinishRequest(&authv1.RegisterDeviceFinishRequest{}))
		assert.Nil(t, srv.validateRegisterDeviceFinishRequest(&authv1.RegisterDeviceFinishRequest{
			Uid: utilrand.GetRandomStringCanonical(10),
		}))
		assert.NotNil(t, srv.validateRegisterDeviceFinishRequest(&authv1.RegisterDeviceFinishRequest{
			Uid: utilrand.GetRandomString(10),
		}))
	}
}

func TestValidateRunDeviceProbe(t *testing.T) {
	srv := &server{}

	{
		assert.NotNil(t, srv.validateRunDeviceProbeBegin(nil))
		assert.Nil(t, srv.validateRunDeviceProbeBegin(&authv1.RunDeviceProbeBeginRequest{}))
	}

	{
		getReq := func() *authv1.RunDeviceProbeFinishRequest {
			return &authv1.RunDeviceProbeFinishRequest{
				AttemptUID: utilrand.GetRandomStringCanonical(32),
				Results: []*authv1.DeviceProbeResult{
					{
						ProbeID: "probe-1",
						Status:  authv1.DeviceProbeResult_OK,
						Value: &authv1.DeviceProbeResult_Text{
							Text: "abc",
						},
					},
					{
						ProbeID: "probe.2",
						Status:  authv1.DeviceProbeResult_NOT_FOUND,
					},
					{
						ProbeID: "Probe_3",
						Status:  authv1.DeviceProbeResult_OK,
						Value: &authv1.DeviceProbeResult_List_{
							List: &authv1.DeviceProbeResult_List{
								Items: []string{"a", "b"},
							},
						},
					},
				},
			}
		}

		assert.NotNil(t, srv.validateRunDeviceProbeFinish(nil))
		assert.Nil(t, srv.validateRunDeviceProbeFinish(getReq()))

		mutations := []func(req *authv1.RunDeviceProbeFinishRequest){
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.AttemptUID = "invalid"
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.Results = nil
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.Results = append(req.Results, nil)
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.Results[0].ProbeID = ""
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.Results[0].ProbeID = "-invalid"
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.Results[0].ProbeID = strings.Repeat("a", 129)
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.Results[0].Status = authv1.DeviceProbeResult_STATUS_UNKNOWN
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.Results[0].Status = authv1.DeviceProbeResult_Status(100)
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.Results[0].Detail = strings.Repeat("a", maxProbeResultDetailLen+1)
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.Results[0].Value = &authv1.DeviceProbeResult_Text{
					Text: strings.Repeat("a", hardProbeMaxOutputBytes+1),
				}
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.Results[0].Value = &authv1.DeviceProbeResult_Data{
					Data: utilrand.GetRandomBytesMust(hardProbeMaxOutputBytes + 1),
				}
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.Results[2].GetList().Items = make([]string, maxProbeResultListItems+1)
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				req.Results[2].GetList().Items = []string{strings.Repeat("a", maxProbeResultListItemLen+1)}
			},
			func(req *authv1.RunDeviceProbeFinishRequest) {
				for range maxProbesPerAttempt {
					req.Results = append(req.Results, &authv1.DeviceProbeResult{
						ProbeID: "probe",
						Status:  authv1.DeviceProbeResult_OK,
					})
				}
			},
		}

		for i, mutate := range mutations {
			req := getReq()
			mutate(req)
			assert.NotNil(t, srv.validateRunDeviceProbeFinish(req), "mutation: %d", i)
		}
	}
}

func TestGetProbeOwnerFilter(t *testing.T) {
	now := time.Now()

	getDevice := func(b *corev1.Device_Status_Binding) *corev1.Device {
		if b != nil {
			b.OwnerRef = &metav1.ObjectReference{Uid: "dm1"}
		}
		return &corev1.Device{
			Status: &corev1.Device_Status{
				Binding: b,
			},
		}
	}

	check := func(b *corev1.Device_Status_Binding, ownerUID string, ok bool) {
		t.Helper()
		resOwnerUID, resOK := getProbeOwnerFilter(getDevice(b), now)
		assert.Equal(t, ownerUID, resOwnerUID)
		assert.Equal(t, ok, resOK)
	}

	check(nil, "", true)
	check(&corev1.Device_Status_Binding{
		State: corev1.Device_Status_Binding_AMBIGUOUS,
	}, "", true)
	check(&corev1.Device_Status_Binding{
		State: corev1.Device_Status_Binding_CONFLICT,
	}, "", true)
	check(&corev1.Device_Status_Binding{
		State:    corev1.Device_Status_Binding_ACCEPTED,
		Validity: corev1.Device_Status_Binding_VALID,
	}, "", false)
	check(&corev1.Device_Status_Binding{
		State:              corev1.Device_Status_Binding_ACCEPTED,
		Validity:           corev1.Device_Status_Binding_VALID,
		NextVerificationAt: pbutils.Timestamp(now.Add(time.Hour)),
	}, "", false)
	check(&corev1.Device_Status_Binding{
		State:              corev1.Device_Status_Binding_ACCEPTED,
		Validity:           corev1.Device_Status_Binding_VALID,
		NextVerificationAt: pbutils.Timestamp(now.Add(-time.Second)),
	}, "dm1", true)
	check(&corev1.Device_Status_Binding{
		State:    corev1.Device_Status_Binding_ACCEPTED,
		Validity: corev1.Device_Status_Binding_SUSPENDED,
	}, "dm1", true)
	check(&corev1.Device_Status_Binding{
		State:    corev1.Device_Status_Binding_ACCEPTED,
		Validity: corev1.Device_Status_Binding_LOST,
	}, "dm1", true)
}

func TestToAuthProbe(t *testing.T) {
	probes := []*corev1.ClusterConfig_Status_Device_Probe{
		{
			Id:               "cmd",
			RequireElevation: true,
			Type: &corev1.ClusterConfig_Status_Device_Probe_RunCommand_{
				RunCommand: &corev1.ClusterConfig_Status_Device_Probe_RunCommand{
					Command:        "/usr/bin/cmd",
					Args:           []string{"-a"},
					TimeoutSeconds: 10,
					MaxOutputBytes: 100,
				},
			},
		},
		{
			Id: "file",
			Type: &corev1.ClusterConfig_Status_Device_Probe_ReadFile_{
				ReadFile: &corev1.ClusterConfig_Status_Device_Probe_ReadFile{
					Path:     "/etc/file",
					MaxBytes: 10,
				},
			},
		},
		{
			Id: "registry",
			Type: &corev1.ClusterConfig_Status_Device_Probe_ReadRegistry_{
				ReadRegistry: &corev1.ClusterConfig_Status_Device_Probe_ReadRegistry{
					Key:  `HKLM\SOFTWARE\Key`,
					Name: "Name",
				},
			},
		},
		{
			Id: "identifier",
			Type: &corev1.ClusterConfig_Status_Device_Probe_PlatformIdentifier_{
				PlatformIdentifier: &corev1.ClusterConfig_Status_Device_Probe_PlatformIdentifier{
					Kind: corev1.ClusterConfig_Status_Device_Probe_PlatformIdentifier_HARDWARE_UUID,
				},
			},
		},
	}

	res := toAuthProbes(probes)
	assert.Equal(t, len(probes), len(res))

	assert.Equal(t, "cmd", res[0].ProbeID)
	assert.True(t, res[0].RequireElevation)
	assert.Equal(t, "/usr/bin/cmd", res[0].GetRunCommand().Command)
	assert.Equal(t, []string{"-a"}, res[0].GetRunCommand().Args)
	assert.Equal(t, uint32(10), res[0].GetRunCommand().TimeoutSeconds)
	assert.Equal(t, uint32(100), res[0].GetRunCommand().MaxOutputBytes)

	assert.Equal(t, "/etc/file", res[1].GetReadFile().Path)
	assert.Equal(t, uint32(10), res[1].GetReadFile().MaxBytes)

	assert.Equal(t, `HKLM\SOFTWARE\Key`, res[2].GetReadRegistry().Key)
	assert.Equal(t, "Name", res[2].GetReadRegistry().Name)

	assert.Equal(t, authv1.DeviceProbe_PlatformIdentifier_HARDWARE_UUID, res[3].GetPlatformIdentifier().Kind)

	assert.Equal(t, 100, probeMaxOutputBytes(probes[0]))
	assert.Equal(t, 10, probeMaxOutputBytes(probes[1]))
	assert.Equal(t, defaultProbeMaxOutputBytes, probeMaxOutputBytes(probes[2]))
	assert.Equal(t, hardProbeMaxOutputBytes, probeMaxOutputBytes(&corev1.ClusterConfig_Status_Device_Probe{
		Type: &corev1.ClusterConfig_Status_Device_Probe_ReadFile_{
			ReadFile: &corev1.ClusterConfig_Status_Device_Probe_ReadFile{
				MaxBytes: 10000000,
			},
		},
	}))
}

func TestRunDeviceProbe(t *testing.T) {
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

	usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)
	assert.NotNil(t, usrT.Session.Status.DeviceRef)

	ctxT := getCtxRT(usrT)

	beginReq := func() *authv1.RunDeviceProbeBeginRequest {
		return &authv1.RunDeviceProbeBeginRequest{}
	}

	begin := func() *authv1.RunDeviceProbeBeginResponse {
		t.Helper()
		resp, err := srv.doRunDeviceProbeBegin(ctxT, beginReq())
		assert.Nil(t, err, "%+v", err)
		return resp
	}

	getProbeIDs := func(resp *authv1.RunDeviceProbeBeginResponse) []string {
		var ret []string
		for _, p := range resp.Probes {
			ret = append(ret, p.ProbeID)
		}
		return ret
	}

	updateCC := func(fn func(cc *corev1.ClusterConfig)) {
		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)
		fn(cc)
		_, err = srv.octeliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	getDevice := func() *corev1.Device {
		dev, err := srv.octeliumC.CoreC().GetDevice(ctx, &rmetav1.GetOptions{
			Uid: usrT.Session.Status.DeviceRef.Uid,
		})
		assert.Nil(t, err)
		return dev
	}

	updateDevice := func(fn func(dev *corev1.Device)) {
		dev := getDevice()
		fn(dev)
		_, err := srv.octeliumC.CoreC().UpdateDevice(ctx, dev)
		assert.Nil(t, err)
	}

	clearAttempt := func() {
		updateDevice(func(dev *corev1.Device) {
			dev.Status.ProbeAttempt = nil
		})
	}

	{
		resp := begin()
		assert.Equal(t, "", resp.AttemptUID, "a Cluster without probes must not issue an attempt")
		assert.Equal(t, 0, len(resp.Probes))
	}

	ownerRef := func(name string) *metav1.ObjectReference {
		return &metav1.ObjectReference{
			Name: name,
			Uid:  fmt.Sprintf("%s-uid", name),
		}
	}

	runCommand := &corev1.ClusterConfig_Status_Device_Probe_RunCommand_{
		RunCommand: &corev1.ClusterConfig_Status_Device_Probe_RunCommand{
			Command:        "/usr/bin/true",
			MaxOutputBytes: 16,
		},
	}

	platformIdentifier := &corev1.ClusterConfig_Status_Device_Probe_PlatformIdentifier_{
		PlatformIdentifier: &corev1.ClusterConfig_Status_Device_Probe_PlatformIdentifier{
			Kind: corev1.ClusterConfig_Status_Device_Probe_PlatformIdentifier_HARDWARE_UUID,
		},
	}

	updateCC(func(cc *corev1.ClusterConfig) {
		cc.Status.Device = &corev1.ClusterConfig_Status_Device{
			Probes: []*corev1.ClusterConfig_Status_Device_Probe{
				{
					Id:       "dm1-cmd",
					OwnerRef: ownerRef("dm1"),
					OsTypes:  []corev1.Device_Status_OSType{corev1.Device_Status_LINUX},
					Type:     runCommand,
				},
				{
					Id:       "dm1-cond-false",
					OwnerRef: ownerRef("dm1"),
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `1 == 2`,
						},
					},
					Type: runCommand,
				},
				{
					Id:       "dm1-cond-true",
					OwnerRef: ownerRef("dm1"),
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: fmt.Sprintf(`ctx.user.metadata.name == "%s" && ctx.device.status.osType == "LINUX"`,
								usrT.Usr.Metadata.Name),
						},
					},
					Type: runCommand,
				},
				{
					Id:       "dm1-cond-session",
					OwnerRef: ownerRef("dm1"),
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `ctx.session.metadata.name != ""`,
						},
					},
					Type: runCommand,
				},
				{
					Id:       "dm1-windows",
					OwnerRef: ownerRef("dm1"),
					OsTypes:  []corev1.Device_Status_OSType{corev1.Device_Status_WINDOWS},
					Type:     runCommand,
				},
				{
					Id:       "dm1-registry",
					OwnerRef: ownerRef("dm1"),
					OsTypes:  []corev1.Device_Status_OSType{corev1.Device_Status_WINDOWS},
					Type: &corev1.ClusterConfig_Status_Device_Probe_ReadRegistry_{
						ReadRegistry: &corev1.ClusterConfig_Status_Device_Probe_ReadRegistry{
							Key:  `HKLM\SOFTWARE\Key`,
							Name: "Name",
						},
					},
				},
				{
					Id:       "dm1-cmd",
					OwnerRef: ownerRef("dm1"),
					Type:     runCommand,
				},
				{
					OwnerRef: ownerRef("dm1"),
					Type:     runCommand,
				},
				{
					Id:   "no-owner",
					Type: runCommand,
				},
				{
					Id:       "dm1-empty",
					OwnerRef: ownerRef("dm1"),
				},
				{
					Id:       "dm2-id",
					OwnerRef: ownerRef("dm2"),
					Type:     platformIdentifier,
				},
				{
					Id:       "dm2-file",
					OwnerRef: ownerRef("dm2"),
					Type: &corev1.ClusterConfig_Status_Device_Probe_ReadFile_{
						ReadFile: &corev1.ClusterConfig_Status_Device_Probe_ReadFile{
							Path:     "/etc/machine-id",
							MaxBytes: 64,
						},
					},
				},
			},
		}
	})

	var attemptUID string

	{
		resp := begin()
		assert.True(t, rgxProbeAttemptUID.MatchString(resp.AttemptUID))
		assert.Equal(t, []string{"dm1-cmd", "dm1-cond-true", "dm2-id", "dm2-file"}, getProbeIDs(resp),
			"an unbound Device must be issued the probes of every DeviceManager")
		assert.Equal(t, "/usr/bin/true", resp.Probes[0].GetRunCommand().Command)
		assert.Equal(t, authv1.DeviceProbe_PlatformIdentifier_HARDWARE_UUID,
			resp.Probes[2].GetPlatformIdentifier().Kind)

		attemptUID = resp.AttemptUID

		attempt := getDevice().Status.ProbeAttempt
		assert.Equal(t, attemptUID, attempt.Uid)
		assert.Equal(t, corev1.Device_Status_ProbeAttempt_ISSUED, attempt.State)
		assert.Equal(t, usrT.Session.Metadata.Uid, attempt.SessionRef.Uid)
		assert.True(t, attempt.ExpiresAt.IsValid())
		assert.Equal(t, 4, len(attempt.Probes))
		for _, p := range attempt.Probes {
			assert.Nil(t, p.Condition)
		}
	}

	{
		resp := begin()
		assert.Equal(t, attemptUID, resp.AttemptUID, "an issued attempt of the same Session must be resumed")
		assert.Equal(t, []string{"dm1-cmd", "dm1-cond-true", "dm2-id", "dm2-file"}, getProbeIDs(resp))
	}

	getResults := func() []*authv1.DeviceProbeResult {
		return []*authv1.DeviceProbeResult{
			{
				ProbeID: "dm1-cmd",
				Status:  authv1.DeviceProbeResult_OK,
				Value: &authv1.DeviceProbeResult_Text{
					Text: "output",
				},
			},
			{
				ProbeID:  "dm1-cond-true",
				Status:   authv1.DeviceProbeResult_FAILED,
				ExitCode: 1,
				Detail:   "exit status 1",
			},
			{
				ProbeID: "dm2-id",
				Status:  authv1.DeviceProbeResult_OK,
				Value: &authv1.DeviceProbeResult_Text{
					Text: "4c4c4544-0042-3510-8044-b4c04f4a4d32",
				},
			},
			{
				ProbeID: "dm2-file",
				Status:  authv1.DeviceProbeResult_NOT_FOUND,
			},
		}
	}

	{
		invalid := []*authv1.RunDeviceProbeFinishRequest{
			{
				AttemptUID: utilrand.GetRandomStringCanonical(32),
				Results:    getResults(),
			},
			{
				AttemptUID: attemptUID,
				Results:    getResults()[:3],
			},
			{
				AttemptUID: attemptUID,
				Results: func() []*authv1.DeviceProbeResult {
					ret := getResults()
					ret[3].ProbeID = "dm1-registry"
					return ret
				}(),
			},
			{
				AttemptUID: attemptUID,
				Results: func() []*authv1.DeviceProbeResult {
					ret := getResults()
					ret[3].ProbeID = "dm1-cmd"
					return ret
				}(),
			},
			{
				AttemptUID: attemptUID,
				Results: func() []*authv1.DeviceProbeResult {
					ret := getResults()
					ret[0].Value = &authv1.DeviceProbeResult_Text{
						Text: strings.Repeat("a", 17),
					}
					return ret
				}(),
			},
		}

		for i, req := range invalid {
			_, err := srv.doRunDeviceProbeFinish(ctxT, req)
			assert.NotNil(t, err, "invalid request: %d", i)
		}

		assert.Equal(t, corev1.Device_Status_ProbeAttempt_ISSUED, getDevice().Status.ProbeAttempt.State)
	}

	{
		_, err := srv.doRunDeviceProbeFinish(ctxT, &authv1.RunDeviceProbeFinishRequest{
			AttemptUID: attemptUID,
			Results:    getResults(),
		})
		assert.Nil(t, err, "%+v", err)

		attempt := getDevice().Status.ProbeAttempt
		assert.Equal(t, corev1.Device_Status_ProbeAttempt_SUBMITTED, attempt.State)
		assert.True(t, attempt.SubmittedAt.IsValid())
		assert.Equal(t, 4, len(attempt.Results))
		assert.Equal(t, "output", attempt.Results[0].GetText())
		assert.Equal(t, corev1.Device_Status_ProbeAttempt_Result_FAILED, attempt.Results[1].Status)
		assert.Equal(t, int32(1), attempt.Results[1].ExitCode)
		assert.Equal(t, "exit status 1", attempt.Results[1].Detail)

		_, err = srv.doRunDeviceProbeFinish(ctxT, &authv1.RunDeviceProbeFinishRequest{
			AttemptUID: attemptUID,
			Results:    getResults(),
		})
		assert.Nil(t, err, "an identical retry must be idempotent: %+v", err)

		changed := getResults()
		changed[0].Value = &authv1.DeviceProbeResult_Text{Text: "changed"}
		_, err = srv.doRunDeviceProbeFinish(ctxT, &authv1.RunDeviceProbeFinishRequest{
			AttemptUID: attemptUID,
			Results:    changed,
		})
		assert.NotNil(t, err)

		reordered := getResults()
		reordered[0], reordered[1] = reordered[1], reordered[0]
		_, err = srv.doRunDeviceProbeFinish(ctxT, &authv1.RunDeviceProbeFinishRequest{
			AttemptUID: attemptUID,
			Results:    reordered,
		})
		assert.Nil(t, err, "a reordered identical retry must be idempotent: %+v", err)

		assert.Equal(t, "output", getDevice().Status.ProbeAttempt.Results[0].GetText())
	}

	{
		resp := begin()
		assert.Equal(t, "", resp.AttemptUID, "submitted results must be processed before a new attempt")
		assert.Equal(t, 0, len(resp.Probes))
	}

	{
		updateDevice(func(dev *corev1.Device) {
			dev.Status.ProbeAttempt.State = corev1.Device_Status_ProbeAttempt_PROCESSED
			dev.Status.Binding = &corev1.Device_Status_Binding{
				Uid:      "binding",
				OwnerRef: ownerRef("dm2"),
				State:    corev1.Device_Status_Binding_ACCEPTED,
				Validity: corev1.Device_Status_Binding_VALID,
			}
		})

		_, err := srv.doRunDeviceProbeFinish(ctxT, &authv1.RunDeviceProbeFinishRequest{
			AttemptUID: attemptUID,
			Results:    getResults(),
		})
		assert.Nil(t, err, "an identical retry of a processed attempt must be idempotent: %+v", err)

		resp := begin()
		assert.Equal(t, "", resp.AttemptUID, "a valid Binding must not be probed")

		updateDevice(func(dev *corev1.Device) {
			dev.Status.Binding.NextVerificationAt = pbutils.Timestamp(time.Now().Add(-time.Second))
		})

		resp = begin()
		assert.Equal(t, []string{"dm2-id", "dm2-file"}, getProbeIDs(resp),
			"verifying a Binding must only probe its DeviceManager")

		clearAttempt()
		updateDevice(func(dev *corev1.Device) {
			dev.Status.Binding.NextVerificationAt = nil
			dev.Status.Binding.Validity = corev1.Device_Status_Binding_SUSPENDED
		})

		resp = begin()
		assert.Equal(t, []string{"dm2-id", "dm2-file"}, getProbeIDs(resp))

		clearAttempt()
		updateDevice(func(dev *corev1.Device) {
			dev.Status.Binding.State = corev1.Device_Status_Binding_AMBIGUOUS
			dev.Status.Binding.Validity = corev1.Device_Status_Binding_VALIDITY_UNKNOWN
		})

		resp = begin()
		assert.Equal(t, []string{"dm1-cmd", "dm1-cond-true", "dm2-id", "dm2-file"}, getProbeIDs(resp))

		clearAttempt()
		updateDevice(func(dev *corev1.Device) {
			dev.Status.Binding = nil
		})
	}

	{
		resp := begin()
		assert.NotEqual(t, "", resp.AttemptUID)
		assert.NotEqual(t, attemptUID, resp.AttemptUID)

		_, err = srv.doRunDeviceProbeFinish(ctxT, &authv1.RunDeviceProbeFinishRequest{
			AttemptUID: attemptUID,
			Results:    getResults(),
		})
		assert.NotNil(t, err, "the results of a replaced attempt must be rejected")

		_, err = srv.doRunDeviceProbeFinish(ctxT, &authv1.RunDeviceProbeFinishRequest{
			AttemptUID: resp.AttemptUID,
			Results:    getResults(),
		})
		assert.Nil(t, err, "%+v", err)

		attempt := getDevice().Status.ProbeAttempt
		assert.Equal(t, resp.AttemptUID, attempt.Uid)
		assert.Equal(t, corev1.Device_Status_ProbeAttempt_SUBMITTED, attempt.State)
	}

	{
		clearAttempt()

		resp := begin()

		updateDevice(func(dev *corev1.Device) {
			dev.Status.ProbeAttempt.SessionRef = &metav1.ObjectReference{
				Uid: "other-session",
			}
		})

		_, err := srv.doRunDeviceProbeFinish(ctxT, &authv1.RunDeviceProbeFinishRequest{
			AttemptUID: resp.AttemptUID,
			Results:    getResults(),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err))

		next := begin()
		assert.NotEqual(t, "", next.AttemptUID)
		assert.NotEqual(t, resp.AttemptUID, next.AttemptUID,
			"an attempt of another Session must not be resumed")
	}

	{
		clearAttempt()

		resp := begin()

		updateDevice(func(dev *corev1.Device) {
			dev.Status.ProbeAttempt.ExpiresAt = pbutils.Timestamp(time.Now().Add(-time.Second))
		})

		_, err := srv.doRunDeviceProbeFinish(ctxT, &authv1.RunDeviceProbeFinishRequest{
			AttemptUID: resp.AttemptUID,
			Results:    getResults(),
		})
		assert.NotNil(t, err)
		assert.Nil(t, getDevice().Status.ProbeAttempt)
	}

	{
		updateCC(func(cc *corev1.ClusterConfig) {
			cc.Spec.Device = &corev1.ClusterConfig_Spec_Device{
				Probing: &corev1.ClusterConfig_Spec_Device_Probing{
					IsDisabled: true,
				},
			}
		})

		resp := begin()
		assert.Equal(t, "", resp.AttemptUID)
		assert.Nil(t, getDevice().Status.ProbeAttempt)

		updateCC(func(cc *corev1.ClusterConfig) {
			cc.Spec.Device.Probing.IsDisabled = false
		})
	}

	{
		updateDevice(func(dev *corev1.Device) {
			dev.Status.IsLocked = true
		})

		_, err := srv.doRunDeviceProbeBegin(ctxT, beginReq())
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err))

		updateDevice(func(dev *corev1.Device) {
			dev.Status.IsLocked = false
			dev.Spec.State = corev1.Device_Spec_REJECTED
		})

		_, err = srv.doRunDeviceProbeBegin(ctxT, beginReq())
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err))

		updateDevice(func(dev *corev1.Device) {
			dev.Spec.State = corev1.Device_Spec_PENDING
		})

		resp := begin()
		assert.NotEqual(t, "", resp.AttemptUID)
	}

	{
		sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: usrT.Session.Metadata.Uid,
		})
		assert.Nil(t, err)
		sess.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATION_REQUIRED
		_, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		_, err = srv.doRunDeviceProbeBegin(ctxT, beginReq())
		assert.NotNil(t, err, "a Session pending an authenticator authentication must not probe")

		_, err = srv.doRunDeviceProbeFinish(ctxT, &authv1.RunDeviceProbeFinishRequest{
			AttemptUID: getDevice().Status.ProbeAttempt.Uid,
			Results:    getResults(),
		})
		assert.NotNil(t, err)
	}
}

func TestGetProbeAttemptResults(t *testing.T) {
	attempt := &corev1.Device_Status_ProbeAttempt{
		Probes: []*corev1.ClusterConfig_Status_Device_Probe{
			{
				Id: "p1",
				Type: &corev1.ClusterConfig_Status_Device_Probe_ReadFile_{
					ReadFile: &corev1.ClusterConfig_Status_Device_Probe_ReadFile{
						MaxBytes: 4,
					},
				},
			},
			{
				Id: "p2",
				Type: &corev1.ClusterConfig_Status_Device_Probe_PlatformIdentifier_{
					PlatformIdentifier: &corev1.ClusterConfig_Status_Device_Probe_PlatformIdentifier{
						Kind: corev1.ClusterConfig_Status_Device_Probe_PlatformIdentifier_MAC_ADDRESS,
					},
				},
			},
		},
	}

	{
		res, err := getProbeAttemptResults(attempt, []*authv1.DeviceProbeResult{
			{
				ProbeID: "p1",
				Status:  authv1.DeviceProbeResult_OK,
				Value: &authv1.DeviceProbeResult_Data{
					Data: []byte("abcd"),
				},
				IsTruncated: true,
			},
			{
				ProbeID: "p2",
				Status:  authv1.DeviceProbeResult_OK,
				Value: &authv1.DeviceProbeResult_List_{
					List: &authv1.DeviceProbeResult_List{
						Items: []string{"00:11:22:33:44:55"},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, 2, len(res))
		assert.Equal(t, []byte("abcd"), res[0].GetData())
		assert.True(t, res[0].IsTruncated)
		assert.Equal(t, []string{"00:11:22:33:44:55"}, res[1].GetList().Items)
	}

	{
		_, err := getProbeAttemptResults(attempt, []*authv1.DeviceProbeResult{
			{
				ProbeID: "p1",
				Status:  authv1.DeviceProbeResult_OK,
				Value: &authv1.DeviceProbeResult_Data{
					Data: []byte("abcde"),
				},
			},
			{
				ProbeID: "p2",
				Status:  authv1.DeviceProbeResult_NOT_FOUND,
			},
		})
		assert.NotNil(t, err)
	}

	{
		big := &corev1.Device_Status_ProbeAttempt{}
		var results []*authv1.DeviceProbeResult
		for i := range 3 {
			id := fmt.Sprintf("p%d", i)
			big.Probes = append(big.Probes, &corev1.ClusterConfig_Status_Device_Probe{
				Id: id,
				Type: &corev1.ClusterConfig_Status_Device_Probe_ReadFile_{
					ReadFile: &corev1.ClusterConfig_Status_Device_Probe_ReadFile{
						MaxBytes: hardProbeMaxOutputBytes,
					},
				},
			})
			results = append(results, &authv1.DeviceProbeResult{
				ProbeID: id,
				Status:  authv1.DeviceProbeResult_OK,
				Value: &authv1.DeviceProbeResult_Data{
					Data: make([]byte, 60000),
				},
			})
		}

		_, err := getProbeAttemptResults(big, results)
		assert.NotNil(t, err, "the total output must not exceed the attempt limit")

		_, err = getProbeAttemptResults(big, results[:2])
		assert.NotNil(t, err)

		big.Probes = big.Probes[:2]
		_, err = getProbeAttemptResults(big, results[:2])
		assert.Nil(t, err)
	}

	{
		dflt := &corev1.Device_Status_ProbeAttempt{
			Probes: []*corev1.ClusterConfig_Status_Device_Probe{
				{
					Id: "p1",
					Type: &corev1.ClusterConfig_Status_Device_Probe_RunCommand_{
						RunCommand: &corev1.ClusterConfig_Status_Device_Probe_RunCommand{
							Command: "/usr/bin/true",
						},
					},
				},
			},
		}

		_, err := getProbeAttemptResults(dflt, []*authv1.DeviceProbeResult{
			{
				ProbeID: "p1",
				Status:  authv1.DeviceProbeResult_OK,
				Value: &authv1.DeviceProbeResult_Text{
					Text: strings.Repeat("a", defaultProbeMaxOutputBytes),
				},
			},
		})
		assert.Nil(t, err)

		_, err = getProbeAttemptResults(dflt, []*authv1.DeviceProbeResult{
			{
				ProbeID: "p1",
				Status:  authv1.DeviceProbeResult_OK,
				Value: &authv1.DeviceProbeResult_Text{
					Text: strings.Repeat("a", defaultProbeMaxOutputBytes+1),
				},
			},
		})
		assert.NotNil(t, err)
	}
}

func TestDeviceEnumsMatch(t *testing.T) {
	assert.Equal(t, authv1.DeviceProbeResult_Status_name,
		corev1.Device_Status_ProbeAttempt_Result_Status_name)
	assert.Equal(t, authv1.DeviceProbe_PlatformIdentifier_Kind_name,
		corev1.ClusterConfig_Status_Device_Probe_PlatformIdentifier_Kind_name)
	assert.Equal(t, authv1.RegisterDeviceRequest_Info_OSType_name,
		corev1.Device_Status_OSType_name)
}

func TestIsProbeAttemptResultsEqual(t *testing.T) {
	getResults := func() []*corev1.Device_Status_ProbeAttempt_Result {
		return []*corev1.Device_Status_ProbeAttempt_Result{
			{
				ProbeID: "p1",
				Status:  corev1.Device_Status_ProbeAttempt_Result_OK,
				Value: &corev1.Device_Status_ProbeAttempt_Result_Text{
					Text: "output",
				},
			},
			{
				ProbeID:  "p2",
				Status:   corev1.Device_Status_ProbeAttempt_Result_FAILED,
				ExitCode: 1,
			},
		}
	}

	assert.True(t, isProbeAttemptResultsEqual(nil, nil))
	assert.True(t, isProbeAttemptResultsEqual(getResults(), getResults()))

	{
		reordered := getResults()
		reordered[0], reordered[1] = reordered[1], reordered[0]
		assert.True(t, isProbeAttemptResultsEqual(getResults(), reordered))
	}

	assert.False(t, isProbeAttemptResultsEqual(getResults(), getResults()[:1]))
	assert.False(t, isProbeAttemptResultsEqual(nil, getResults()))

	{
		changed := getResults()
		changed[0].Value = &corev1.Device_Status_ProbeAttempt_Result_Data{
			Data: []byte("output"),
		}
		assert.False(t, isProbeAttemptResultsEqual(getResults(), changed))
	}

	{
		changed := getResults()
		changed[1].ExitCode = 2
		assert.False(t, isProbeAttemptResultsEqual(getResults(), changed))
	}

	{
		changed := getResults()
		changed[1].ProbeID = "p3"
		assert.False(t, isProbeAttemptResultsEqual(getResults(), changed))
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
			Info: &authv1.RegisterDeviceRequest_Info{
				Id:           fmt.Sprintf("%x", sha256.Sum256([]byte(utilrand.GetRandomBytesMust(32)))),
				SerialNumber: utilrand.GetRandomString(12),
				Hostname:     utilrand.GetRandomString(6),
				OsType:       authv1.RegisterDeviceRequest_Info_LINUX,
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
