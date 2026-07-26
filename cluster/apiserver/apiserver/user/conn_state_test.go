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

package user

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/sshutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestGetConnectionState(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	octeliumC := tst.C.OcteliumC

	cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	{
		sess := usrT.Session
		sess.Status.Connection = &corev1.Session_Status_Connection{}

		privateKey, err := wgtypes.GeneratePrivateKey()
		assert.Nil(t, err)

		_, ed25519Priv, err := ed25519.GenerateKey(nil)
		assert.Nil(t, err)

		resp, err := getConnectionState(ctx, tst.C.OcteliumC, sess, cc, privateKey, ed25519Priv)
		assert.Nil(t, err)

		zap.L().Debug("resp", zap.Any("resp", resp))
	}

}

func newConnStateKeys(t *testing.T) (wgtypes.Key, ed25519.PrivateKey) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	assert.Nil(t, err, "%+v", err)

	_, ed25519Priv, err := ed25519.GenerateKey(nil)
	assert.Nil(t, err, "%+v", err)

	return privateKey, ed25519Priv
}

func TestGetConnectionStateNilConnection(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err, "%+v", err)

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err, "%+v", err)

	privateKey, ed25519Priv := newConnStateKeys(t)

	{
		sess := usrT.Session
		sess.Status.Connection = nil

		_, err = getConnectionState(ctx, tst.C.OcteliumC, sess, cc, privateKey, ed25519Priv)
		assert.NotNil(t, err)
	}

	{
		sess := usrT.Session
		sess.Status = nil

		_, err = getConnectionState(ctx, tst.C.OcteliumC, sess, cc, privateKey, ed25519Priv)
		assert.NotNil(t, err)
	}
}

func TestGetConnectionStateContent(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err, "%+v", err)

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err, "%+v", err)

	privateKey, ed25519Priv := newConnStateKeys(t)

	sess := usrT.Session
	sess.Status.Connection = &corev1.Session_Status_Connection{
		L3Mode: corev1.Session_Status_Connection_BOTH,
	}

	resp, err := getConnectionState(ctx, tst.C.OcteliumC, sess, cc, privateKey, ed25519Priv)
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, resp.CreatedAt)

	state := resp.GetState()
	assert.NotNil(t, state)

	assert.Equal(t, privateKey[:], state.X25519Key)
	assert.Equal(t, []byte(ed25519Priv), state.Ed25519Key)
	assert.True(t, state.Mtu > 0)
	assert.NotNil(t, state.Cidr)
	assert.NotNil(t, state.Dns)
	assert.True(t, len(state.Dns.Servers) > 0)
	assert.Equal(t, userv1.ConnectionState_BOTH, state.L3Mode)
	assert.NotNil(t, state.Gateways)
	assert.Nil(t, state.ServiceOptions)

	assert.Equal(t, 1, len(state.ServiceConfigs))
	sshCfg := state.ServiceConfigs[0].GetSsh()
	assert.NotNil(t, sshCfg)
	assert.Equal(t, 1, len(sshCfg.KnownHosts))
	assert.Equal(t, 1, len(sshCfg.AuthorizedKeys))
	assert.True(t, strings.HasPrefix(sshCfg.KnownHosts[0], "@cert-authority "))
	assert.True(t, strings.HasPrefix(sshCfg.AuthorizedKeys[0], "cert-authority "))
}

func TestGetConnectionStateL3Mode(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err, "%+v", err)

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err, "%+v", err)

	privateKey, ed25519Priv := newConnStateKeys(t)

	tcs := []struct {
		mode     corev1.Session_Status_Connection_L3Mode
		expected userv1.ConnectionState_L3Mode
	}{
		{
			mode:     corev1.Session_Status_Connection_BOTH,
			expected: userv1.ConnectionState_BOTH,
		},
		{
			mode:     corev1.Session_Status_Connection_V4,
			expected: userv1.ConnectionState_V4,
		},
		{
			mode:     corev1.Session_Status_Connection_V6,
			expected: userv1.ConnectionState_V6,
		},
	}

	for _, tc := range tcs {
		sess := usrT.Session
		sess.Status.Connection = &corev1.Session_Status_Connection{
			L3Mode: tc.mode,
		}

		resp, err := getConnectionState(ctx, tst.C.OcteliumC, sess, cc, privateKey, ed25519Priv)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, tc.expected, resp.GetState().L3Mode)
	}
}

func TestGetConnectionStateMTU(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err, "%+v", err)

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err, "%+v", err)

	privateKey, ed25519Priv := newConnStateKeys(t)

	types := []corev1.Session_Status_Connection_Type{
		corev1.Session_Status_Connection_WIREGUARD,
		corev1.Session_Status_Connection_QUICV0,
		corev1.Session_Status_Connection_TYPE_UNKNOWN,
	}

	for _, typ := range types {
		sess := usrT.Session
		sess.Status.Connection = &corev1.Session_Status_Connection{
			Type: typ,
		}

		resp, err := getConnectionState(ctx, tst.C.OcteliumC, sess, cc, privateKey, ed25519Priv)
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.GetState().Mtu >= 1280, "%d", resp.GetState().Mtu)
	}
}

func TestGetConnectionStateAddresses(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err, "%+v", err)

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err, "%+v", err)

	_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
	assert.Nil(t, err, "%+v", err)

	usrT.Resync()

	privateKey, ed25519Priv := newConnStateKeys(t)

	resp, err := getConnectionState(ctx, tst.C.OcteliumC, usrT.Session, cc, privateKey, ed25519Priv)
	assert.Nil(t, err, "%+v", err)

	state := resp.GetState()
	assert.True(t, len(state.Addresses) > 0)
	for _, addr := range state.Addresses {
		assert.True(t, addr.V4 != "" || addr.V6 != "")
	}
}

func TestGetAuthorizedKeyCALine(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	ca, err := sshutils.GetCAPublicKey(ctx, tst.C.OcteliumC)
	assert.Nil(t, err, "%+v", err)

	line := getAuthorizedKeyCALine(ca)

	args := strings.Split(line, " ")
	assert.Equal(t, 3, len(args))
	assert.Equal(t, "cert-authority", args[0])
	assert.Equal(t, ca.Type(), args[1])
	assert.NotEmpty(t, args[2])
}
