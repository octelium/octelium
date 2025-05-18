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

package quicv0

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/quicv0"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/gwagent/gwagent/gw"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	osuser "os/user"
)

func fakeNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: name,
			UID:  types.UID(vutils.UUIDv4()),
		},

		Spec: corev1.NodeSpec{},

		Status: corev1.NodeStatus{},
	}
}

func TestController(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		usr, err := osuser.Current()
		assert.Nil(t, err)
		if usr.Uid != "0" {
			zap.L().Warn("Skipping this test since the running user is not root")
			return
		}
	}

	node, err := fakeC.K8sC.CoreV1().Nodes().Create(ctx, fakeNode("node"), k8smetav1.CreateOptions{})
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	privateKey, err := wgtypes.GeneratePrivateKey()
	assert.Nil(t, err)
	err = gw.InitGateway(context.Background(), []string{"1.2.3.4"}, node, fakeC.OcteliumC, 0, &metav1.ObjectReference{
		Name: "default",
		Uid:  vutils.UUIDv4(),
	}, privateKey)
	assert.NotNil(t, err, "%+v", err)

	ctl, err := New(ctx, tst.C.OcteliumC, k8sutils.GetGatewayName(node))
	assert.Nil(t, err)

	cert, err := ctl.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: vutils.ClusterCertSecretName})
	assert.Nil(t, err)

	err = ctl.SetClusterCertificate(cert)
	assert.Nil(t, err)

	err = ctl.Run(ctx)
	assert.Nil(t, err)

	quicCfg := &quic.Config{
		EnableDatagrams: true,
		Versions:        []quic.Version{quic.Version1, quic.Version2},
		KeepAlivePeriod: 30 * time.Second,
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: true,
	}

	{

		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		err = usr.ConnectQUIC0()
		assert.Nil(t, err)

		conn, err := quic.DialAddr(ctx, "localhost:8443", tlsCfg, quicCfg)
		assert.Nil(t, err)

		err = conn.SendDatagram(utilrand.GetRandomBytesMust(60))
		assert.Nil(t, err)

		strm, err := conn.OpenStreamSync(ctx)
		assert.Nil(t, err)

		err = conn.SendDatagram(utilrand.GetRandomBytesMust(60))
		assert.Nil(t, err)

		reqMsg := &quicv0.InitRequest{
			AccessToken: string(usr.GetAccessToken().AccessToken),
		}
		reqMsgBytes, err := encodeMsg(reqMsg, 1)
		assert.Nil(t, err)

		_, err = strm.Write(reqMsgBytes)
		assert.Nil(t, err)

		payload, typ, err := decodeMsg(strm)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, typ, uint32(1))

		respMsg := &quicv0.InitResponse{}
		err = pbutils.Unmarshal(payload, respMsg)
		assert.Nil(t, err)

		assert.Equal(t, quicv0.InitResponse_OK, respMsg.Type)
		err = strm.Close()
		assert.Nil(t, err)

		err = strm.Close()
		assert.Nil(t, err)

		err = conn.SendDatagram(utilrand.GetRandomBytesMust(60))
		assert.Nil(t, err)

		err = conn.SendDatagram(nil)
		assert.Nil(t, err)

		err = conn.SendDatagram(utilrand.GetRandomBytesMust(3))
		assert.Nil(t, err)
	}

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		err = usr.ConnectQUIC0()
		assert.Nil(t, err)

		conn, err := quic.DialAddr(ctx, "localhost:8443", tlsCfg, quicCfg)
		assert.Nil(t, err)

		err = conn.SendDatagram(utilrand.GetRandomBytesMust(60))
		assert.Nil(t, err)

		strm, err := conn.OpenStreamSync(ctx)
		assert.Nil(t, err)

		err = conn.SendDatagram(utilrand.GetRandomBytesMust(60))
		assert.Nil(t, err)

		reqMsg := &quicv0.InitRequest{
			AccessToken: string(usr.GetAccessToken().AccessToken),
		}
		reqMsgBytes, err := encodeMsg(reqMsg, 1)
		assert.Nil(t, err)

		_, err = strm.Write(reqMsgBytes[:10])
		assert.Nil(t, err)

		time.Sleep(500 * time.Millisecond)
		_, err = strm.Write(reqMsgBytes[10:])
		assert.Nil(t, err)

		payload, typ, err := decodeMsg(strm)
		assert.Nil(t, err)
		assert.Equal(t, typ, uint32(1))

		respMsg := &quicv0.InitResponse{}
		err = pbutils.Unmarshal(payload, respMsg)
		assert.Nil(t, err)

		assert.Equal(t, quicv0.InitResponse_OK, respMsg.Type)
		err = strm.Close()
		assert.Nil(t, err)

		err = strm.Close()
		assert.Nil(t, err)

		err = conn.SendDatagram(utilrand.GetRandomBytesMust(60))
		assert.Nil(t, err)

		err = conn.SendDatagram(nil)
		assert.Nil(t, err)

		err = conn.SendDatagram(utilrand.GetRandomBytesMust(3))
		assert.Nil(t, err)
	}

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		err = usr.ConnectQUIC0()
		assert.Nil(t, err)

		conn, err := quic.DialAddr(ctx, "localhost:8443", tlsCfg, quicCfg)
		assert.Nil(t, err)

		err = conn.SendDatagram(utilrand.GetRandomBytesMust(60))
		assert.Nil(t, err)

		strm, err := conn.OpenStreamSync(ctx)
		assert.Nil(t, err)

		err = conn.SendDatagram(utilrand.GetRandomBytesMust(60))
		assert.Nil(t, err)

		reqMsg := &quicv0.InitRequest{
			AccessToken: string(usr.GetAccessToken().AccessToken),
		}
		reqMsgBytes, err := encodeMsg(reqMsg, 1)
		assert.Nil(t, err)

		_, err = strm.Write(reqMsgBytes[:10])
		assert.Nil(t, err)

		time.Sleep(1500 * time.Millisecond)
		_, err = strm.Write(reqMsgBytes[10:20])
		assert.Nil(t, err)

		time.Sleep(1500 * time.Millisecond)
		_, err = strm.Write(reqMsgBytes[20:30])
		assert.Nil(t, err)

		// 4-second deadline is now exceeded
		time.Sleep(1500 * time.Millisecond)
		_, err = strm.Write(reqMsgBytes[30:40])
		assert.NotNil(t, err)

	}

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		err = usr.ConnectQUIC0()
		assert.Nil(t, err)

		conn, err := quic.DialAddr(ctx, "localhost:8443", tlsCfg, quicCfg)
		assert.Nil(t, err)

		err = conn.SendDatagram(utilrand.GetRandomBytesMust(60))
		assert.Nil(t, err)

		strm, err := conn.OpenStreamSync(ctx)
		assert.Nil(t, err)

		err = conn.SendDatagram(utilrand.GetRandomBytesMust(60))
		assert.Nil(t, err)

		reqMsg := &quicv0.InitRequest{
			AccessToken: string(usr.GetAccessToken().AccessToken),
		}
		reqMsgBytes, err := encodeMsg(reqMsg, 1)
		assert.Nil(t, err)

		strm.Write(reqMsgBytes[:6])

		buf := make([]byte, 1024)
		_, err = strm.Read(buf)
		assert.NotNil(t, err)

		zap.L().Debug("err", zap.Error(err))
	}

	time.Sleep(3 * time.Second)
	err = ctl.Close()
	assert.Nil(t, err)
}
