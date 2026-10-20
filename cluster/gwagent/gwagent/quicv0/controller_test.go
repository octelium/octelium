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
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	maincorev1 "github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/quicv0"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/jwkctl"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/gwagent/gwagent/gw"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func newTstQUICCertificate(t *testing.T) *maincorev1.Secret {
	t.Helper()
	crt, err := utils_cert.GenerateSelfSignedCert("localhost", []string{"localhost"}, time.Hour)
	require.Nil(t, err)
	chain, err := utils_cert.GetCertificatePEMStr(crt.Certificate)
	require.Nil(t, err)
	key, err := utils_cert.GetPrivateKeyPEM(crt.PrivateKey)
	require.Nil(t, err)
	ret := &maincorev1.Secret{
		Metadata: &metav1.Metadata{Name: vutils.ClusterCertSecretName},
		Spec:     &maincorev1.Secret_Spec{},
		Status:   &maincorev1.Secret_Status{},
	}
	ucorev1.ToSecret(ret).SetCertificate(chain, string(key))
	return ret
}

func newTstQUICPair(t *testing.T) (*quic.Conn, *quic.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	secret := newTstQUICCertificate(t)
	chain, key, err := ucorev1.ToSecret(secret).GetCertificateChainAndKey()
	require.Nil(t, err)
	crt, err := tls.X509KeyPair(chain, key)
	require.Nil(t, err)
	lis, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{crt}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13,
	}, &quic.Config{EnableDatagrams: true})
	require.Nil(t, err)
	t.Cleanup(func() {
		lis.Close()
	})
	client, err := quic.DialAddr(ctx, lis.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13,
	}, &quic.Config{EnableDatagrams: true})
	require.Nil(t, err)
	t.Cleanup(func() {
		client.CloseWithError(0, "")
	})
	server, err := lis.Accept(ctx)
	require.Nil(t, err)
	t.Cleanup(func() {
		server.CloseWithError(0, "")
	})
	return server, client
}

func newTstQUICStream(t *testing.T, buf []byte) (*quic.Stream, *quic.Stream) {
	t.Helper()
	server, client := newTstQUICPair(t)
	out, err := client.OpenStreamSync(t.Context())
	require.Nil(t, err)
	_, err = out.Write(buf)
	require.Nil(t, err)
	require.Nil(t, out.Close())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	in, err := server.AcceptStream(ctx)
	require.Nil(t, err)
	require.Nil(t, in.SetDeadline(time.Now().Add(5*time.Second)))
	return in, out
}

func TestDecodeMsg(t *testing.T) {
	frame := func(size, typ uint32, payload []byte) []byte {
		buf := make([]byte, hdrSize)
		binary.BigEndian.PutUint32(buf[:4], size)
		binary.BigEndian.PutUint32(buf[4:], typ)
		return append(buf, payload...)
	}
	for _, tc := range []struct {
		name string
		buf  []byte
		err  string
	}{
		{name: "empty", err: "message header"},
		{name: "shortHeader", buf: []byte{0, 0, 0, 1}, err: "message header"},
		{name: "zeroType", buf: frame(1, 0, []byte{1}), err: "Invalid msg type"},
		{name: "zeroSize", buf: frame(0, 1, nil), err: "Invalid payload size"},
		{name: "oversize", buf: frame(4097, 1, nil), err: "Invalid payload size"},
		{name: "sizeOverflow", buf: frame(^uint32(0), 1, nil), err: "Invalid payload size"},
		{name: "missingPayload", buf: frame(4, 1, nil), err: "message payload"},
		{name: "shortPayload", buf: frame(4, 1, []byte{1, 2}), err: "message payload"},
		{name: "minimum", buf: frame(1, 1, []byte{42})},
		{name: "maximum", buf: frame(4096, 99, make([]byte, 4096))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream, _ := newTstQUICStream(t, tc.buf)
			payload, typ, err := decodeMsg(stream)
			if tc.err != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tc.err)
				assert.Nil(t, payload)
				assert.Zero(t, typ)
				return
			}
			require.Nil(t, err)
			assert.Equal(t, tc.buf[hdrSize:], payload)
			assert.Equal(t, binary.BigEndian.Uint32(tc.buf[4:hdrSize]), typ)
		})
	}
}

func TestQUICMessages(t *testing.T) {
	t.Run("roundTrip", func(t *testing.T) {
		req := &quicv0.InitRequest{AccessToken: "token"}
		buf, err := encodeMsg(req, 1)
		require.Nil(t, err)
		in, out := newTstQUICStream(t, buf)
		ctl := &QUICController{}
		payload, err := ctl.getBuf(t.Context(), in, 1)
		require.Nil(t, err)
		decoded := &quicv0.InitRequest{}
		require.Nil(t, pbutils.Unmarshal(payload, decoded))
		assert.True(t, pbutils.IsEqual(req, decoded))
		require.Nil(t, ctl.writeResponse(t.Context(), in,
			&quicv0.InitResponse{Type: quicv0.InitResponse_OK}, 1))
		payload, typ, err := decodeMsg(out)
		require.Nil(t, err)
		assert.Equal(t, uint32(1), typ)
		resp := &quicv0.InitResponse{}
		require.Nil(t, pbutils.Unmarshal(payload, resp))
		assert.Equal(t, quicv0.InitResponse_OK, resp.Type)
		require.Nil(t, in.Close())
		assert.NotNil(t, ctl.writeResponse(t.Context(), in, resp, 1))
	})

	t.Run("wrongType", func(t *testing.T) {
		buf, err := encodeMsg(&quicv0.InitRequest{AccessToken: "token"}, 2)
		require.Nil(t, err)
		in, _ := newTstQUICStream(t, buf)
		payload, err := (&QUICController{}).getBuf(t.Context(), in, 1)
		assert.Nil(t, payload)
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "Invalid msg type")
	})

	t.Run("invalidUTF8", func(t *testing.T) {
		req := &quicv0.InitRequest{AccessToken: string([]byte{0xff})}
		buf, err := encodeMsg(req, 1)
		assert.Nil(t, buf)
		assert.NotNil(t, err)
		assert.NotNil(t, (&QUICController{}).writeResponse(t.Context(), nil, req, 1))
	})
}

type tstQUICClient struct {
	octeliumc.ClientInterface
	core rcorev1.ResourceServiceClient
}

func (c *tstQUICClient) CoreC() rcorev1.ResourceServiceClient {
	return c.core
}

type tstQUICCoreClient struct {
	rcorev1.ResourceServiceClient
	session    *maincorev1.Session
	sessionErr error
	secret     *maincorev1.Secret
	secretErr  error
	getFn      func(*rmetav1.GetOptions)
}

func (c *tstQUICCoreClient) GetSession(ctx context.Context, opts *rmetav1.GetOptions,
	_ ...grpc.CallOption) (*maincorev1.Session, error) {
	if c.getFn != nil {
		c.getFn(opts)
	}
	return c.session, c.sessionErr
}

func (c *tstQUICCoreClient) GetSecret(ctx context.Context, opts *rmetav1.GetOptions,
	_ ...grpc.CallOption) (*maincorev1.Secret, error) {
	if c.getFn != nil {
		c.getFn(opts)
	}
	return c.secret, c.secretErr
}

func newTstQUICSession() *maincorev1.Session {
	return &maincorev1.Session{
		Metadata: &metav1.Metadata{Name: "session", Uid: vutils.UUIDv4()},
		Spec: &maincorev1.Session_Spec{
			State: maincorev1.Session_Spec_ACTIVE,
		},
		Status: &maincorev1.Session_Status{
			Type: maincorev1.Session_Status_CLIENT,
			Authentication: &maincorev1.Session_Status_Authentication{
				TokenID: vutils.UUIDv4(), SetAt: pbutils.Now(),
				AccessTokenDuration: &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 1}},
			},
			Connection: &maincorev1.Session_Status_Connection{
				Type: maincorev1.Session_Status_Connection_QUICV0, StartedAt: pbutils.Now(),
				Addresses: []*metav1.DualStackNetwork{{V4: "100.66.0.10/32", V6: "fdee::2:0:0:10/128"}},
			},
		},
	}
}

func TestQUICInit(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	signer, err := jwkctl.NewJWKController(t.Context(), tst.C.OcteliumC, nil)
	require.Nil(t, err)
	ctl, err := New(t.Context(), tst.C.OcteliumC, "gateway")
	require.Nil(t, err)

	for _, tc := range []struct {
		name      string
		mutate    func(*maincorev1.Session)
		token     string
		err       string
		fetchErr  error
		malformed bool
	}{
		{name: "valid"},
		{name: "emptyToken", token: "empty", err: "Empty token"},
		{name: "invalidToken", token: "invalid", err: "Token"},
		{name: "malformedPayload", malformed: true, err: ""},
		{name: "missingSession", fetchErr: status.Error(codes.NotFound, "missing"), err: "missing"},
		{name: "backendUnavailable", fetchErr: status.Error(codes.Unavailable, "unavailable"), err: "unavailable"},
		{name: "pending", mutate: func(sess *maincorev1.Session) {
			sess.Spec.State = maincorev1.Session_Spec_PENDING
		}, err: "not valid"},
		{name: "expired", mutate: func(sess *maincorev1.Session) {
			sess.Spec.ExpiresAt = pbutils.Timestamp(time.Now().Add(-time.Hour))
		}, err: "not valid"},
		{name: "expiredAuthentication", mutate: func(sess *maincorev1.Session) {
			sess.Status.Authentication.SetAt = pbutils.Timestamp(time.Now().Add(-2 * time.Hour))
		}, err: "not valid"},
		{name: "rotatedToken", mutate: func(sess *maincorev1.Session) {
			sess.Status.Authentication.TokenID = vutils.UUIDv4()
		}, err: "Invalid claims"},
		{name: "nonClient", mutate: func(sess *maincorev1.Session) {
			sess.Status.Type = maincorev1.Session_Status_CLIENTLESS
		}, err: "Not a CLIENT"},
		{name: "disconnected", mutate: func(sess *maincorev1.Session) {
			sess.Status.Connection = nil
		}, err: "not Connected"},
		{name: "wrongTunnel", mutate: func(sess *maincorev1.Session) {
			sess.Status.Connection.Type = maincorev1.Session_Status_Connection_WIREGUARD
		}, err: "Not a QUIC"},
		{name: "locked", mutate: func(sess *maincorev1.Session) {
			sess.Status.IsLocked = true
		}, err: "locked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := newTstQUICSession()
			token, err := signer.CreateAccessToken(sess)
			require.Nil(t, err)
			if tc.mutate != nil {
				tc.mutate(sess)
			}
			if tc.token != "" {
				token = tc.token
				if tc.token == "empty" {
					token = ""
				}
			}
			fetched := false
			ctl.octeliumC = &tstQUICClient{core: &tstQUICCoreClient{
				session: sess, sessionErr: tc.fetchErr,
				getFn: func(opts *rmetav1.GetOptions) {
					fetched = true
					assert.Equal(t, sess.Metadata.Uid, opts.Uid)
					assert.Empty(t, opts.Name)
				},
			}}
			buf, err := encodeMsg(&quicv0.InitRequest{AccessToken: token}, 1)
			require.Nil(t, err)
			if tc.malformed {
				buf = []byte{0, 0, 0, 1, 0, 0, 0, 1, 0xff}
			}
			if tc.token == "empty" {
				buf = []byte{0, 0, 0, 2, 0, 0, 0, 1, 0x0a, 0}
			}
			in, out := newTstQUICStream(t, buf)
			got, err := ctl.doInit(t.Context(), in)
			if tc.name != "valid" {
				require.NotNil(t, err)
				if tc.err != "" {
					assert.Contains(t, err.Error(), tc.err)
				}
				assert.Nil(t, got)
				assert.Equal(t, tc.token == "" && !tc.malformed, fetched)
				return
			}
			require.Nil(t, err)
			assert.True(t, fetched)
			assert.Same(t, sess, got)
			payload, typ, err := decodeMsg(out)
			require.Nil(t, err)
			assert.Equal(t, uint32(1), typ)
			resp := &quicv0.InitResponse{}
			require.Nil(t, pbutils.Unmarshal(payload, resp))
			assert.Equal(t, quicv0.InitResponse_OK, resp.Type)
		})
	}
}

func TestQUICTLSConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "ready"},
		{name: "missing", err: status.Error(codes.NotFound, "missing")},
		{name: "unavailable", err: status.Error(codes.Unavailable, "unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := newTstQUICCertificate(t)
			core := &tstQUICCoreClient{secret: secret, secretErr: tc.err, getFn: func(opts *rmetav1.GetOptions) {
				assert.Equal(t, vutils.ClusterCertSecretName, opts.Name)
			}}
			if tc.err != nil {
				core.secret = nil
			}
			ctl := &QUICController{octeliumC: &tstQUICClient{core: core}}
			cfg, err := ctl.getTLSConfig(t.Context())
			if tc.name == "unavailable" {
				assert.ErrorIs(t, err, tc.err)
				assert.Nil(t, cfg)
				return
			}
			require.Nil(t, err)
			assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
			assert.Equal(t, uint16(tls.VersionTLS13), cfg.MaxVersion)
			assert.Equal(t, []string{"h3"}, cfg.NextProtos)
			crt, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
			if tc.name == "missing" {
				assert.NotNil(t, err)
				assert.Nil(t, crt)
			} else {
				require.Nil(t, err)
				require.NotEmpty(t, crt.Certificate)
			}
			require.Nil(t, ctl.SetClusterCertificate(secret))
			_, err = cfg.GetCertificate(&tls.ClientHelloInfo{})
			assert.Nil(t, err)
			require.Nil(t, ctl.SetClusterCertificate(nil))
			_, err = cfg.GetCertificate(&tls.ClientHelloInfo{})
			assert.NotNil(t, err)
			require.Nil(t, ctl.SetClusterCertificate(&maincorev1.Secret{}))
			_, err = cfg.GetCertificate(&tls.ClientHelloInfo{})
			assert.NotNil(t, err)
		})
	}
}

func TestQUICTLSCertificateConcurrent(t *testing.T) {
	secret := newTstQUICCertificate(t)
	ctl := &QUICController{octeliumC: &tstQUICClient{core: &tstQUICCoreClient{secret: secret}}}
	cfg, err := ctl.getTLSConfig(t.Context())
	require.Nil(t, err)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 20 {
				assert.Nil(t, ctl.SetClusterCertificate(secret))
				_, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
				assert.Nil(t, err)
			}
		})
	}
	wg.Wait()
}

func TestQUICConfig(t *testing.T) {
	cfg, err := (&QUICController{}).getQUICCfg(t.Context())
	require.Nil(t, err)
	assert.True(t, cfg.EnableDatagrams)
	assert.Equal(t, []quic.Version{quic.Version1, quic.Version2}, cfg.Versions)
	assert.Equal(t, int64(5), cfg.MaxIncomingStreams)
	assert.Equal(t, int64(-1), cfg.MaxIncomingUniStreams)
	assert.Equal(t, 3*time.Second, cfg.HandshakeIdleTimeout)
	assert.Equal(t, 45*time.Second, cfg.MaxIdleTimeout)
}

func TestQUICHandleInvalidConnection(t *testing.T) {
	server, client := newTstQUICPair(t)
	ctl := &QUICController{}
	done := make(chan struct{})
	go func() {
		ctl.handleConnection(t.Context(), server)
		close(done)
	}()
	stream, err := client.OpenStreamSync(t.Context())
	require.Nil(t, err)
	_, err = stream.Write([]byte{0, 0, 0, 1, 0, 0, 0, 0, 1})
	require.Nil(t, err)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("The invalid connection was not closed")
	}
	select {
	case <-client.Context().Done():
		assert.Contains(t, fmt.Sprint(context.Cause(client.Context())), "0x8")
	case <-time.After(5 * time.Second):
		t.Fatal("The client did not observe the connection close")
	}
}
