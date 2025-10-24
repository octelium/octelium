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
	"net/netip"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/quicv0"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/jwkctl"
	"github.com/octelium/octelium/cluster/common/ocrypto"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/tun"
)

type QUICController struct {
	octeliumC octeliumc.ClientInterface
	lis       *quic.Listener

	cancelFn context.CancelFunc
	jwkCtl   *jwkctl.Controller

	tunWriteCh chan []byte
	tunReadCh  chan []byte

	tundev tun.Device

	lookupMap lookupMap
	dctxMap   dctxMap

	mu sync.Mutex

	gwName string

	crtMan struct {
		mu  sync.RWMutex
		crt *corev1.Secret
	}

	svcCIDRs []netip.Prefix

	mtu int
}

type lookupMap struct {
	sync.RWMutex
	lookupMap map[string]*dctx
}

type dctxMap struct {
	sync.RWMutex
	dctxMap map[string]*dctx
}

func New(ctx context.Context, octeliumC octeliumc.ClientInterface, gwName string) (*QUICController, error) {
	ret := &QUICController{
		octeliumC:  octeliumC,
		tunReadCh:  make(chan []byte, 1024),
		tunWriteCh: make(chan []byte, 1024),
		dctxMap: dctxMap{
			dctxMap: make(map[string]*dctx),
		},
		lookupMap: lookupMap{
			lookupMap: make(map[string]*dctx),
		},
		gwName: gwName,
	}
	var err error

	ret.jwkCtl, err = jwkctl.NewJWKController(ctx, octeliumC)
	if err != nil {
		return nil, err
	}

	zap.L().Debug("Created a QUICv0 controller")

	return ret, nil
}

func (c *QUICController) Run(ctx context.Context) error {
	var err error

	ctx, cancelFn := context.WithCancel(ctx)
	c.cancelFn = cancelFn
	zap.L().Debug("Starting running QUIC controller")

	gw, err := c.octeliumC.CoreC().GetGateway(ctx, &rmetav1.GetOptions{Name: c.gwName})
	if err != nil {
		return err
	}

	if gw.Status.Quicv0 == nil {
		return errors.Errorf("status.quicv0 is not defined")
	}

	cc, err := c.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	zap.L().Debug("dev MTU", zap.Int("mtu", ucorev1.ToClusterConfig(cc).GetDevMTUQUIV0()))

	c.mtu = ucorev1.ToClusterConfig(cc).GetDevMTUQUIV0()

	if gw.Status.Cidr.V4 != "" {
		c.svcCIDRs = append(c.svcCIDRs, netip.MustParsePrefix(gw.Status.Cidr.V4))
	}
	if gw.Status.Cidr.V6 != "" {
		c.svcCIDRs = append(c.svcCIDRs, netip.MustParsePrefix(gw.Status.Cidr.V6))
	}

	if err := c.jwkCtl.Run(ctx); err != nil {
		return err
	}

	if err := c.createTunDev(ctx, gw, cc); err != nil {
		return errors.Errorf("Could not create tundev: %+v", err)
	}

	if err := c.runTunDev(ctx); err != nil {
		return errors.Errorf("Could not run tundev: %+v", err)
	}

	tlsCfg, err := c.getTLSConfig(ctx)
	if err != nil {
		return err
	}

	quicCfg, err := c.getQUICCfg(ctx)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf(":%d", gw.Status.Quicv0.Port)
	zap.L().Debug("Starting a QUIC server", zap.String("addr", addr))
	c.lis, err = quic.ListenAddr(addr, tlsCfg, quicCfg)
	if err != nil {
		return err
	}

	go c.startLoop(ctx)

	zap.L().Debug("QUIC controller is now running")

	return nil
}

func (c *QUICController) startLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := c.lis.Accept(ctx)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go c.handleConnection(ctx, conn)
		}
	}
}

func (c *QUICController) handleConnection(ctx context.Context, conn *quic.Conn) {
	if err := c.doHandleConnection(ctx, conn); err != nil {
		conn.CloseWithError(8, "")
		zap.L().Debug("Could not handle connection", zap.Error(err))
	}
}

const hdrSize = 8

func (c *QUICController) getBuf(ctx context.Context, stream *quic.Stream, desiredType uint32) ([]byte, error) {
	payload, typ, err := decodeMsg(stream)
	if err != nil {
		return nil, err
	}

	if typ != desiredType {
		return nil, errors.Errorf("Invalid msg type. Desired type = %d", desiredType)
	}

	return payload, nil
}

func decodeMsg(stream *quic.Stream) ([]byte, uint32, error) {
	bufSize := 1024
	buf := make([]byte, bufSize)
	n, err := stream.Read(buf)
	if err != nil {
		return nil, 0, errors.Errorf("Could not read init stream req: %+v", err)
	}

	if n <= hdrSize || n >= 1024 {
		return nil, 0, errors.Errorf("Invalid init stream req size: %d", n)
	}
	payloadSize := binary.BigEndian.Uint32(buf[:4])
	typ := binary.BigEndian.Uint32(buf[4:hdrSize])

	switch typ {
	case 0:
		return nil, 0, errors.Errorf("Invalid msg type")
	}

	if payloadSize > 4096 {
		return nil, 0, errors.Errorf("Invalid msg size")
	}

	if payloadSize+uint32(hdrSize) < uint32(n) {
		return nil, 0, errors.Errorf("msg size does not match")
	}

	if payloadSize+uint32(hdrSize) == uint32(n) {
		return buf[hdrSize:n], typ, nil
	}

	var ni int
	curPayloadSize := uint32(n - hdrSize)

	ret := make([]byte, n)
	copy(ret[:], buf[:n])

	for ; curPayloadSize < payloadSize; curPayloadSize = curPayloadSize + uint32(ni) {
		iBuf := make([]byte, bufSize)
		ni, err = stream.Read(iBuf)
		if err != nil {
			return nil, 0, errors.Errorf("Could not read subsequent stream req %+v", err)
		}
		ret = append(ret, iBuf[:ni]...)
	}

	if uint32(len(ret[hdrSize:])) != payloadSize {
		return nil, 0, errors.Errorf("Final payloadSize does not match: %d ... %d", len(ret[hdrSize:]), payloadSize)
	}

	return ret[hdrSize:], typ, nil
}

func (c *QUICController) doInit(ctx context.Context, stream *quic.Stream) (*corev1.Session, error) {
	buf, err := c.getBuf(ctx, stream, 1)
	if err != nil {
		return nil, err
	}

	req := &quicv0.InitRequest{}

	if err := pbutils.Unmarshal(buf[:], req); err != nil {
		return nil, err
	}

	claims, err := c.jwkCtl.VerifyAccessToken(req.AccessToken)
	if err != nil {
		return nil, err
	}

	sess, err := c.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: claims.SessionUID})
	if err != nil {
		return nil, err
	}

	if !ucorev1.ToSession(sess).IsValid() {
		return nil, errors.Errorf("The Session is not valid")
	}

	if sess.Status.Authentication.TokenID != claims.TokenID {
		return nil, errors.Errorf("Invalid claims")
	}

	zap.L().Debug("Found Session", zap.String("session", sess.Metadata.Uid))

	if !ucorev1.ToSession(sess).IsClient() {
		return nil, errors.Errorf("Not a CLIENT Session")
	}

	if c.hasActiveSessionUID(sess.Metadata.Uid) {
		return nil, errors.Errorf("Session already has another active Connection")
	}

	if sess.Status.Connection == nil {
		return nil, errors.Errorf("This Session is not Connected")
	}

	if sess.Status.Connection.Type != corev1.Session_Status_Connection_QUICV0 {
		return nil, errors.Errorf("Not a QUIC connection")
	}

	if sess.Status.IsLocked {
		return nil, errors.Errorf("Session is locked")
	}

	resp := &quicv0.InitResponse{
		Type: quicv0.InitResponse_OK,
	}

	if err := c.writeResponse(ctx, stream, resp, 1); err != nil {
		return nil, err
	}
	return sess, nil
}

func (c *QUICController) writeResponse(ctx context.Context, stream *quic.Stream, resp pbutils.Message, typ uint32) error {

	buf, err := encodeMsg(resp, typ)
	if err != nil {
		return err
	}
	if _, err := stream.Write(buf); err != nil {
		return err
	}

	return nil
}

func encodeMsg(resp pbutils.Message, typ uint32) ([]byte, error) {

	respBytes, err := pbutils.Marshal(resp)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(respBytes)+hdrSize)

	binary.BigEndian.PutUint32(buf[0:4], uint32(len(respBytes)))
	binary.BigEndian.PutUint32(buf[4:hdrSize], typ)
	copy(buf[hdrSize:], respBytes[:])

	return buf, nil
}

/*
func (c *QUICController) doHandleConnection(ctx context.Context, conn quic.Connection) error {
	initCtx, cancelFn := context.WithTimeout(ctx, 3*time.Second)
	defer cancelFn()
	zap.L().Debug("Accepting new stream", zap.String("conn", conn.RemoteAddr().String()))
	initStream, err := conn.AcceptStream(initCtx)
	if err != nil {
		return err
	}
	defer initStream.Close()

	if err := initStream.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return err
	}

	buf := make([]byte, 1024)
	n, err := initStream.Read(buf)
	if err != nil {
		return errors.Errorf("Could not read init stream req: %+v", err)
	}
	if n == 0 || n >= 1024 {
		return errors.Errorf("Invalid init stream req size: %d", n)
	}

	req := &pbauth.InitiateGatewaySessionRequest{}

	if err := pbutils.Unmarshal(buf[:n], req); err != nil {
		return err
	}

	claims, err := c.jwkCtl.VerifyAccessToken(req.AccessToken)
	if err != nil {
		return err
	}

	sess, err := c.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: claims.Subject})
	if err != nil {
		return err
	}

	if !claims.IsValid(sess) {
		return errors.Errorf("Invalid claims")
	}

	zap.L().Debug("Found Session", zap.String("session", sess.Metadata.Uid))

	if !ucorev1.ToSession(sess).IsClient() {
		return errors.Errorf("Not a CLIENT Session")
	}

	if c.hasActiveSessionUID(sess.Metadata.Uid) {
		return errors.Errorf("Session already has another active Connection")
	}

	if sess.Status.Connection == nil {
		return errors.Errorf("Nil Connection")
	}

	if sess.Status.Connection.Type != corev1.Session_Status_Connection_QUICV0 {
		return errors.Errorf("Not a QUIC connection")
	}

	resp := &pbauth.InitiateGatewaySessionResponse{
		Type: pbauth.InitiateGatewaySessionResponse_OK,
	}

	respBytes, err := pbutils.Marshal(resp)
	if err != nil {
		return err
	}

	zap.L().Debug("Writing accept response", zap.String("session", sess.Metadata.Uid))
	if _, err := initStream.Write(respBytes); err != nil {
		return err
	}

	dctx := newDctx(sess, conn, c.tunWriteCh, c.svcCIDRs, c.mtu)

	c.dctxMap.Lock()
	c.dctxMap.dctxMap[dctx.id] = dctx
	c.dctxMap.Unlock()

	c.lookupMap.Lock()
	for _, addr := range dctx.addrs {
		c.lookupMap.lookupMap[addr.Addr().String()] = dctx
	}
	c.lookupMap.Unlock()

	err = dctx.runAndWait(ctx)

	c.dctxMap.Lock()
	delete(c.dctxMap.dctxMap, dctx.id)
	c.dctxMap.Unlock()

	c.lookupMap.Lock()
	for _, addr := range dctx.addrs {
		delete(c.lookupMap.lookupMap, addr.Addr().String())
	}
	c.lookupMap.Unlock()

	return err
}
*/

func (c *QUICController) doHandleConnection(ctx context.Context, conn *quic.Conn) error {
	initCtx, cancelFn := context.WithTimeout(ctx, 3*time.Second)
	defer cancelFn()
	zap.L().Debug("Accepting new stream", zap.String("conn", conn.RemoteAddr().String()))
	initStream, err := conn.AcceptStream(initCtx)
	if err != nil {
		return err
	}
	defer initStream.Close()

	if err := initStream.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return err
	}

	sess, err := c.doInit(ctx, initStream)
	if err != nil {
		return err
	}

	dctx := newDctx(sess, conn, c.tunWriteCh, c.svcCIDRs, c.mtu)

	c.dctxMap.Lock()
	c.dctxMap.dctxMap[dctx.id] = dctx
	c.dctxMap.Unlock()

	c.lookupMap.Lock()
	for _, addr := range dctx.addrs {
		c.lookupMap.lookupMap[addr.Addr().String()] = dctx
	}
	c.lookupMap.Unlock()

	if err := dctx.runAndWait(ctx); err != nil {
		zap.L().Debug("runAndWait error", zap.Error(err))
	}

	c.dctxMap.Lock()
	delete(c.dctxMap.dctxMap, dctx.id)
	c.dctxMap.Unlock()

	c.lookupMap.Lock()
	for _, addr := range dctx.addrs {
		delete(c.lookupMap.lookupMap, addr.Addr().String())
	}
	c.lookupMap.Unlock()

	return nil
}

func (c *QUICController) hasActiveSessionUID(sessUID string) bool {
	c.dctxMap.RLock()
	defer c.dctxMap.RUnlock()

	_, ok := c.dctxMap.dctxMap[sessUID]
	return ok
}

func (c *QUICController) Close() error {

	c.mu.Lock()
	defer c.mu.Unlock()

	zap.L().Debug("Closing QUIC controller")

	for _, dctx := range c.dctxMap.dctxMap {
		dctx.close()
	}

	c.cancelFn()
	c.lis.Close()
	if c.tundev != nil {
		c.tundev.Close()
	}

	zap.L().Debug("QUIC controller closed")

	return nil
}

func (s *QUICController) getTLSConfig(ctx context.Context) (*tls.Config, error) {

	crt, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: vutils.ClusterCertSecretName})
	if err != nil && !grpcerr.IsNotFound(err) {
		return nil, err
	}

	s.crtMan.mu.Lock()
	s.crtMan.crt = crt
	s.crtMan.mu.Unlock()

	ret := &tls.Config{
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.crtMan.mu.RLock()
			defer s.crtMan.mu.RUnlock()

			return ocrypto.GetTLSCertificate(s.crtMan.crt)
		},
	}

	return ret, nil
}

func (c *QUICController) getQUICCfg(ctx context.Context) (*quic.Config, error) {
	ret := &quic.Config{
		EnableDatagrams:       true,
		Versions:              []quic.Version{quic.Version1, quic.Version2},
		MaxIncomingStreams:    5,
		MaxIncomingUniStreams: -1,
		HandshakeIdleTimeout:  3 * time.Second,
		MaxIdleTimeout:        45 * time.Second,
	}

	return ret, nil
}

func (c *QUICController) SetClusterCertificate(crt *corev1.Secret) error {
	c.crtMan.mu.Lock()
	defer c.crtMan.mu.Unlock()
	zap.L().Debug("QUICv0 ctl: Setting Cluster Certificate")
	c.crtMan.crt = crt
	return nil
}

func (c *QUICController) RemoveConnection(sess *corev1.Session) error {
	c.dctxMap.Lock()
	defer c.dctxMap.Unlock()

	conn := sess.Status.Connection
	if conn == nil {
		return nil
	}

	if conn.Type != corev1.Session_Status_Connection_QUICV0 {
		return nil
	}

	zap.L().Debug("QUICv0: Removing Session", zap.String("uid", sess.Metadata.Uid))

	dctx, ok := c.dctxMap.dctxMap[sess.Metadata.Uid]
	if !ok {
		zap.L().Debug("Session doesn't exist. Nothing to be done...", zap.String("id", sess.Metadata.Uid))
		return nil
	}

	zap.L().Debug("Closing dctx of Session", zap.String("uid", sess.Metadata.Uid))

	return dctx.close()
}
