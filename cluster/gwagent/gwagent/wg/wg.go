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

package wg

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	k8scorev1 "k8s.io/api/core/v1"
)

const (
	opQueueSize            = 20000
	opTimeout              = 30 * time.Second
	keyRotationCheckPeriod = 3 * time.Minute
)

type opType int

const (
	opTypeAdd opType = iota + 1
	opTypeUpdate
	opTypeRemove
)

type op struct {
	typ   opType
	sess  *corev1.Session
	errCh chan error
}

type Wg struct {
	client    *wgctrl.Client
	octeliumC octeliumc.ClientInterface
	gwName    string

	opCh   chan *op
	doneCh chan struct{}

	closeOnce sync.Once
}

func New(ctx context.Context, node *k8scorev1.Node, octeliumC octeliumc.ClientInterface, initPrivateKey wgtypes.Key) (*Wg, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	ret := &Wg{
		client:    client,
		octeliumC: octeliumC,
		gwName:    k8sutils.GetGatewayName(node),
		opCh:      make(chan *op, opQueueSize),
		doneCh:    make(chan struct{}),
	}

	gw, err := octeliumC.CoreC().GetGateway(ctx, &rmetav1.GetOptions{Name: ret.gwName})
	if err != nil {
		return nil, err
	}

	cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}

	if err := ret.initWG(ctx, gw, cc, initPrivateKey); err != nil {
		return nil, err
	}

	return ret, nil
}

func (wg *Wg) initWG(ctx context.Context,
	gw *corev1.Gateway,
	cc *corev1.ClusterConfig,
	privateKey wgtypes.Key) error {

	zap.L().Debug("initializing new wg dev")

	if err := wg.initializeDev(gw, cc); err != nil {
		return err
	}

	cfg := wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   new(int(gw.Status.Wireguard.Port)),
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{},
	}

	if err := wg.client.ConfigureDevice(devName, cfg); err != nil {
		return err
	}

	return nil

}

func isConnWG(c *corev1.Session_Status_Connection) bool {
	if c == nil {
		return false
	}
	return c.Type == corev1.Session_Status_Connection_WIREGUARD
}

func getAllowedIPs(sess *corev1.Session) []net.IPNet {
	ret := []net.IPNet{}

	if sess.Status.Connection == nil {
		return ret
	}

	for _, addr := range sess.Status.Connection.Addresses {
		addrGo := umetav1.ToDualStackNetwork(addr).ToGo()
		if addrGo.V4 != nil && ucorev1.ToSession(sess).HasV4() {
			ret = append(ret, *addrGo.V4)
		}
		if addrGo.V6 != nil && ucorev1.ToSession(sess).HasV6() {
			ret = append(ret, *addrGo.V6)
		}
	}

	return ret
}

func (wg *Wg) enqueue(typ opType, sess *corev1.Session) error {
	o := &op{
		typ:   typ,
		sess:  sess,
		errCh: make(chan error, 1),
	}

	timer := time.NewTimer(opTimeout)
	defer timer.Stop()

	select {
	case wg.opCh <- o:
	case <-wg.doneCh:
		return errors.Errorf("The wg controller is closed")
	case <-timer.C:
		return errors.Errorf("Timed out while enqueuing the wg operation")
	}

	select {
	case err := <-o.errCh:
		return err
	case <-wg.doneCh:
		return errors.Errorf("The wg controller is closed")
	case <-timer.C:
		return errors.Errorf("Timed out while waiting for the wg operation")
	}
}

func (wg *Wg) AddConnection(sess *corev1.Session) error {
	if !isConnWG(sess.Status.Connection) {
		return nil
	}

	return wg.enqueue(opTypeAdd, sess)
}

func (wg *Wg) UpdateConnection(sess *corev1.Session) error {
	if !isConnWG(sess.Status.Connection) {
		return nil
	}

	return wg.enqueue(opTypeUpdate, sess)
}

func (wg *Wg) RemoveConnection(sess *corev1.Session) error {
	if !isConnWG(sess.Status.Connection) {
		return nil
	}

	return wg.enqueue(opTypeRemove, sess)
}

func (wg *Wg) doOp(o *op) error {
	switch o.typ {
	case opTypeAdd:
		return wg.doAddConnection(o.sess)
	case opTypeUpdate:
		return wg.doUpdateConnection(o.sess)
	case opTypeRemove:
		return wg.doRemoveConnection(o.sess)
	default:
		return errors.Errorf("Unknown wg operation type: %d", o.typ)
	}
}

func (wg *Wg) doAddConnection(sess *corev1.Session) error {

	zap.L().Debug("Adding wg for Session", zap.String("sess", sess.Metadata.Name))

	connPubKey, err := wgtypes.NewKey(sess.Status.Connection.X25519PublicKey)
	if err != nil {
		return err
	}

	return wg.client.ConfigureDevice(devName, wgtypes.Config{
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         connPubKey,
				ReplaceAllowedIPs: true,
				AllowedIPs:        getAllowedIPs(sess),
			},
		},
	})
}

func (wg *Wg) doUpdateConnection(sess *corev1.Session) error {

	zap.L().Debug("Updating wg for Session", zap.String("sess", sess.Metadata.Name))

	connPubKey, err := wgtypes.NewKey(sess.Status.Connection.X25519PublicKey)
	if err != nil {
		return err
	}

	return wg.client.ConfigureDevice(devName, wgtypes.Config{
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         connPubKey,
				ReplaceAllowedIPs: true,
				UpdateOnly:        true,
				AllowedIPs:        getAllowedIPs(sess),
			},
		},
	})
}

func (wg *Wg) doRemoveConnection(sess *corev1.Session) error {

	zap.L().Debug("Deleting wg for Session", zap.String("sess", sess.Metadata.Name))

	connPubKey, err := wgtypes.NewKey(sess.Status.Connection.X25519PublicKey)
	if err != nil {
		return err
	}

	return wg.client.ConfigureDevice(devName, wgtypes.Config{
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: connPubKey,
				Remove:    true,
			},
		},
	})
}

func (wg *Wg) runLoop(ctx context.Context) {
	defer close(wg.doneCh)

	tickerCh := time.NewTicker(keyRotationCheckPeriod)
	defer tickerCh.Stop()

	zap.L().Debug("Starting the wg operation loop")

	for {
		select {
		case <-ctx.Done():
			zap.L().Debug("Exiting the wg operation loop")
			return
		case o := <-wg.opCh:
			err := wg.doOp(o)
			if err != nil {
				zap.L().Warn("Could not apply the wg operation",
					zap.Int("type", int(o.typ)), zap.Error(err))
			}
			select {
			case o.errCh <- err:
			default:
			}
		case <-tickerCh.C:
			if err := wg.doUpdateGatewayKey(ctx); err != nil {
				zap.L().Warn("Could not doUpdateGatewayKey", zap.Error(err))
			}
		}
	}
}

func (wg *Wg) Cleanup() error {

	wg.closeOnce.Do(func() {
		if wg.client != nil {
			if err := wg.client.Close(); err != nil {
				zap.L().Warn("Could not close the wgctrl client", zap.Error(err))
			}
		}
	})

	if err := doCleanupDev(); err != nil {
		return err
	}

	return nil
}

func (wg *Wg) doUpdateGatewayKey(ctx context.Context) error {

	gw, err := wg.octeliumC.CoreC().GetGateway(ctx, &rmetav1.GetOptions{Name: wg.gwName})
	if err != nil {
		return err
	}

	cc, err := wg.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	var rotationDuration time.Duration

	if cc.Spec.Gateway != nil && cc.Spec.Gateway.WireguardKeyRotationDuration != nil &&
		int(umetav1.ToDuration(cc.Spec.Gateway.WireguardKeyRotationDuration).ToGo().Seconds()) >= 30 {
		rotationDuration = umetav1.ToDuration(cc.Spec.Gateway.WireguardKeyRotationDuration).ToGo()
	} else {
		rotationDuration = time.Hour * 12
	}

	if time.Now().After(gw.Status.Wireguard.KeyRotatedAt.AsTime().Add(rotationDuration)) {
		if err := wg.doRotateKey(ctx, gw); err != nil {
			return err
		}
	}

	return nil
}

func (wg *Wg) doRotateKey(ctx context.Context, gw *corev1.Gateway) error {

	zap.L().Debug("starting to rotate wg key for Gateway", zap.String("gw", gw.Metadata.Name))

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}

	dev, err := wg.client.Device(devName)
	if err != nil {
		return err
	}

	oldPrivateKey := dev.PrivateKey

	if err := wg.client.ConfigureDevice(devName, wgtypes.Config{
		PrivateKey:   &privateKey,
		ReplacePeers: false,
	}); err != nil {
		return err
	}

	gw.Status.Wireguard.PublicKey = privateKey.PublicKey().String()
	gw.Status.Wireguard.KeyRotatedAt = pbutils.Now()

	_, err = wg.octeliumC.CoreC().UpdateGateway(ctx, gw)
	if err != nil {
		zap.L().Warn("Could not updateGateway after rotating wg key",
			zap.String("gw", gw.Metadata.Name), zap.Error(err))
		if err := wg.client.ConfigureDevice(devName, wgtypes.Config{
			PrivateKey:   &oldPrivateKey,
			ReplacePeers: false,
		}); err != nil {
			return err
		}

		return err
	}

	zap.L().Debug("Rotating wg key for Gateway is complete", zap.String("gw", gw.Metadata.Name))

	return nil
}

func (wg *Wg) Run(ctx context.Context) error {
	go wg.runLoop(ctx)
	return nil
}
