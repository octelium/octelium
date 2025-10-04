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
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	k8scorev1 "k8s.io/api/core/v1"
)

type Wg struct {
	client    *wgctrl.Client
	octeliumC octeliumc.ClientInterface
	gwName    string
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
		ListenPort:   utils_types.IntToPtr(int(gw.Status.Wireguard.Port)),
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

func (wg *Wg) AddConnection(sess *corev1.Session) error {

	if sess.Status.Connection == nil {
		return nil
	}

	if !isConnWG(sess.Status.Connection) {
		return nil
	}

	zap.L().Debug("Adding wg for Session", zap.String("sess", sess.Metadata.Name))

	dev, err := wg.client.Device(devName)
	if err != nil {
		return err
	}

	connPubKey, err := wgtypes.NewKey(sess.Status.Connection.X25519PublicKey)
	if err != nil {
		return err
	}

	cfg := wgtypes.Config{
		ReplacePeers: false,
		ListenPort:   &dev.ListenPort,
		PrivateKey:   &dev.PrivateKey,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: connPubKey,
				AllowedIPs: func() []net.IPNet {

					ret := []net.IPNet{}

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
				}(),
			},
		},
	}

	return wg.client.ConfigureDevice(devName, cfg)

}

func (wg *Wg) UpdateConnection(sess *corev1.Session) error {
	if sess.Status.Connection == nil {
		return nil
	}

	if !isConnWG(sess.Status.Connection) {
		return nil
	}

	zap.L().Debug("Updating wg for Session", zap.String("sess", sess.Metadata.Name))
	dev, err := wg.client.Device(devName)
	if err != nil {
		return err
	}

	connPubKey, err := wgtypes.NewKey(sess.Status.Connection.X25519PublicKey)
	if err != nil {
		return err
	}

	cfg := wgtypes.Config{
		ReplacePeers: false,
		ListenPort:   &dev.ListenPort,
		PrivateKey:   &dev.PrivateKey,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         connPubKey,
				ReplaceAllowedIPs: true,
				UpdateOnly:        true,
				AllowedIPs: func() []net.IPNet {

					ret := []net.IPNet{}

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
				}(),
			},
		},
	}

	if err := wg.client.ConfigureDevice(devName, cfg); err != nil {
		return err
	}

	return nil
}

func (wg *Wg) RemoveConnection(sess *corev1.Session) error {
	if sess.Status.Connection == nil {
		return nil
	}

	if !isConnWG(sess.Status.Connection) {
		return nil
	}

	zap.L().Debug("Deleting wg for Session", zap.String("sess", sess.Metadata.Name))

	connPubKey, err := wgtypes.NewKey(sess.Status.Connection.X25519PublicKey)
	if err != nil {
		return err
	}

	dev, err := wg.client.Device(devName)
	if err != nil {
		return err
	}

	if err := wg.client.ConfigureDevice(devName, wgtypes.Config{
		PrivateKey:   &dev.PrivateKey,
		ListenPort:   &dev.ListenPort,
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: connPubKey,
				Remove:    true,
			},
		},
	}); err != nil {
		return err
	}

	return nil
}

func (wg *Wg) Cleanup() error {

	if err := doCleanupDev(); err != nil {
		return err
	}

	return nil
}

func (wg *Wg) runKeyRotation(ctx context.Context) {
	tickerCh := time.NewTicker(3 * time.Minute)
	defer tickerCh.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerCh.C:
			if err := wg.doUpdateGatewayKey(ctx); err != nil {
				zap.L().Warn("Could not doUpdateGatewayKey", zap.Error(err))
			}
		}
	}
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
		cc.Spec.Gateway.WireguardKeyRotationDuration.GetSeconds() >= 300 {
		rotationDuration = umetav1.ToDuration(cc.Spec.Gateway.WireguardKeyRotationDuration).ToGo()
	} else {
		rotationDuration = time.Hour * 12
	}

	if time.Now().After(gw.Status.Wireguard.KeyRotatedAt.AsTime().Add(rotationDuration)) {
		zap.L().Debug("Rotating wg key for Gateway", zap.String("gw", gw.Metadata.Name))

		_, err := wg.octeliumC.CoreC().UpdateGateway(ctx, gw)
		if err != nil {
			return err
		}
	}

	return nil
}

func (wg *Wg) Run(ctx context.Context) error {
	go wg.runKeyRotation(ctx)
	return nil
}
