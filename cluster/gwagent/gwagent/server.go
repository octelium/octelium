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

package gwagent

import (
	"context"
	"os"
	"slices"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/commoninit"
	"github.com/octelium/octelium/cluster/common/healthcheck"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/common/watchers"
	secretcontroller "github.com/octelium/octelium/cluster/gwagent/gwagent/controllers/secrets"
	sesscontroller "github.com/octelium/octelium/cluster/gwagent/gwagent/controllers/sessions"
	"github.com/octelium/octelium/cluster/gwagent/gwagent/gw"
	"github.com/octelium/octelium/cluster/gwagent/gwagent/quicv0"
	"github.com/octelium/octelium/cluster/gwagent/gwagent/wg"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	k8scorev1 "k8s.io/api/core/v1"
)

type Server struct {
	octeliumC   octeliumc.ClientInterface
	k8sC        *kubernetes.Clientset
	wgC         *wg.Wg
	nodeName    string
	publicIPs   []string
	node        *k8scorev1.Node
	regionIndex int
	regionRef   *metav1.ObjectReference

	hasQUICV0 bool
	quicCtl   *quicv0.QUICController
}

func NewServer(ctx context.Context) (*Server, error) {

	nodeName := os.Getenv("OCTELIUM_NODE")

	zap.L().Debug("Gateway node name", zap.String("node", nodeName))

	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	k8sC, err := k8sutils.NewClient(ctx, nil)
	if err != nil {
		return nil, err
	}

	ret := &Server{
		octeliumC: octeliumC,
		k8sC:      k8sC,
		nodeName:  nodeName,
	}

	return ret, nil
}

func (s *Server) Run(ctx context.Context) error {

	zap.L().Debug("Starting running Gateway agent", zap.String("node", s.nodeName))

	region, err := s.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{Name: vutils.GetMyRegionName()})
	if err != nil {
		return err
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	s.regionIndex = int(region.Status.Index)
	s.regionRef = umetav1.GetObjectReference(region)

	node, err := s.k8sC.CoreV1().Nodes().Get(ctx, s.nodeName, k8smetav1.GetOptions{})
	if err != nil {
		return err
	}
	s.node = node

	if err := s.prepareTUN(); err != nil {
		zap.L().Warn("Could not prepareTUN", zap.Error(err))
	}

	if err := s.setNodePublicIPs(ctx); err != nil {
		return err
	}

	initWGPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}

	if err := gw.InitGateway(ctx,
		s.publicIPs, node, s.octeliumC, s.regionIndex, s.regionRef, initWGPrivateKey); err != nil {
		return errors.Errorf("Could not init Gateway: %+v", err)
	}

	wgC, err := wg.New(ctx, node, s.octeliumC, initWGPrivateKey)
	if err != nil {
		return err
	}
	s.wgC = wgC

	if err := wgC.Run(ctx); err != nil {
		return err
	}

	if cc.Status.NetworkConfig != nil &&
		cc.Status.NetworkConfig.Quicv0 != nil &&
		cc.Status.NetworkConfig.Quicv0.Enable {
		zap.L().Debug("QUICv0 controller is enabled")
		s.hasQUICV0 = true
		s.quicCtl, err = quicv0.New(ctx, s.octeliumC, k8sutils.GetGatewayName(s.node))
		if err != nil {
			return errors.Errorf("Could not create QUIC ctl: %+v", err)
		}

		if err := s.quicCtl.Run(ctx); err != nil {
			zap.L().Debug("Could not run QUICv0 controller", zap.Error(err))
		} else {
			zap.L().Debug("QUICv0 controller is now running")
		}

	} else {
		zap.L().Debug("QUICv0 mode is NOT enabled.")
	}

	sessCtl := sesscontroller.NewController(&sesscontroller.Opts{
		WgC:       s.wgC,
		HasQuicV0: s.hasQUICV0,
		Quicv0Ctl: s.quicCtl,
	})

	watcher := watchers.NewCoreV1(s.octeliumC)

	if err := watcher.Session(ctx, nil, sessCtl.OnAdd, sessCtl.OnUpdate, sessCtl.OnDelete); err != nil {
		return err
	}

	if s.hasQUICV0 && s.quicCtl != nil {
		secretCtl := secretcontroller.NewController(s.quicCtl)
		if err := watcher.Secret(ctx, nil, secretCtl.OnAdd, secretCtl.OnUpdate, secretCtl.OnDelete); err != nil {
			return err
		}
	}

	if err := untaintNode(ctx, s.k8sC, s.nodeName); err != nil {
		return errors.Errorf("Could not set the node as Gateway-registered: %+v", err)
	}

	zap.L().Debug("Gateway agent is now running", zap.String("node", s.nodeName))

	return nil
}

func (s *Server) prepareTUN() error {
	zap.L().Debug("Checking whether /dev/net/tun exists")
	_, err := os.Stat("/dev/net/tun")
	if err == nil {
		zap.L().Debug("/dev/net/tun exists. No mknod needed")
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}

	zap.L().Debug("creating /dev/net/tun")

	if err := os.MkdirAll("/dev/net", 0755); err != nil {
		return errors.Errorf("could not create /dev/net directory: %+v", err)
	}

	mode := uint32(unix.S_IFCHR | 0600)

	dev := int(unix.Mkdev(10, 200))

	if err := unix.Mknod("/dev/net/tun", mode, dev); err != nil {
		if err == unix.EPERM {
			zap.L().Warn("Could not create /dev/net/tun. Missing CAP_MKNOD or insufficient privileges")
		}

		return errors.Errorf("Could not create /dev/net/tun device: %+v", err)
	}

	return nil
}

func untaintNode(ctx context.Context, k8sC kubernetes.Interface, nodeName string) error {

	zap.L().Debug("Setting the node as Gateway-registered", zap.String("node", nodeName))

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {

		node, err := k8sC.CoreV1().Nodes().Get(ctx, nodeName, k8smetav1.GetOptions{})
		if err != nil {
			return err
		}

		taints := slices.DeleteFunc(slices.Clone(node.Spec.Taints),
			func(taint k8scorev1.Taint) bool {
				return taint.Key == vutils.NodeTaintGatewayInit
			})

		if node.Labels == nil {
			node.Labels = make(map[string]string)
		}

		isTainted := len(taints) != len(node.Spec.Taints)
		isRegistered := node.Labels[vutils.NodeLabelGatewayRegistered] == "true"

		if !isTainted && isRegistered {
			return nil
		}

		if isTainted {
			zap.L().Info("Found gateway-init taint. Removing it",
				zap.String("node", nodeName))
		}

		node.Spec.Taints = taints
		node.Labels[vutils.NodeLabelGatewayRegistered] = "true"

		_, err = k8sC.CoreV1().Nodes().Update(ctx, node, k8smetav1.UpdateOptions{})
		return err
	})
}

func Run(ctx context.Context) error {

	healthcheck.RunWithAddr("localhost:10101")

	srv, err := NewServer(ctx)
	if err != nil {
		return err
	}

	if err := commoninit.Run(ctx, nil); err != nil {
		return err
	}

	if err := srv.Run(ctx); err != nil {
		srv.cleanup()
		return errors.Errorf("Could not run node agent: %s server: %+v", srv.nodeName, err)
	}

	zap.L().Info("Gateway agent is now running...", zap.String("node", srv.nodeName))

	<-ctx.Done()

	if srv.hasQUICV0 && srv.quicCtl != nil {
		srv.quicCtl.Close()
	}

	srv.cleanup()

	return nil
}

func (s *Server) cleanup() {
	if s.wgC != nil {
		zap.L().Debug("Cleaning up wg devices")
		if err := s.wgC.Cleanup(); err != nil {
			zap.L().Warn("Could not cleanup wg dev", zap.Error(err))
		}
	}
}
