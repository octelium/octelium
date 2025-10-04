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
	"os/exec"
	"time"

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
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

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

	/*
		if err := s.setNodeIndex(ctx); err != nil {
			return err
		}
	*/

	if err := untaintNode(ctx, s.k8sC, node); err != nil {
		zap.L().Warn("Could not untaint node", zap.Error(err))
	}

	if _, err := os.Stat("/dev/net/tun"); err != nil && os.IsNotExist(err) {
		cmds := []string{
			"mkdir -p /dev/net",
			"mknod /dev/net/tun c 10 200",
			"chmod 600 /dev/net/tun",
		}

		for _, cmd := range cmds {
			if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
				zap.L().Warn("Could not execute command",
					zap.String("cmd", cmd), zap.Error(err))
			}
		}
	}
	/*
		if _, err := os.Stat("/dev/net/tun"); err != nil && os.IsNotExist(err) {
			zap.L().Debug("Mknoding tun dev")
			if err := os.WriteFile("/tmp/install_dev_net_tun.sh", []byte(devNetTunScript), 0755); err != nil {
				return err
			}
			if err := exec.Command("/bin/sh", "-c", "/tmp/install_dev_net_tun.sh").Run(); err != nil {
				return errors.Errorf("Could not install /dev/net/tun device: %+v", err)
			}
		}
	*/

	/*
		if _, ok := node.Labels["octelium.com/wireguard-installed"]; !ok {
			zap.L().Debug("WireGuard kernel module is not installed. Going for the user implementation instead...")
			s.isUserspaceMode = true
		}
	*/

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

	zap.L().Debug("Gateway agent is now running", zap.String("node", s.nodeName))

	return nil
}

func untaintNode(ctx context.Context, k8sC kubernetes.Interface, n *k8scorev1.Node) error {

	zap.L().Debug("untainting node", zap.String("node", n.Name))

	for i, taint := range n.Spec.Taints {
		if taint.Key == "octelium.com/gateway-init" {
			zap.L().Info("Found gateway-init taint. Removing it")
			if err := waitForMultusPod(ctx, k8sC, n); err != nil {
				return err
			}

			node, err := k8sC.CoreV1().Nodes().Get(ctx, n.Name, k8smetav1.GetOptions{})
			if err != nil {
				return err
			}

			node.Spec.Taints = append(node.Spec.Taints[:i], node.Spec.Taints[i+1:]...)
			node.Labels["octelium.com/gateway-registered"] = "true"

			_, err = k8sC.CoreV1().Nodes().Update(ctx, node, k8smetav1.UpdateOptions{})
			if err != nil {
				return err
			}
			return nil
		}
	}

	return nil
}

func waitForMultusPod(ctx context.Context, k8sC kubernetes.Interface, n *k8scorev1.Node) error {
	doFn := func() error {
		pods, err := k8sC.CoreV1().Pods("kube-system").List(ctx, k8smetav1.ListOptions{
			LabelSelector: "octelium.com/dependency=multus",
		})
		if err != nil {
			return err
		}

		pod := func() *k8scorev1.Pod {
			for _, pod := range pods.Items {
				if pod.Spec.NodeName == n.Name {
					return &pod
				}
			}
			return nil
		}()

		if pod == nil {
			return errors.Errorf("Could not find the multus pod on the Node: %s", n.Name)
		}

		zap.L().Debug("Found multus pod. Checking its readiness...", zap.String("pod", pod.Name))

		for _, condition := range pod.Status.Conditions {
			if condition.Type == "Ready" && condition.Status == "True" {
				return nil
			}
		}

		return errors.Errorf("Pod is not ready")
	}

	zap.L().Debug("Waiting for Multus pod to be ready")

	for i := range 1000 {
		err := doFn()
		if err == nil {
			zap.L().Debug("Multus is ready")
			return nil
		}
		zap.L().Info("Multus pod is not ready yet. Trying again...",
			zap.Int("attempt", i+1), zap.Error(err))
		time.Sleep(2 * time.Second)
	}

	return errors.Errorf("Could not check for multus pod readiness on the Node: %s", n.Name)
}

func Run(ctx context.Context) error {

	healthcheck.RunWithAddr("localhost:10101")

	if err := os.MkdirAll("/etc/cni/multus/net.d", os.ModePerm); err != nil {
		return err
	}

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
