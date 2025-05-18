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
	"os/signal"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/commoninit"
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
	"k8s.io/client-go/tools/clientcmd"

	k8scorev1 "k8s.io/api/core/v1"
)

type Server struct {
	octeliumC       octeliumc.ClientInterface
	k8sC            *kubernetes.Clientset
	wgC             *wg.Wg
	nodeName        string
	publicIPs       []string
	node            *k8scorev1.Node
	isUserspaceMode bool
	// nodeIndex       int
	regionIndex int
	regionRef   *metav1.ObjectReference

	hasQUICV0 bool
	quicCtl   *quicv0.QUICController
}

func NewServer(ctx context.Context) (*Server, error) {

	nodeName := os.Getenv("OCTELIUM_NODE")

	zap.S().Debugf("node name: %s", nodeName)

	cfg, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		return nil, err
	}

	zap.S().Debugf("Creating octeliumC")

	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	zap.S().Debugf("Creating k8sC")

	k8sC, err := kubernetes.NewForConfig(cfg)
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

var devNetTunScript = `
#!/bin/sh

mkdir -p /dev/net
mknod /dev/net/tun c 10 200
chmod 600 /dev/net/tun
`

func (s *Server) Run(ctx context.Context) error {

	zap.S().Debugf("Starting running Gateway agent")

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

	zap.S().Debugf("My node is: %s", node.Name)

	/*
		if err := s.setNodeIndex(ctx); err != nil {
			return err
		}
	*/

	if err := untaintNode(ctx, s.k8sC, node); err != nil {
		return err
	}

	if _, err := os.Stat("/dev/net/tun"); err != nil && os.IsNotExist(err) {
		zap.L().Debug("Mknoding tun dev")
		if err := os.WriteFile("/tmp/install_dev_net_tun.sh", []byte(devNetTunScript), 0755); err != nil {
			return err
		}
		if err := exec.Command("/bin/sh", "-c", "/tmp/install_dev_net_tun.sh").Run(); err != nil {
			return errors.Errorf("Could not install /dev/net/tun device: %+v", err)
		}
	}

	if _, ok := node.Labels["octelium.com/wireguard-installed"]; !ok {
		zap.S().Debugf("WireGuard kernel module is not installed. Going for the user implementation instead...")
		s.isUserspaceMode = true
	}

	{
		if ipv4, ok := node.Annotations["octelium.com/public-ipv4"]; ok {
			s.publicIPs = append(s.publicIPs, ipv4)
		}

		if ipv6, ok := node.Annotations["octelium.com/public-ipv6"]; ok {
			s.publicIPs = append(s.publicIPs, ipv6)
		}

		if s.publicIPs == nil {
			if nIP, ok := node.Annotations["octelium.com/public-ip"]; ok {
				s.publicIPs = append(s.publicIPs, nIP)
			}
		}

		if s.publicIPs == nil {
			if err := s.setExternalIP(ctx); err != nil {
				return err
			}
		}

		zap.S().Debugf("Found public IPs: %+v", s.publicIPs)
	}

	initWGPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}

	if err := gw.InitGateway(ctx, s.publicIPs, node, s.octeliumC, s.regionIndex, s.regionRef, initWGPrivateKey); err != nil {
		return errors.Errorf("Could not init Gateway: %+v", err)
	}

	wgC, err := wg.NewWg(ctx, s.regionRef, node, s.octeliumC, s.isUserspaceMode, initWGPrivateKey)
	if err != nil {
		return err
	}
	s.wgC = wgC

	if err := wgC.Run(ctx); err != nil {
		return err
	}

	if cc.Status.NetworkConfig != nil && cc.Status.NetworkConfig.Quicv0 != nil && cc.Status.NetworkConfig.Quicv0.Enable {
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
			zap.S().Debugf("Found gateway-init taint. Removing it")
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

/*
func (s *Server) setNodeIndex(ctx context.Context) error {

	zap.L().Debug("Setting node index")

	doFn := func() error {
		cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		if err != nil {
			return err
		}

		for _, ni := range cc.Status.NodeIndexes {
			if ni.Uid == string(s.node.UID) {
				zap.S().Debugf("Node previously registered with the index: %d. No need to add node index", ni.Index)
				s.nodeIndex = int(ni.Index)
				return nil
			}
		}

		idx, err := func() (int, error) {

			lstNodes := func() []int {
				ret := []int{}
				for _, ni := range cc.Status.NodeIndexes {
					ret = append(ret, int(ni.Index))
				}
				return ret
			}()

			inList := func(lst []int, i int) bool {
				for _, itm := range lst {
					if i == itm {
						return true
					}
				}
				return false
			}

			for i := 0; i < 100000; i++ {
				if !inList(lstNodes, i) {
					return i, nil
				}
			}
			return 0, errors.Errorf("Could not get node index")
		}()
		if err != nil {
			return err
		}
		s.nodeIndex = idx
		cc.Status.NodeIndexes = append(cc.Status.NodeIndexes, &corev1.ClusterConfig_Status_NodeIndex{
			Name:  s.node.Name,
			Uid:   string(s.node.UID),
			Index: int32(s.nodeIndex),
		})

		if _, err := s.octeliumC.CoreC().UpdateClusterConfig(ctx, cc); err != nil {
			return err
		}
		return nil
	}

	for i := 0; i < 100; i++ {
		err := doFn()
		if err == nil {
			zap.S().Debugf("Registered node index %d for node: %s", s.nodeIndex, s.node.Name)
			return nil
		}
		time.Sleep(2 * time.Second)
	}

	return errors.Errorf("Could not register node index")
}
*/

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

		zap.S().Debugf("Found multus pod %s on the node %s. Checking its readiness...", pod.Name, n.Name)

		for _, condition := range pod.Status.Conditions {
			if condition.Type == "Ready" && condition.Status == "True" {
				return nil
			}
		}

		return errors.Errorf("Pod is not ready")
	}

	zap.L().Debug("Waiting for Multus pod to be ready")

	for i := 0; i < 1000; i++ {
		err := doFn()
		if err == nil {
			zap.L().Debug("Multus is ready")
			return nil
		}
		zap.L().Debug("Multus pod is not ready yet. Trying again...", zap.Error(err))
		time.Sleep(2 * time.Second)
	}

	return errors.Errorf("Could not check for multus pod readiness on the Node: %s", n.Name)
}

func Run() error {

	ctx, cancelFn := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancelFn()
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

	zap.L().Info("Gateway agent is now running...")

	<-ctx.Done()

	if srv.hasQUICV0 && srv.quicCtl != nil {
		srv.quicCtl.Close()
	}

	srv.cleanup()

	return nil
}

func (s *Server) cleanup() {
	zap.S().Debugf("Starting cleaning up for node: %s", s.nodeName)
	zap.S().Debugf("Cleaning up wg devices")

	if s.wgC != nil {
		if err := s.wgC.Cleanup(); err != nil {
			zap.S().Errorf("Could not cleanup wg devices: %+v", err)
		}
	}

	/*
		zap.S().Debugf("Cleaning up node gws")

		gwList, err := s.octeliumC.CoreC().ListGateway(ctx, &rmetav1.ListOptions{})
		if err != nil {
			zap.S().Errorf("Could not list gws for cleanup: %+v", err)
			return
		}

		for _, gw := range gwList.Items {
			if gw.Metadata.Name == s.nodeName {
				_, err = s.octeliumC.CoreC().DeleteGateway(ctx, &rmetav1.DeleteOptions{Uid: gw.Metadata.Uid})
				if err != nil && !grpcerr.IsNotFound(err) {
					zap.S().Errorf("Could not delete gw:%s for cleanup: %+v", gw.Metadata.Uid, err)
				}
			}
		}
	*/

	/*
		cniPath := "/etc/cni/multus/net.d"

		zap.S().Debugf("Cleaning up the CNI directory")
		cniFiles, err := ioutil.ReadDir(cniPath)
		if err != nil {
			zap.S().Errorf("Could not list files in the CNI directory: %+v", err)
		}

		for _, f := range cniFiles {
			zap.S().Debugf("removing cni file: %s", f.Name())
			if err := os.Remove(path.Join(cniPath, f.Name())); err != nil {
				zap.S().Errorf("Could not remove cni file %s: %+v", f.Name(), err)
			}
		}

	*/

}
