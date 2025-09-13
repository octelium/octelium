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

package genesis

import (
	"context"

	nadclientset "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"go.uber.org/zap"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Genesis struct {
	k8sC      kubernetes.Interface
	octeliumC octeliumc.ClientInterface
	nadC      nadclientset.Interface
}

func NewGenesis() (*Genesis, error) {
	ret := &Genesis{}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	cfg.QPS = 100
	cfg.Burst = 200

	k8sClientSet, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	nadC, err := nadclientset.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	ret.k8sC = k8sClientSet
	ret.nadC = nadC

	return ret, nil
}

func (g *Genesis) RemoveAll(ctx context.Context) error {

	err := g.deleteNamespaces(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (g *Genesis) deleteNamespaces(ctx context.Context) error {
	err := g.k8sC.CoreV1().Namespaces().Delete(ctx, vutils.K8sNS, k8smetav1.DeleteOptions{})
	if err != nil && !k8serr.IsNotFound(err) {
		return err
	}
	return nil
}

func (g *Genesis) initRegion(cr *LoadedClusterResource) (*corev1.Region, error) {

	if cr.Region != nil {
		region := cr.Region

		if region.Metadata == nil {
			region.Metadata = &metav1.Metadata{
				Name: "default",
			}
		}
		region.Metadata.IsSystem = true
		if region.Metadata.Name == "" {
			region.Metadata.Name = "default"
		}

		if region.Spec == nil {
			region.Spec = &corev1.Region_Spec{}
		}
		if region.Status == nil {
			region.Status = &corev1.Region_Status{}
		}
		region.Status.Version = ldflags.GetVersion()
		vutils.SetRegionPublicHostName(region)

		zap.L().Debug("Initialized Region from loaded init", zap.Any("region", region))

		return region, nil
	}

	ret := &corev1.Region{
		Metadata: &metav1.Metadata{
			Name:     "default",
			IsSystem: true,
		},
		Spec: &corev1.Region_Spec{},
		Status: &corev1.Region_Status{

			Version: ldflags.GetVersion(),
		},
	}
	vutils.SetRegionPublicHostName(ret)

	/*
		if cr.Bootstrap.Spec.Kubernetes != nil && len(cr.Bootstrap.Spec.Kubernetes.ExternalIPs) > 0 {
			ret.Metadata.SystemLabels = make(map[string]string)
			externalIPBytes, err := json.Marshal(cr.Bootstrap.Spec.Kubernetes.ExternalIPs)
			if err != nil {
				return nil, err
			}
			ret.Metadata.SystemLabels["external-ips"] = string(externalIPBytes)
		}
	*/

	zap.L().Debug("Initialized Region", zap.Any("region", ret))

	return ret, nil
}

func (g *Genesis) createPostgresSecret(ctx context.Context, dataMap map[string][]byte) error {
	zap.L().Debug("Creating postgres k8s secret")
	_, err := g.k8sC.CoreV1().Secrets(vutils.K8sNS).Create(ctx, &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      "octelium-postgres",
			Namespace: vutils.K8sNS,
		},
		Data: dataMap,
	}, k8smetav1.CreateOptions{})
	return err
}

func (g *Genesis) createRedisSecret(ctx context.Context, dataMap map[string][]byte) error {
	zap.L().Debug("Creating redis k8s secret")
	_, err := g.k8sC.CoreV1().Secrets(vutils.K8sNS).Create(ctx, &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      "octelium-redis",
			Namespace: vutils.K8sNS,
		},
		Data: dataMap,
	}, k8smetav1.CreateOptions{})
	return err
}

type LoadedClusterResource struct {
	Bootstrap *cbootstrapv1.Config
	Region    *corev1.Region
	Domain    string
}
