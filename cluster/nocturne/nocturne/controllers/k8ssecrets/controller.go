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

package k8ssecretcontroller

import (
	"context"
	"strings"

	"go.uber.org/zap"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/grpcerr"

	k8scorev1 "k8s.io/api/core/v1"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
)

func NewController(
	k8sC kubernetes.Interface,
	octeliumC octeliumc.ClientInterface,
	secretInformer coreinformers.SecretInformer) {

	secretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{

		AddFunc: func(obj any) {

			ctx := context.Background()

			secret, ok := obj.(*k8scorev1.Secret)
			if !ok {
				return
			}

			if err := setCert(ctx, octeliumC, secret); err != nil {
				zap.S().Errorf("Could not create cluster cert from k8s secret: %+v", err)
			}

		},

		UpdateFunc: func(old, new any) {

			ctx := context.Background()

			oldSecret, ok := old.(*k8scorev1.Secret)
			if !ok {
				return
			}
			newSecret, ok := new.(*k8scorev1.Secret)
			if !ok {
				return
			}

			if oldSecret.ResourceVersion == newSecret.ResourceVersion {
				return
			}

			if err := setCert(ctx, octeliumC, newSecret); err != nil {
				zap.S().Errorf("Could not update cluster cert from k8s secret: %+v", err)
			}

		},

		/*
			DeleteFunc: func(obj any) {
				ctx := context.Background()

				secret, ok := obj.(*k8scorev1.Secret)
				if !ok {
					return
				}

				if err := deleteCert(ctx, octeliumC, secret); err != nil {
					zap.S().Errorf("Could not delete cluster cert from k8s secret: %+v", err)
				}

			},
		*/

	})
}

func setCert(ctx context.Context, octeliumC octeliumc.ClientInterface, secret *k8scorev1.Secret) error {

	if secret.Namespace != vutils.K8sNS {
		return nil
	}

	if secret.Name == "cert-cluster" {
		return doSetCert(ctx, octeliumC, secret)
	}

	if arg, ok := strings.CutPrefix(secret.Name, "cert-ns-"); ok && arg != "" {
		if err := apivalidation.ValidateName(arg, 0, 0); err == nil {
			return doSetCertNS(ctx, octeliumC, secret)
		}
	}

	return nil
}

func doSetCert(ctx context.Context, octeliumC octeliumc.ClientInterface, secret *k8scorev1.Secret) error {

	crt, err := octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: vutils.ClusterCertSecretName})
	if err == nil {
		ucorev1.ToSecret(crt).SetCertificate(string(secret.Data["tls.crt"]), string(secret.Data["tls.key"]))

		_, err := octeliumC.CoreC().UpdateSecret(ctx, crt)
		if err != nil {
			return err
		}

		zap.L().Info("Successfully updated Cluster certificate Secret")

		return nil
	}

	if !grpcerr.IsNotFound(err) {
		return err
	}

	if err := doCreateCertSecret(ctx, octeliumC, vutils.ClusterCertSecretName, secret); err != nil {
		return err
	}

	zap.L().Info("Successfully created Cluster certificate Secret")
	return nil
}

func doSetCertNS(ctx context.Context, octeliumC octeliumc.ClientInterface, secret *k8scorev1.Secret) error {

	secName := strings.Replace(secret.Name, "cert-ns", "crt-ns", 1)
	crt, err := octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: secName})
	if err == nil {
		ucorev1.ToSecret(crt).SetCertificate(string(secret.Data["tls.crt"]), string(secret.Data["tls.key"]))
		_, err := octeliumC.CoreC().UpdateSecret(ctx, crt)
		if err != nil {
			return err
		}

		zap.L().Info("Successfully updated Namespace certificate Secret",
			zap.String("ns", strings.TrimPrefix(secName, "crt-ns")))

		return nil
	}

	if !grpcerr.IsNotFound(err) {
		return err
	}

	if err := doCreateCertSecret(ctx, octeliumC, secName, secret); err != nil {
		return err
	}

	zap.L().Info("Successfully created Namespace certificate Secret",
		zap.String("ns", strings.TrimPrefix(secName, "crt-ns")))

	return nil
}

func doCreateCertSecret(ctx context.Context, octeliumC octeliumc.ClientInterface, secName string, secret *k8scorev1.Secret) error {

	nCrt := &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: secName,
			SystemLabels: map[string]string{
				"octelium-cert": "true",
			},
			IsSystem:       true,
			IsUserHidden:   true,
			IsSystemHidden: true,
		},
		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},
	}

	ucorev1.ToSecret(nCrt).SetCertificate(string(secret.Data["tls.crt"]), string(secret.Data["tls.key"]))

	_, err := octeliumC.CoreC().CreateSecret(ctx, nCrt)
	if err != nil {
		return err
	}

	return nil
}
