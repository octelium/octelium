// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package install

import (
	"context"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	ocorev1 "github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const octeliumNS = "octelium"
const installationConfigMapName = "octelium-installation"
const installationConfigMapKey = "installation.json"

type SPIFFEOpts struct {
	CSIDriver   string
	TrustDomain string
}

func spiffeFromBootstrap(bs *cbootstrapv1.Config) *SPIFFEOpts {
	spiffe := bs.GetSpec().GetSpiffe()
	if !spiffe.GetEnable() {
		return nil
	}

	return &SPIFFEOpts{
		CSIDriver:   spiffe.GetCsiDriver().GetName(),
		TrustDomain: spiffe.GetTrustDomain(),
	}
}

func GetSPIFFE(ctx context.Context, c kubernetes.Interface) *SPIFFEOpts {

	cm, err := c.CoreV1().ConfigMaps(octeliumNS).
		Get(ctx, installationConfigMapName, k8smetav1.GetOptions{})
	if err != nil {
		zap.L().Debug("Could not get the installation ConfigMap. Assuming defaults",
			zap.Error(err))
		return nil
	}

	val, ok := cm.Data[installationConfigMapKey]
	if !ok || val == "" {
		return nil
	}

	installation := &ocorev1.ClusterConfig_Status_Installation{}
	if err := pbutils.UnmarshalJSON([]byte(val), installation); err != nil {
		zap.L().Debug("Could not unmarshal the installation ConfigMap. Assuming defaults",
			zap.Error(err))
		return nil
	}

	spiffe := installation.GetSpiffe()
	if !spiffe.GetEnable() {
		return nil
	}

	return &SPIFFEOpts{
		CSIDriver:   spiffe.GetCsiDriver().GetName(),
		TrustDomain: spiffe.GetTrustDomain(),
	}
}

func (o *SPIFFEOpts) getCSIDriver() string {
	if o.CSIDriver != "" {
		return o.CSIDriver
	}
	return "csi.spiffe.io"
}

func checkExistingInstallation(ctx context.Context, c kubernetes.Interface) error {
	alreadyInstalled := errors.Errorf("An existing Cluster installation was found. Use octops upgrade instead of init")
	if _, err := c.CoreV1().Secrets(octeliumNS).Get(ctx, "init-token", k8smetav1.GetOptions{}); err == nil {
		return alreadyInstalled
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	if state, err := c.CoreV1().Secrets(octeliumNS).Get(ctx, "octelium-genesis-init", k8smetav1.GetOptions{}); err == nil {
		if state.Annotations["octelium.com/genesis-init-complete"] == "true" {
			return alreadyInstalled
		}
		return nil
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	if _, err := c.CoreV1().Secrets(octeliumNS).Get(ctx, "octelium-init", k8smetav1.GetOptions{}); err == nil {
		return alreadyInstalled
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	if _, err := c.CoreV1().ConfigMaps(octeliumNS).Get(ctx, installationConfigMapName, k8smetav1.GetOptions{}); err == nil {
		return alreadyInstalled
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	return nil
}
