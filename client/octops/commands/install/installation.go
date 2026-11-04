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
	spiffe, err := GetSPIFFEWithError(ctx, c)
	if err != nil {
		zap.L().Debug("Could not get the installation ConfigMap. Assuming defaults", zap.Error(err))
	}
	return spiffe
}

func GetSPIFFEWithError(ctx context.Context, c kubernetes.Interface) (*SPIFFEOpts, error) {
	cm, err := getK8sConfigMap(ctx, c, octeliumNS, installationConfigMapName)
	if k8serr.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	val := cm.Data[installationConfigMapKey]
	if val == "" {
		return nil, errors.Errorf("The installation ConfigMap has no installation configuration")
	}
	installation := &ocorev1.ClusterConfig_Status_Installation{}
	if err := pbutils.UnmarshalJSON([]byte(val), installation); err != nil {
		return nil, errors.Wrap(err, "Invalid installation configuration")
	}
	spiffe := installation.GetSpiffe()
	if !spiffe.GetEnable() {
		return nil, nil
	}
	return &SPIFFEOpts{CSIDriver: spiffe.GetCsiDriver().GetName(), TrustDomain: spiffe.GetTrustDomain()}, nil
}

func (o *SPIFFEOpts) getCSIDriver() string {
	if o.CSIDriver != "" {
		return o.CSIDriver
	}
	return "csi.spiffe.io"
}

func checkExistingInstallation(ctx context.Context, c kubernetes.Interface) error {
	alreadyInstalled := errors.Errorf("An existing Cluster installation was found. Use octops upgrade instead of init")
	if _, err := getK8sSecret(ctx, c, octeliumNS, "init-token"); err == nil {
		return alreadyInstalled
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	if state, err := getK8sSecret(ctx, c, octeliumNS, "octelium-genesis-init"); err == nil {
		if state.Annotations["octelium.com/genesis-init-complete"] == "true" {
			return alreadyInstalled
		}
		return nil
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	if _, err := getK8sSecret(ctx, c, octeliumNS, "octelium-init"); err == nil {
		return alreadyInstalled
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	if _, err := getK8sConfigMap(ctx, c, octeliumNS, installationConfigMapName); err == nil {
		return alreadyInstalled
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	return nil
}
