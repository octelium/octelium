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
	"os"
	"path/filepath"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	k8scorev1 "k8s.io/api/core/v1"

	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Opts struct {
	ClusterDomain     string
	K8sC              kubernetes.Interface
	Region            *corev1.Region
	Bootstrap         *cbootstrapv1.Config
	Version           string
	AuthTokenSavePath string
}

func DoInstall(ctx context.Context, o *Opts) error {
	if err := checkExistingInstallation(ctx, o.K8sC); err != nil {
		return err
	}

	if err := createGenesis(ctx, o); err != nil {
		return err
	}

	if err := setInitialAuthToken(ctx, o); err != nil {
		return err
	}

	return nil

}

func setInitialAuthToken(ctx context.Context, o *Opts) error {
	k8sC := o.K8sC
	clusterDomain := o.ClusterDomain
	zap.L().Debug("Getting the initial access token...")
	s := cliutils.NewSpinner(os.Stdout)
	s.SetSuffix("Waiting for Cluster installation to finish")
	s.Start()

	secret, err := func() (*k8scorev1.Secret, error) {
		for i := 0; i < 4000; i++ {
			secret, err := k8sC.CoreV1().Secrets("octelium").Get(ctx, "init-token", k8smetav1.GetOptions{})
			if err != nil {
				if k8serr.IsNotFound(err) {
					zap.L().Debug("Init Token not found. Trying again...")
					time.Sleep(2000 * time.Millisecond)
					continue
				} else {
					return nil, err
				}
			}
			return secret, nil
		}
		return nil, errors.Errorf("Could not find init Token secret")
	}()
	if err != nil {
		return err
	}

	authToken := string(secret.Data["data"])

	s.Stop()

	if err := cliutils.GetDB().Delete(clusterDomain); err != nil {
		zap.L().Debug("Could not purge DB for domain", zap.Error(err))
	}

	switch {
	case os.Getenv("OCTELIUM_SKIP_MESSAGES") == "true":
	default:
		printClusterMsgs()

		cliutils.LineNotify("Once you set up your public DNS and Cluster TLS certificate,\n")
		cliutils.LineNotify("use the following command to login and start interacting with the Cluster.\n")
		cliutils.LineInfo("octelium login --domain %s --auth-token %s\n", clusterDomain, authToken)
	}

	if o.AuthTokenSavePath != "" {
		dir := filepath.Dir(o.AuthTokenSavePath)

		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}

		if err := os.WriteFile(o.AuthTokenSavePath, []byte(authToken), 0600); err != nil {
			return err
		}
	}

	return nil
}

func printClusterMsgs() {
	cliutils.LineNotify("The Cluster installation is now complete!\n")
	cliutils.LineNotify("You can start interacting with the Cluster once you set the Cluster TLS certificate and the public DNS.")
	cliutils.LineNotify("For more information, you might want to visit the docs at https://octelium.com/docs \n")
	cliutils.LineNotify(`You can also interact with the Cluster before setting the Cluster TLS certificate by setting the "OCTELIUM_INSECURE_TLS" environment variable to "true" (i.e. via the "export OCTELIUM_INSECURE_TLS=true" command) before running "octelium" and "octeliumctl" commands`)
	cliutils.LineInfo("\n")
}

func setClusterResources(ctx context.Context, o *Opts) error {
	dataMap := map[string][]byte{
		"region":    pbutils.MarshalMust(o.Region),
		"bootstrap": pbutils.MarshalMust(o.Bootstrap),
		"domain":    []byte(o.ClusterDomain),
	}

	secrets := o.K8sC.CoreV1().Secrets("default")
	secret, err := secrets.Get(ctx, "octelium-init", k8smetav1.GetOptions{})
	if k8serr.IsNotFound(err) {
		secret, err = o.K8sC.CoreV1().Secrets(octeliumNS).Get(ctx, "octelium-init", k8smetav1.GetOptions{})
	}
	if k8serr.IsNotFound(err) {
		_, err = secrets.Create(ctx, &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init"}, Data: dataMap}, k8smetav1.CreateOptions{})
		if !k8serr.IsAlreadyExists(err) {
			return err
		}
		secret, err = secrets.Get(ctx, "octelium-init", k8smetav1.GetOptions{})
	}
	if err != nil {
		return err
	}
	bs, region := &cbootstrapv1.Config{}, &corev1.Region{}
	if err := pbutils.Unmarshal(secret.Data["bootstrap"], bs); err != nil {
		return err
	}
	if err := pbutils.Unmarshal(secret.Data["region"], region); err != nil {
		return err
	}
	desiredBS, desiredRegion := o.Bootstrap, o.Region
	if desiredBS == nil {
		desiredBS = &cbootstrapv1.Config{}
	}
	if desiredRegion == nil {
		desiredRegion = &corev1.Region{}
	}
	if string(secret.Data["domain"]) != o.ClusterDomain || !proto.Equal(bs, desiredBS) || !proto.Equal(region, desiredRegion) {
		return errors.Errorf("The existing bootstrap differs. Refusing to replace another initialization's input")
	}
	return nil
}
