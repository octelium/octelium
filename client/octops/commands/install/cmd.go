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

	if err := setClusterResources(ctx, o); err != nil {
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
	// cliutils.LineNotify("Also you might need to flush your machine's local DNS cache if your machine is using one so that you do not have to wait for too long until the newly set Cluster domain's public DNS entry is synchronized with your local machine\n\n\n")
}

func setClusterResources(ctx context.Context, o *Opts) error {

	k8sC := o.K8sC

	dataMap := map[string][]byte{
		"region":    pbutils.MarshalMust(o.Region),
		"bootstrap": pbutils.MarshalMust(o.Bootstrap),
		"domain":    []byte(o.ClusterDomain),
	}

	{

		if secret, err := k8sC.CoreV1().Secrets("default").Get(ctx, "octelium-init", k8smetav1.GetOptions{}); err == nil {
			secret.Data = dataMap
			_, err := k8sC.CoreV1().Secrets("default").Update(ctx, secret, k8smetav1.UpdateOptions{})
			if err != nil {
				return err
			}
		} else if k8serr.IsNotFound(err) {
			_, err := k8sC.CoreV1().Secrets("default").Create(ctx, &k8scorev1.Secret{
				ObjectMeta: k8smetav1.ObjectMeta{
					Name: "octelium-init",
				},
				Data: dataMap,
			}, k8smetav1.CreateOptions{})
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}

/*
func setRegcred(ctx context.Context, k8sC kubernetes.Interface) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dockerJsonBytes, err := os.ReadFile(path.Join(homeDir, ".docker", "config.json"))
	if err != nil {
		return err
	}

	if secret, err := k8sC.CoreV1().Secrets("default").Get(ctx, "octelium-regcred", k8smetav1.GetOptions{}); err == nil {
		secret.StringData = map[string]string{
			".dockerconfigjson": string(dockerJsonBytes),
		}
		secret.Type = k8scorev1.SecretTypeDockerConfigJson

		_, err := k8sC.CoreV1().Secrets("default").Update(ctx, secret, k8smetav1.UpdateOptions{})
		if err != nil {
			return err
		}
	} else if k8serr.IsNotFound(err) {
		_, err := k8sC.CoreV1().Secrets("default").Create(ctx, &k8scorev1.Secret{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name: "octelium-regcred",
			},
			StringData: map[string]string{
				".dockerconfigjson": string(dockerJsonBytes),
			},

			Type: k8scorev1.SecretTypeDockerConfigJson,
		}, k8smetav1.CreateOptions{})
		if err != nil {
			return err
		}
	} else {
		return err
	}

	return nil

}
*/
