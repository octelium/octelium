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

/*
import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/octelium/octelium/client/common/cliutils"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func checkReadiness(ctx context.Context, k8sC kubernetes.Interface) error {

	if err := checkNodeReadiness(ctx, k8sC); err != nil {
		return err
	}
	if err := checkDependencies(ctx, k8sC); err != nil {
		return err
	}
	if err := checkAPIServer(ctx, k8sC); err != nil {
		return err
	}
	if err := checkIngress(ctx, k8sC); err != nil {
		return err
	}

	if err := checkIngressPods(ctx, k8sC); err != nil {
		return err
	}

	return nil
}

func shouldRetry(err error) bool {
	return k8serr.IsConflict(err) ||
		k8serr.IsServerTimeout(err) ||
		k8serr.IsUnexpectedServerError(err) ||
		k8serr.IsTooManyRequests(err) ||
		k8serr.IsTimeout(err)
}

func checkNodeReadiness(ctx context.Context, k8sC kubernetes.Interface) error {
	doCheck := func() (bool, error) {
		nodes, err := k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{})
		if err != nil {
			return false, err
		}
		if len(nodes.Items) == 0 {
			return false, nil
		}
		for _, node := range nodes.Items {
			for _, condition := range node.Status.Conditions {
				if condition.Type == "Ready" && condition.Status != "True" {
					return false, nil
				}
			}
		}

		return true, nil
	}

	s := cliutils.NewSpinner(os.Stdout)
	s.SetSuffix("Checking for node readiness")
	s.Start()

	for {
		isDone, err := doCheck()
		if err != nil && !shouldRetry(err) {
			return err
		}

		if isDone {
			s.Stop()
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}

func checkDependencies(ctx context.Context, k8sC kubernetes.Interface) error {
	doCheck := func() (bool, error) {
		_, err := k8sC.AppsV1().Deployments("octelium").Get(ctx, "octelium-apiserver", k8smetav1.GetOptions{})
		if err == nil {
			return true, nil
		}
		if k8serr.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	s := cliutils.NewSpinner(os.Stdout)
	s.SetSuffix("Installing Octelium dependencies")
	s.Start()

	for {
		isDone, err := doCheck()
		if err != nil && !shouldRetry(err) {
			return err
		}

		if isDone {
			s.Stop()
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}

func checkAPIServer(ctx context.Context, k8sC kubernetes.Interface) error {
	doCheck := func() (bool, error) {
		dep, err := k8sC.AppsV1().Deployments("octelium").Get(ctx, "octelium-apiserver", k8smetav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if dep.Status.Replicas > 0 && dep.Status.ReadyReplicas > 0 && dep.Status.ReadyReplicas == dep.Status.Replicas {
			return true, nil
		}

		return false, nil
	}

	s := cliutils.NewSpinner(os.Stdout)
	s.SetSuffix("Installing Octelium components")
	s.Start()

	for {
		isDone, err := doCheck()
		if err != nil && !shouldRetry(err) {
			return err
		}

		if isDone {
			s.Stop()
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}

func checkIngress(ctx context.Context, k8sC kubernetes.Interface) error {
	doCheck := func() (bool, *corev1.Service, error) {
		svc, err := k8sC.CoreV1().Services("octelium").Get(ctx, "octelium-ingress-dataplane", k8smetav1.GetOptions{})
		if err != nil {
			return false, nil, err
		}

		if svc.Spec.ExternalIPs != nil && len(svc.Spec.ExternalIPs) > 0 {
			return true, svc, nil
		}

		if svc.Status.LoadBalancer.Ingress != nil && len(svc.Status.LoadBalancer.Ingress) > 0 {
			return true, svc, nil
		}

		return false, nil, nil
	}

	doGetIPs := func(svc *corev1.Service) []string {

		if svc.Spec.ExternalIPs != nil {
			return svc.Spec.ExternalIPs
		}

		ret := []string{}

		for _, ing := range svc.Status.LoadBalancer.Ingress {
			ret = append(ret, ing.IP)
		}

		return ret

	}

	s := cliutils.NewSpinner(os.Stdout)
	s.SetSuffix("Checking for Ingress readiness (1)")
	s.Start()

	for {
		isDone, svc, err := doCheck()
		if err != nil && !shouldRetry(err) {
			return err
		}

		if isDone {
			s.Stop()
			addrs := doGetIPs(svc)
			cliutils.LineNotify("Please set the addresses `%s` to refer to your domain in your DNS provider\n",
				strings.Join(addrs, ", "))
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}

func checkIngressPods(ctx context.Context, k8sC kubernetes.Interface) error {
	doCheck := func() (bool, error) {
		dep, err := k8sC.AppsV1().Deployments("octelium").Get(ctx, "octelium-ingress-dataplane", k8smetav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if dep.Status.Replicas > 0 && dep.Status.ReadyReplicas > 0 && dep.Status.ReadyReplicas == dep.Status.Replicas {
			return true, nil
		}

		return false, nil
	}

	s := cliutils.NewSpinner(os.Stdout)
	s.SetSuffix("Checking for Ingress readiness (2)")
	s.Start()

	for {
		isDone, err := doCheck()
		if err != nil && !shouldRetry(err) {
			return err
		}

		if isDone {
			s.Stop()
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}
*/
