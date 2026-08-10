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

package scenario

import (
	"context"
	"os"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Provisioner interface {
	Name() string

	KubeconfigPath() string

	CNIPaths() CNIPaths

	Provision(ctx context.Context, r *Runner) error

	Teardown(ctx context.Context, r *Runner) error

	ExternalIP(ctx context.Context, r *Runner) (string, error)
}

type Runner struct {
	Scenario *Scenario
	State    *State

	statePath string
	extraEnv  map[string]string
	k8sC      kubernetes.Interface
}

type RunnerOpts struct {
	StatePath string
	LoadState bool
}

func NewRunner(s *Scenario, o *RunnerOpts) (*Runner, error) {
	if o == nil {
		o = &RunnerOpts{}
	}

	statePath := o.StatePath
	if statePath == "" {
		statePath = DefaultStatePath()
	}

	ret := &Runner{
		Scenario:  s,
		statePath: statePath,
		extraEnv:  map[string]string{},
	}

	if o.LoadState {
		state, err := LoadState(statePath)
		if err != nil {
			return nil, err
		}
		if state.ScenarioID != s.ID {
			return nil, errors.Errorf(
				"The existing e2e state is for scenario %q but %q was requested",
				state.ScenarioID, s.ID)
		}
		ret.State = state
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, errors.Errorf("Could not resolve the home directory: %+v", err)
		}

		ret.State = &State{
			ScenarioID:     s.ID,
			Caps:           s.Caps,
			Domain:         s.Domain,
			KubeconfigPath: s.Provisioner.KubeconfigPath(),
			HomeDir:        homeDir,
		}
	}

	ret.applyEnv()

	return ret, nil
}

func (r *Runner) StatePath() string {
	return r.statePath
}

func (r *Runner) SaveState() error {
	return r.State.Save(r.statePath)
}

func (r *Runner) applyEnv() {
	r.SetEnv("KUBECONFIG", r.State.KubeconfigPath)
	r.SetEnv("OCTELIUM_DOMAIN", r.State.Domain)
	r.SetEnv("OCTELIUM_PRODUCTION", "true")

	r.SetEnv("DEBIAN_FRONTEND", "noninteractive")
}

func (r *Runner) SetEnv(k, v string) {
	r.extraEnv[k] = v
	os.Setenv(k, v)
}

func (r *Runner) K8sC() (kubernetes.Interface, error) {
	if r.k8sC != nil {
		return r.k8sC, nil
	}

	cfg, err := clientcmd.BuildConfigFromFlags("", r.State.KubeconfigPath)
	if err != nil {
		return nil, err
	}

	k8sC, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	r.k8sC = k8sC
	return k8sC, nil
}

func (r *Runner) Provision(ctx context.Context) error {
	zap.L().Info("Provisioning",
		zap.String("scenario", r.Scenario.ID),
		zap.String("provisioner", r.Scenario.Provisioner.Name()))

	if err := r.Scenario.Provisioner.Provision(ctx, r); err != nil {
		return err
	}

	externalIP, err := r.Scenario.Provisioner.ExternalIP(ctx, r)
	if err != nil {
		return err
	}
	r.State.ExternalIP = externalIP
	r.State.ProvisionedAt = time.Now()

	zap.L().Info("Provisioned",
		zap.String("externalIP", externalIP),
		zap.String("kubeconfig", r.State.KubeconfigPath))

	return r.SaveState()
}

func (r *Runner) Prepare(ctx context.Context) error {
	if err := runSteps(ctx, r, "prepare", r.prepareSteps()); err != nil {
		return err
	}
	return r.SaveState()
}

func (r *Runner) Install(ctx context.Context) error {
	if err := runSteps(ctx, r, "install", r.installSteps()); err != nil {
		return err
	}
	r.State.InstalledAt = time.Now()
	return r.SaveState()
}

func (r *Runner) Teardown(ctx context.Context) error {
	if err := r.Scenario.Provisioner.Teardown(ctx, r); err != nil {
		zap.L().Warn("Could not fully tear down the cluster", zap.Error(err))
	}

	if err := os.Remove(r.statePath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
