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

package harness

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/cluster/e2e/scenario"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type H struct {
	Scenario *scenario.Scenario
	State    *scenario.State

	Domain     string
	HomeDir    string
	ExternalIP string

	k8sC  kubernetes.Interface
	conn  *grpc.ClientConn
	coreC corev1.MainServiceClient

	ports     *PortAllocator
	artifacts *ArtifactCollector
	rootCtx   context.Context
	dbOpened  bool
}

type Opts struct {
	StatePath   string
	ArtifactDir string
}

func New(ctx context.Context, o *Opts) (*H, error) {
	if o == nil {
		o = &Opts{}
	}

	statePath := o.StatePath
	if statePath == "" {
		statePath = scenario.DefaultStatePath()
	}

	state, err := scenario.LoadState(statePath)
	if err != nil {
		return nil, err
	}

	sc, err := scenario.Get(state.ScenarioID)
	if err != nil {
		return nil, err
	}

	ret := &H{
		Scenario:   sc,
		State:      state,
		Domain:     state.Domain,
		HomeDir:    state.HomeDir,
		ExternalIP: state.ExternalIP,
		ports:      NewPortAllocator(),
		rootCtx:    ctx,
	}

	ret.artifacts = NewArtifactCollector(ret, o.ArtifactDir)

	ret.applyEnv()

	if err := ret.initK8s(); err != nil {
		return nil, err
	}

	if err := cliutils.OpenDB(""); err != nil {
		return nil, errors.Errorf("Could not open the CLI credential store: %+v", err)
	}
	ret.dbOpened = true

	conn, err := client.GetGRPCClientConn(ctx, ret.Domain)
	if err != nil {
		return nil, errors.Errorf("Could not dial the Cluster API at %s: %+v", ret.Domain, err)
	}
	ret.conn = conn
	ret.coreC = corev1.NewMainServiceClient(conn)

	return ret, nil
}

func (h *H) applyEnv() {
	os.Setenv("OCTELIUM_DOMAIN", h.Domain)
	os.Setenv("OCTELIUM_INSECURE_TLS", "false")
	os.Setenv("OCTELIUM_PRODUCTION", "true")
	os.Setenv("HOME", h.HomeDir)
	os.Setenv("KUBECONFIG", h.State.KubeconfigPath)

	zap.L().Debug("Harness environment",
		zap.String("domain", h.Domain),
		zap.String("home", h.HomeDir),
		zap.String("kubeconfig", h.State.KubeconfigPath),
		zap.String("externalIP", h.ExternalIP))
}

func (h *H) initK8s() error {
	cfg, err := clientcmd.BuildConfigFromFlags("", h.State.KubeconfigPath)
	if err != nil {
		return err
	}

	k8sC, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}

	h.k8sC = k8sC
	return nil
}

func (h *H) Close() error {
	if h.conn != nil {
		h.conn.Close()
	}
	if h.dbOpened {
		cliutils.CloseDB()
	}
	return nil
}

func (h *H) K8sC() kubernetes.Interface { return h.k8sC }

func (h *H) CoreC() corev1.MainServiceClient { return h.coreC }

func (h *H) Conn() *grpc.ClientConn { return h.conn }

func (h *H) Port() int { return h.ports.Get() }

func (h *H) Require(t *testing.T, caps ...scenario.Capability) {
	t.Helper()
	for _, c := range caps {
		if !h.Scenario.Caps.Has(c) {
			t.Skipf("scenario %q does not provide the capability %q", h.Scenario.ID, c)
		}
	}
}

func (h *H) opCtx(t *testing.T) (context.Context, context.CancelFunc) {
	if t.Context().Err() == nil {
		return context.WithCancel(t.Context())
	}
	return context.WithTimeout(context.Background(), 60*time.Second)
}

func (h *H) Setup(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if t.Failed() {
			h.artifacts.Collect(t)
		}
	})
}
