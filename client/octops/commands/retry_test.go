package commands

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestUpgradeAndPackageConfigurationRetryE2E(t *testing.T) {
	for _, command := range []string{"upgrade", "install-package"} {
		for _, stage := range []string{"transient", "forbidden", "corrupt", "missing-key", "legacy-missing"} {
			t.Run(command+"/"+stage, func(t *testing.T) {
				c, config := newTestKubernetes(t)
				if stage != "legacy-missing" {
					cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "octelium-installation", Namespace: "octelium"}, Data: map[string]string{"installation.json": `{"spiffe":{"enable":true,"trustDomain":"test.local","csiDriver":{"name":"custom.csi"}}}`}}
					if stage == "corrupt" {
						cm.Data["installation.json"] = "{invalid"
					}
					if stage == "missing-key" {
						cm.Data = nil
					}
					require.NoError(t, c.Tracker().Add(cm))
				}
				failed := false
				c.PrependReactor("get", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if stage == "forbidden" {
						return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "octelium-installation", fmt.Errorf("permission denied"))
					}
					if stage == "transient" && !failed {
						failed = true
						return true, nil, k8serr.NewServiceUnavailable("temporary installation metadata outage")
					}
					return false, nil, nil
				})
				args := []string{command, "example.com", "--kubeconfig=" + config, "--version=1.2.3"}
				if command == "install-package" {
					args = append(args, "--package=cordium", "--upgrade")
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				out, err := executeTestCommand(t, ctx, args...)
				jobs, listErr := c.BatchV1().Jobs("octelium").List(t.Context(), metav1.ListOptions{})
				require.NoError(t, listErr)
				if stage == "transient" || stage == "legacy-missing" {
					require.NoError(t, err, out)
					require.Len(t, jobs.Items, 1)
					if stage == "transient" {
						assert.True(t, failed)
						assert.Equal(t, "custom.csi", jobs.Items[0].Spec.Template.Spec.Volumes[0].CSI.Driver)
					} else {
						assert.Empty(t, jobs.Items[0].Spec.Template.Spec.Volumes)
					}
				} else {
					require.Error(t, err)
					assert.Empty(t, jobs.Items)
					assert.NotContains(t, out, "has started")
				}
			})
		}
	}
}
