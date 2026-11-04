package commands

import (
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestCommandClusterTargetE2E(t *testing.T) {
	for _, command := range []string{"upgrade", "install-package/cordium", "upgrade-package/octeliumee"} {
		for _, state := range []string{"bound", "legacy", "secret-forbidden", "wrong-domain", "wrong-bootstrap", "wrong-region", "corrupt-region", "partial-identity", "transient", "lost-create-response"} {
			t.Run(command+"/"+state, func(t *testing.T) {
				c, config := newTestKubernetes(t)
				annotations := map[string]string{
					"octelium.com/genesis-cluster-uid": "cluster-uid", "octelium.com/genesis-domain": "example.com",
					"octelium.com/genesis-region-uid": "region-uid", "octelium.com/genesis-region-name": "west", "octelium.com/genesis-namespace-uid": "namespace-uid",
				}
				if state == "legacy" || state == "secret-forbidden" {
					annotations = nil
				}
				if state == "partial-identity" {
					delete(annotations, "octelium.com/genesis-namespace-uid")
				}
				require.NoError(t, c.Tracker().Add(&k8scorev1.ConfigMap{
					ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-installation", Namespace: "octelium", Annotations: annotations},
					Data:       map[string]string{"installation.json": `{"spiffe":{"enable":true,"csiDriver":{"name":"custom.csi"}}}`},
				}))
				bootstrap := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "octelium"}, Data: map[string][]byte{
					"domain": []byte("example.com"), "region": pbutils.MarshalMust(&corev1.Region{Metadata: &metav1.Metadata{Name: "west"}}),
				}}
				if state == "wrong-bootstrap" {
					bootstrap.Data["domain"] = []byte("another.example")
				}
				if state == "wrong-region" {
					bootstrap.Data["region"] = pbutils.MarshalMust(&corev1.Region{Metadata: &metav1.Metadata{Name: "east"}})
				}
				if state == "corrupt-region" {
					bootstrap.Data["region"] = []byte{0xff}
				}
				require.NoError(t, c.Tracker().Add(bootstrap))
				failed := false
				c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if state == "secret-forbidden" {
						return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "octelium-init", fmt.Errorf("legacy restricted role"))
					}
					if state == "transient" && !failed {
						failed = true
						return true, nil, k8serr.NewServiceUnavailable("short bootstrap read outage")
					}
					return false, nil, nil
				})
				if state == "lost-create-response" {
					c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
						job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
						job.UID = "accepted-target-job"
						require.NoError(t, c.Tracker().Create(action.GetResource(), job, action.GetNamespace()))
						return true, nil, k8serr.NewServiceUnavailable("response lost after commit")
					})
				}
				domain := "example.com"
				if state == "wrong-domain" {
					domain = "another.example"
				}
				args := []string{"upgrade", domain, "--kubeconfig=" + config, "--version=1.2.3"}
				if command != "upgrade" {
					args[0] = "install-package"
					pkg := "cordium"
					if command == "upgrade-package/octeliumee" {
						pkg = "octeliumee"
						args = append(args, "--upgrade")
					}
					args = append(args, "--package="+pkg)
				}
				out, err := executeTestCommand(t, t.Context(), args...)
				blocked := state == "wrong-domain" || state == "wrong-bootstrap" || state == "wrong-region" || state == "corrupt-region" || state == "partial-identity"
				if blocked {
					require.Error(t, err)
					assert.NotContains(t, out, "has started")
					for _, action := range c.Actions() {
						assert.Contains(t, []string{"get", "list"}, action.GetVerb())
					}
				} else {
					require.NoError(t, err, out)
				}
				jobs, listErr := c.BatchV1().Jobs("octelium").List(t.Context(), k8smetav1.ListOptions{})
				require.NoError(t, listErr)
				if blocked {
					assert.Empty(t, jobs.Items)
					return
				}
				require.Len(t, jobs.Items, 1)
				job := jobs.Items[0]
				assert.Nil(t, job.Spec.Suspend)
				assert.Equal(t, "custom.csi", job.Spec.Template.Spec.Volumes[0].CSI.Driver)
				env := map[string]string{}
				for _, value := range job.Spec.Template.Spec.Containers[0].Env {
					env[value.Name] = value.Value
				}
				if state == "secret-forbidden" {
					assert.Equal(t, "default", env["OCTELIUM_REGION_NAME"])
				} else {
					assert.Equal(t, "west", env["OCTELIUM_REGION_NAME"])
				}
				if annotations != nil {
					assert.Equal(t, "cluster-uid", env["OCTELIUM_GENESIS_CLUSTER_UID"])
					assert.Equal(t, "region-uid", env["OCTELIUM_GENESIS_REGION_UID"])
					assert.Equal(t, "namespace-uid", env["OCTELIUM_GENESIS_NAMESPACE_UID"])
				} else {
					assert.NotContains(t, env, "OCTELIUM_GENESIS_CLUSTER_UID")
				}
				if state == "transient" {
					assert.True(t, failed)
				}
			})
		}
	}
}
