//go:build e2e

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

package tests

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newAllowPolicy(t *testing.T, h *harness.H, name string) *corev1.Policy {
	t.Helper()

	return h.CreatePolicy(t, &corev1.Policy{
		Metadata: &metav1.Metadata{Name: name},
		Spec: &corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{harness.AllowAnyRule("allow", 0)},
		},
	})
}

func testRscServerMetadata(t *testing.T, h *harness.H) {
	ctx := t.Context()

	policy := newAllowPolicy(t, h, h.Name())

	require.NotEmpty(t, policy.Metadata.Uid)
	require.NotEmpty(t, policy.Metadata.ResourceVersion)
	require.NotNil(t, policy.Metadata.CreatedAt)

	t.Run("ActorTrail", func(t *testing.T) {
		require.NotNil(t, policy.Metadata.ActorRef,
			"a resource written through the API must record its actor")

		assert.NotEmpty(t, policy.Metadata.ActorRef.Uid)
		assert.Equal(t, "Session", policy.Metadata.ActorRef.Kind)

		assert.Equal(t, "octelium.api.main.core.v1.MainService/CreatePolicy",
			policy.Metadata.ActorOperation)

		sess := h.Status(t).Session
		require.NotNil(t, sess)
		assert.Equal(t, sess.Metadata.Uid, policy.Metadata.ActorRef.Uid)
	})

	t.Run("UpdateBumpsResourceVersion", func(t *testing.T) {
		before := policy.Metadata.ResourceVersion

		policy.Metadata.DisplayName = "updated"
		policy = h.UpdatePolicy(t, policy)

		assert.NotEqual(t, before, policy.Metadata.ResourceVersion)
		assert.Equal(t, before, policy.Metadata.LastResourceVersion)
		assert.Equal(t, "octelium.api.main.core.v1.MainService/UpdatePolicy",
			policy.Metadata.ActorOperation)
	})

	t.Run("NoOpUpdateKeepsResourceVersion", func(t *testing.T) {
		before := policy.Metadata.ResourceVersion

		policy = h.UpdatePolicy(t, policy)

		assert.Equal(t, before, policy.Metadata.ResourceVersion,
			"an update that changes nothing must not create a new resource version")
	})

	t.Run("IdentityIsStable", func(t *testing.T) {
		got, err := h.CoreC().GetPolicy(ctx, &metav1.GetOptions{Name: policy.Metadata.Name})
		require.Nil(t, err)

		assert.Equal(t, policy.Metadata.Uid, got.Metadata.Uid)
		assert.Equal(t, policy.Metadata.CreatedAt.AsTime(), got.Metadata.CreatedAt.AsTime())
		assert.Equal(t, "updated", got.Metadata.DisplayName)
	})

	t.Run("GetByUID", func(t *testing.T) {
		got, err := h.CoreC().GetPolicy(ctx, &metav1.GetOptions{Uid: policy.Metadata.Uid})
		require.Nil(t, err)

		assert.Equal(t, policy.Metadata.Name, got.Metadata.Name)
	})

	t.Run("LabelsRoundTrip", func(t *testing.T) {
		policy.Metadata.Labels = map[string]string{"e2e": "yes", "kind": "policy"}
		policy.Metadata.Annotations = map[string]string{"note": "written by the e2e suite"}
		policy.Metadata.Tags = []string{"e2e"}
		policy = h.UpdatePolicy(t, policy)

		got, err := h.CoreC().GetPolicy(ctx, &metav1.GetOptions{Uid: policy.Metadata.Uid})
		require.Nil(t, err)

		assert.Equal(t, "yes", got.Metadata.Labels["e2e"])
		assert.Equal(t, "policy", got.Metadata.Labels["kind"])
		assert.Equal(t, "written by the e2e suite", got.Metadata.Annotations["note"])
		assert.Equal(t, []string{"e2e"}, got.Metadata.Tags)
	})
}

func testRscServerLifecycle(t *testing.T, h *harness.H) {
	ctx := t.Context()

	name := h.Name()
	policy := newAllowPolicy(t, h, name)

	t.Run("DuplicateNameRejected", func(t *testing.T) {
		_, err := h.CoreC().CreatePolicy(ctx, &corev1.Policy{
			Metadata: &metav1.Metadata{Name: name},
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{harness.AllowAnyRule("allow", 0)},
			},
		})
		require.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err),
			"a duplicate name should be rejected as AlreadyExists, got: %+v", err)
	})

	t.Run("GetUnknownIsNotFound", func(t *testing.T) {
		_, err := h.CoreC().GetPolicy(ctx, &metav1.GetOptions{Name: h.Name()})
		require.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	})

	t.Run("DeleteIsNotIdempotent", func(t *testing.T) {
		_, err := h.CoreC().DeletePolicy(ctx, &metav1.DeleteOptions{Uid: policy.Metadata.Uid})
		require.Nil(t, err)

		_, err = h.CoreC().DeletePolicy(ctx, &metav1.DeleteOptions{Uid: policy.Metadata.Uid})
		require.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))

		_, err = h.CoreC().GetPolicy(ctx, &metav1.GetOptions{Uid: policy.Metadata.Uid})
		require.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	})
}

func testRscServerList(t *testing.T, h *harness.H) {
	ctx := t.Context()

	const total = 24
	prefix := fmt.Sprintf("e2e-list-%s", h.Name())

	var created []string
	createdUIDs := map[string]string{}
	for i := range total {
		p := newAllowPolicy(t, h, fmt.Sprintf("%s-%03d", prefix, i))
		created = append(created, p.Metadata.Name)
		createdUIDs[p.Metadata.Uid] = p.Metadata.Name
	}

	listPage := func(t *testing.T, page, itemsPerPage uint32,
		orderBy *metav1.CommonListOptions_OrderBy) *corev1.PolicyList {

		t.Helper()

		ret, err := h.CoreC().ListPolicy(ctx, &corev1.ListPolicyOptions{
			Common: &metav1.CommonListOptions{
				Page:         page,
				ItemsPerPage: itemsPerPage,
				OrderBy:      orderBy,
			},
		})
		require.Nil(t, err)
		require.NotNil(t, ret.ListResponseMeta)

		return ret
	}

	t.Run("Pagination", func(t *testing.T) {
		const perPage = 7

		first := listPage(t, 0, perPage, nil)
		totalCount := first.ListResponseMeta.TotalCount

		require.True(t, totalCount >= total,
			"the Cluster reports %d Policies, expected at least the %d just created",
			totalCount, total)

		assert.Equal(t, uint32(perPage), first.ListResponseMeta.ItemsPerPage)
		assert.Equal(t, uint32(0), first.ListResponseMeta.Page)

		seen := map[string]struct{}{}
		var page uint32

		for {
			res := listPage(t, page, perPage, nil)

			assert.Equal(t, totalCount, res.ListResponseMeta.TotalCount,
				"the total count changed between pages")
			assert.True(t, uint32(len(res.Items)) <= perPage,
				"page %d returned %d items, more than the requested %d",
				page, len(res.Items), perPage)

			for _, itm := range res.Items {
				if _, ok := seen[itm.Metadata.Uid]; ok {
					t.Fatalf("the Policy %s was returned on more than one page",
						itm.Metadata.Name)
				}
				seen[itm.Metadata.Uid] = struct{}{}
			}

			if !res.ListResponseMeta.HasMore {
				break
			}

			page++
			require.True(t, page < 1000, "the pagination never reported the last page")
		}

		assert.Equal(t, int(totalCount), len(seen),
			"walking every page returned %d Policies, want the reported %d",
			len(seen), totalCount)

		for uid, name := range createdUIDs {
			_, ok := seen[uid]
			assert.True(t, ok, "the Policy %s was never returned by any page", name)
		}
	})

	t.Run("OrderByName", func(t *testing.T) {
		collect := func(mode metav1.CommonListOptions_OrderBy_Mode) []string {
			var ret []string
			var page uint32

			for {
				res := listPage(t, page, 100, &metav1.CommonListOptions_OrderBy{
					Type: metav1.CommonListOptions_OrderBy_NAME,
					Mode: mode,
				})

				for _, itm := range res.Items {
					if strings.HasPrefix(itm.Metadata.Name, prefix) {
						ret = append(ret, itm.Metadata.Name)
					}
				}

				if !res.ListResponseMeta.HasMore {
					return ret
				}
				page++
			}
		}

		asc := collect(metav1.CommonListOptions_OrderBy_ASC)
		require.Equal(t, total, len(asc))
		assert.True(t, sort.StringsAreSorted(asc),
			"NAME ASC returned an unsorted list: %v", asc)

		desc := collect(metav1.CommonListOptions_OrderBy_DESC)
		require.Equal(t, total, len(desc))

		reversed := make([]string, len(desc))
		copy(reversed, desc)
		for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
			reversed[i], reversed[j] = reversed[j], reversed[i]
		}
		assert.Equal(t, asc, reversed, "NAME DESC is not the reverse of NAME ASC")
	})

	t.Run("OrderByCreatedAt", func(t *testing.T) {
		var got []string
		var page uint32

		for {
			res := listPage(t, page, 100, &metav1.CommonListOptions_OrderBy{
				Type: metav1.CommonListOptions_OrderBy_CREATED_AT,
				Mode: metav1.CommonListOptions_OrderBy_ASC,
			})

			for _, itm := range res.Items {
				if strings.HasPrefix(itm.Metadata.Name, prefix) {
					got = append(got, itm.Metadata.Name)
				}
			}

			if !res.ListResponseMeta.HasMore {
				break
			}
			page++
		}

		assert.Equal(t, created, got,
			"CREATED_AT ASC did not return the Policies in creation order")
	})

	t.Run("PageBeyondTheEnd", func(t *testing.T) {
		res := listPage(t, 9000, 10, nil)
		assert.Equal(t, 0, len(res.Items))
	})

	t.Run("PageTooHighRejected", func(t *testing.T) {
		_, err := h.CoreC().ListPolicy(ctx, &corev1.ListPolicyOptions{
			Common: &metav1.CommonListOptions{Page: 20000, ItemsPerPage: 10},
		})
		require.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err),
			"an out-of-range page should be rejected as InvalidArgument, got: %+v", err)
	})
}

func testRscServerResilience(t *testing.T, h *harness.H) {
	svc := h.NewPublicService(t, "default")
	usr := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{
		InlinePolicies: harness.InlineAllowAny("allow"),
	})

	c := h.ServiceClient(svc, h.AccessToken(t, usr))
	h.WaitAllowed(t, c)

	watchers := []string{"octovigil", "nocturne", "ingress"}

	restartsBefore := map[string]int32{}
	for _, component := range watchers {
		restartsBefore[component] = h.ComponentRestarts(t, component)
	}

	replaced := h.RestartComponent(t, "rscserver")
	zap.L().Info("rscServer replaced", zap.Duration("elapsed", replaced))

	h.Eventually(t, "the admin API to answer again", harness.DeploymentBudget,
		func(ctx context.Context) error {
			_, err := h.CoreC().ListPolicy(ctx, &corev1.ListPolicyOptions{})
			return err
		})

	h.WaitAllowed(t, c)

	usr.Spec.Authorization = nil
	usr = h.UpdateUser(t, usr)

	revoke := h.WaitDenied(t, c)

	usr.Spec.Authorization = &corev1.User_Spec_Authorization{
		InlinePolicies: harness.InlineAllowAny("allow"),
	}
	usr = h.UpdateUser(t, usr)

	grant := h.WaitAllowed(t, c)

	zap.L().Info("Authorization propagation after the rscServer restart",
		zap.Duration("revoke", revoke), zap.Duration("grant", grant))

	assert.Less(t, revoke, propagationBudget,
		"revoking access after the rscServer restart took %s, budget is %s",
		revoke, propagationBudget)

	for _, component := range watchers {
		after := h.ComponentRestarts(t, component)
		zap.L().Info("Component restarts across the rscServer restart",
			zap.String("component", component),
			zap.Int32("before", restartsBefore[component]),
			zap.Int32("after", after))
	}

	h.Eventually(t, "every component to be running again", harness.DeploymentBudget,
		func(ctx context.Context) error {
			for _, component := range append([]string{"rscserver"}, watchers...) {
				pods, err := h.ComponentPods(ctx, component)
				if err != nil {
					return err
				}
				for _, pod := range pods {
					if pod.Status.Phase != "Running" {
						return errors.Errorf("the %s pod %s is %s",
							component, pod.Name, pod.Status.Phase)
					}
				}
			}
			return nil
		})
}
