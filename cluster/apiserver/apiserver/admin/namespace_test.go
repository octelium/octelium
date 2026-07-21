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

package admin

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

func genTestNamespace() *corev1.Namespace {
	return &corev1.Namespace{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Namespace_Spec{},
	}
}

func genTestNamespaceService(name string, namespace string) *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.%s", name, namespace),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com",
					},
				},
			},
		},
	}
}

func TestNamespace(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	ns := genTestNamespace()

	item, err := srv.CreateNamespace(ctx, ns)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, ns.Metadata.Name, item.Metadata.Name)
	assert.NotNil(t, item.Status)

	{
		_, err = srv.CreateNamespace(ctx, ns)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err), "%+v", err)
	}

	{
		ret, err := srv.GetNamespace(ctx, &metav1.GetOptions{Uid: item.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, item.Metadata.Uid, ret.Metadata.Uid)

		ret, err = srv.GetNamespace(ctx, &metav1.GetOptions{Name: item.Metadata.Name})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, item.Metadata.Uid, ret.Metadata.Uid)
	}

	{
		_, err = srv.GetNamespace(ctx, &metav1.GetOptions{
			Name: utilrand.GetRandomStringCanonical(8),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)
	}

	{
		_, err = srv.GetNamespace(ctx, &metav1.GetOptions{})
		assert.NotNil(t, err)
	}

	{
		attrs, err := structpb.NewStruct(map[string]any{
			"myKey": "myValue",
		})
		assert.Nil(t, err, "%+v", err)

		item.Spec.Attrs = attrs
		updated, err := srv.UpdateNamespace(ctx, item)
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, updated.Spec.Attrs)
		item = updated
	}

	{
		_, err = srv.UpdateNamespace(ctx, genTestNamespace())
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)
	}

	{
		_, err = srv.DeleteNamespace(ctx, &metav1.DeleteOptions{Uid: item.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.DeleteNamespace(ctx, &metav1.DeleteOptions{Uid: item.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)
	}
}

func TestValidateNamespace(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	policy, err := srv.CreatePolicy(ctx, &corev1.Policy{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{
							MatchAny: true,
						},
					},
					Effect: corev1.Policy_Spec_Rule_ALLOW,
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	invalids := []*corev1.Namespace{
		{},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		},
		{
			Spec: &corev1.Namespace_Spec{},
		},
		{
			Metadata: &metav1.Metadata{Name: strings.Repeat("a", 256)},
			Spec:     &corev1.Namespace_Spec{},
		},
		{
			Metadata: &metav1.Metadata{Name: "octelium"},
			Spec:     &corev1.Namespace_Spec{},
		},
		{
			Metadata: &metav1.Metadata{Name: "octelium-api"},
			Spec:     &corev1.Namespace_Spec{},
		},
		{
			Metadata: &metav1.Metadata{Name: "local"},
			Spec:     &corev1.Namespace_Spec{},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Namespace_Spec{
				Authorization: &corev1.Namespace_Spec_Authorization{
					Policies: []string{utilrand.GetRandomStringCanonical(8)},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Namespace_Spec{
				Authorization: &corev1.Namespace_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Name: utilrand.GetRandomStringCanonical(8),
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Condition: &corev1.Condition{
											Type: &corev1.Condition_Match{
												Match: "!!!!",
											},
										},
										Effect: corev1.Policy_Spec_Rule_ALLOW,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, invalid := range invalids {
		_, err = srv.CreateNamespace(ctx, invalid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	valids := []*corev1.Namespace{
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec:     &corev1.Namespace_Spec{},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Namespace_Spec{
				Authorization: &corev1.Namespace_Spec_Authorization{
					Policies: []string{policy.Metadata.Name},
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Name: utilrand.GetRandomStringCanonical(8),
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
										Effect: corev1.Policy_Spec_Rule_ALLOW,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, valid := range valids {
		_, err = srv.CreateNamespace(ctx, valid)
		assert.Nil(t, err, "%+v", err)
	}
}

func TestNamespaceServiceConflict(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	name := utilrand.GetRandomStringCanonical(8)

	_, err = srv.CreateService(ctx, genTestNamespaceService(name, "default"))
	assert.Nil(t, err, "%+v", err)

	_, err = srv.CreateNamespace(ctx, &corev1.Namespace{
		Metadata: &metav1.Metadata{Name: name},
		Spec:     &corev1.Namespace_Spec{},
	})
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
}

func TestDeleteNamespaceWithServices(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	ns, err := srv.CreateNamespace(ctx, genTestNamespace())
	assert.Nil(t, err, "%+v", err)

	svc, err := srv.CreateService(ctx,
		genTestNamespaceService(utilrand.GetRandomStringCanonical(8), ns.Metadata.Name))
	assert.Nil(t, err, "%+v", err)

	_, err = srv.DeleteNamespace(ctx, &metav1.DeleteOptions{Uid: ns.Metadata.Uid})
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)

	_, err = srv.DeleteService(ctx, &metav1.DeleteOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err, "%+v", err)

	_, err = srv.DeleteNamespace(ctx, &metav1.DeleteOptions{Uid: ns.Metadata.Uid})
	assert.Nil(t, err, "%+v", err)
}
