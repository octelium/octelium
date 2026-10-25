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

package vcache

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	c, err := NewCache(ctx)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Port: uint32(tests.GetPort()),
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com",
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	{
		c.SetService(svc)
		out := c.GetService()
		assert.True(t, pbutils.IsEqual(svc, out))
	}
	{
		svc.Spec.IsDisabled = true

		c.SetService(svc)
		out := c.GetService()
		assert.True(t, pbutils.IsEqual(svc, out))
	}

	{
		svc.Spec.IsDisabled = false

		c.SetService(svc)
		out := c.GetService()
		assert.True(t, pbutils.IsEqual(svc, out))
	}

	{
		svc.Spec.Port = uint32(utilrand.GetRandomRangeMath(10000, 50000))
		c.SetService(svc)
		out := c.GetService()
		assert.True(t, pbutils.IsEqual(svc, out))
	}
}

func TestServiceIsolation(t *testing.T) {
	c, err := NewCache(t.Context())
	require.Nil(t, err)
	assert.Nil(t, c.GetService())

	svc := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name:   "test.default",
			Labels: map[string]string{"owner": "original"},
		},
		Spec: &corev1.Service_Spec{
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "https://example.com"},
				},
			},
		},
	}
	c.SetService(svc)
	svc.Metadata.Labels["owner"] = "changed"
	svc.Spec.Config.Upstream.Type = &corev1.Service_Spec_Config_Upstream_Url{Url: "https://other.example.com"}

	got := c.GetService()
	assert.Equal(t, "original", got.Metadata.Labels["owner"])
	assert.Equal(t, "https://example.com", got.Spec.Config.Upstream.GetUrl())
	got.Metadata.Labels["owner"] = "reader"
	got.Spec.IsDisabled = true
	assert.Equal(t, "original", c.GetService().Metadata.Labels["owner"])
	assert.False(t, c.GetService().Spec.IsDisabled)
}

func TestServiceConcurrentAccess(t *testing.T) {
	c, err := NewCache(t.Context())
	require.Nil(t, err)
	c.SetService(&corev1.Service{
		Metadata: &metav1.Metadata{Name: "initial"},
		Spec:     &corev1.Service_Spec{Config: &corev1.Service_Spec_Config{Name: "initial"}},
	})

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for j := range 32 {
				name := fmt.Sprintf("service-%d-%d", i, j)
				c.SetService(&corev1.Service{
					Metadata: &metav1.Metadata{Name: name},
					Spec:     &corev1.Service_Spec{Config: &corev1.Service_Spec_Config{Name: name}},
				})
				got := c.GetService()
				assert.Equal(t, got.Metadata.Name, got.Spec.Config.Name)
				got.Metadata.Name = "reader"
			}
		})
	}
	wg.Wait()
	got := c.GetService()
	assert.Equal(t, got.Metadata.Name, got.Spec.Config.Name)
}
