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

package user

import (
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestListService(t *testing.T) {

}

func TestServiceDiscovery(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	s, adminS := newFakeServers(tst.C)
	ns, err := adminS.CreateNamespace(t.Context(), &corev1.Namespace{Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)}, Spec: &corev1.Namespace_Spec{}})
	require.Nil(t, err)
	services := map[string]*corev1.Service{}
	for _, tc := range []struct {
		name   string
		mode   corev1.Service_Spec_Mode
		hidden bool
	}{
		{"http", corev1.Service_Spec_HTTP, false},
		{"tcp", corev1.Service_Spec_TCP, false},
		{"hidden", corev1.Service_Spec_HTTP, true},
	} {
		svc, err := adminS.CreateService(t.Context(), &corev1.Service{
			Metadata: &metav1.Metadata{Name: fmt.Sprintf("%s.%s", tc.name, ns.Metadata.Name), DisplayName: tc.name, Labels: map[string]string{"private": "value"}},
			Spec: &corev1.Service_Spec{Mode: tc.mode, Port: 8080, Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "http://example.com:8080"}},
			}},
		})
		require.Nil(t, err)
		if tc.hidden {
			svc.Metadata.IsUserHidden = true
			svc, err = s.octeliumC.CoreC().UpdateService(t.Context(), svc)
			require.Nil(t, err)
		}
		services[tc.name] = svc
	}
	list, err := s.ListService(t.Context(), &userv1.ListServiceOptions{Namespace: ns.Metadata.Name})
	require.Nil(t, err)
	assert.Equal(t, "user/v1", list.ApiVersion)
	assert.Equal(t, "ServiceList", list.Kind)
	require.Len(t, list.Items, 2)
	assert.EqualValues(t, 2, list.ListResponseMeta.TotalCount)
	for _, svc := range list.Items {
		assert.Equal(t, ns.Metadata.Name, svc.Status.Namespace)
		assert.Nil(t, svc.Metadata.Labels)
		assert.Nil(t, svc.Metadata.SpecLabels)
		assert.Nil(t, svc.Metadata.SystemLabels)
		assert.NotEqual(t, services["hidden"].Metadata.Uid, svc.Metadata.Uid)
	}
	list, err = s.ListService(t.Context(), &userv1.ListServiceOptions{Namespace: ns.Metadata.Name, Type: userv1.Service_Spec_HTTP})
	require.Nil(t, err)
	require.Len(t, list.Items, 1)
	assert.Equal(t, services["http"].Metadata.Uid, list.Items[0].Metadata.Uid)
	list, err = s.ListService(t.Context(), &userv1.ListServiceOptions{Namespace: ns.Metadata.Name, Common: &metav1.CommonListOptions{ItemsPerPage: 1}})
	require.Nil(t, err)
	require.Len(t, list.Items, 1)
	assert.EqualValues(t, 2, list.ListResponseMeta.TotalCount)
	got, err := s.GetService(t.Context(), &metav1.GetOptions{Uid: services["http"].Metadata.Uid})
	require.Nil(t, err)
	assert.Equal(t, services["http"].Metadata.Name, got.Metadata.Name)
	for _, opts := range []*metav1.GetOptions{{Name: services["hidden"].Metadata.Name}, {Uid: services["hidden"].Metadata.Uid}} {
		_, err := s.GetService(t.Context(), opts)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	}
	_, err = s.ListService(t.Context(), &userv1.ListServiceOptions{Namespace: "invalid/name"})
	assert.NotNil(t, err)
	_, err = s.ListService(t.Context(), &userv1.ListServiceOptions{Namespace: "missing-namespace"})
	assert.Equal(t, codes.NotFound, status.Code(err))
	ns.Metadata.IsUserHidden = true
	_, err = s.octeliumC.CoreC().UpdateNamespace(t.Context(), ns)
	require.Nil(t, err)
	_, err = s.ListService(t.Context(), &userv1.ListServiceOptions{Namespace: ns.Metadata.Name})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = s.GetService(t.Context(), &metav1.GetOptions{Name: "missing.default"})
	assert.Equal(t, codes.NotFound, status.Code(err))
	_, err = s.GetService(t.Context(), &metav1.GetOptions{Name: "invalid/name"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = tst.C.OcteliumC.CoreC().GetService(t.Context(), &rmetav1.GetOptions{Uid: services["http"].Metadata.Uid})
	assert.Nil(t, err)
}
