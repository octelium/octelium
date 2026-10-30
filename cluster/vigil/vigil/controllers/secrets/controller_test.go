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

package certcontroller

import (
	"errors"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testServer struct {
	certs []*corev1.Secret
	err   error
}

func (s *testServer) SetClusterCertificate(crt *corev1.Secret) error {
	s.certs = append(s.certs, crt)
	return s.err
}

type testSecretManager struct {
	sets    []*corev1.Secret
	deletes []*corev1.Secret
}

func (s *testSecretManager) Set(secret *corev1.Secret) {
	s.sets = append(s.sets, secret)
}

func (s *testSecretManager) Delete(secret *corev1.Secret) {
	s.deletes = append(s.deletes, secret)
}

type testServiceGetter struct {
	namespace string
}

func (s *testServiceGetter) GetService() *corev1.Service {
	return &corev1.Service{Status: &corev1.Service_Status{NamespaceRef: &metav1.ObjectReference{Name: s.namespace}}}
}

func newTestCertificate(t *testing.T, namespace string) *corev1.Secret {
	t.Helper()
	crt, err := utils_cert.GenerateSelfSignedCert("service.example.com", []string{"service.example.com"}, time.Hour)
	require.Nil(t, err)
	certPEM, err := crt.GetCertPEM()
	require.Nil(t, err)
	keyPEM, err := crt.GetPrivateKeyPEM()
	require.Nil(t, err)
	secret := &corev1.Secret{Metadata: &metav1.Metadata{Name: "crt-ns-" + namespace}}
	ucorev1.ToSecret(secret).SetCertificate(certPEM, keyPEM)
	return secret
}

func TestSecretEventsAndCertificateRotation(t *testing.T) {
	srv := &testServer{}
	sm := &testSecretManager{}
	c := NewController(srv, sm, &testServiceGetter{namespace: "team"})
	secret := &corev1.Secret{Metadata: &metav1.Metadata{Name: "password"}}
	require.Nil(t, c.OnAdd(t.Context(), secret))
	require.Nil(t, c.OnUpdate(t.Context(), secret, secret))
	require.Nil(t, c.OnDelete(t.Context(), secret))
	assert.Equal(t, []*corev1.Secret{secret, secret}, sm.sets)
	assert.Equal(t, []*corev1.Secret{secret}, sm.deletes)
	assert.Empty(t, srv.certs)
	first := newTestCertificate(t, "team")
	second := newTestCertificate(t, "team")
	require.Nil(t, c.OnAdd(t.Context(), first))
	require.Nil(t, c.OnUpdate(t.Context(), second, first))
	require.Nil(t, c.OnDelete(t.Context(), second))
	assert.Equal(t, []*corev1.Secret{first, second, nil}, srv.certs)
	assert.Len(t, sm.sets, 2)
}

func TestCertificateNamespaceAndCallbackError(t *testing.T) {
	srv := &testServer{err: errors.New("certificate install failed")}
	sm := &testSecretManager{}
	c := NewController(srv, sm, nil)
	other := newTestCertificate(t, "other")
	require.Nil(t, c.OnAdd(t.Context(), other))
	assert.Empty(t, srv.certs)
	assert.Equal(t, []*corev1.Secret{other}, sm.sets)
	cert := newTestCertificate(t, "default")
	assert.ErrorIs(t, c.OnAdd(t.Context(), cert), srv.err)
	assert.ErrorIs(t, c.OnUpdate(t.Context(), cert, cert), srv.err)
	assert.ErrorIs(t, c.OnDelete(t.Context(), cert), srv.err)
}

func TestDeletedUnreadyClusterCertificateClearsListener(t *testing.T) {
	srv := &testServer{}
	sm := &testSecretManager{}
	c := NewController(srv, sm, nil)
	first := newTestCertificate(t, "default")
	require.Nil(t, c.OnAdd(t.Context(), first))
	unready := &corev1.Secret{Metadata: &metav1.Metadata{Name: first.Metadata.Name}}
	require.Nil(t, c.OnUpdate(t.Context(), unready, first))
	require.Nil(t, c.OnDelete(t.Context(), unready))
	assert.Equal(t, []*corev1.Secret{first, nil}, srv.certs)
}
