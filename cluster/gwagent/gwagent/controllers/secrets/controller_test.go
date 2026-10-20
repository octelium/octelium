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

package secretcontroller

import (
	"fmt"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tstServer struct {
	certificates []*corev1.Secret
	err          error
}

func (s *tstServer) SetClusterCertificate(crt *corev1.Secret) error {
	s.certificates = append(s.certificates, crt)
	return s.err
}

func TestController(t *testing.T) {
	crt, err := utils_cert.GenerateSelfSignedCert("example.com", []string{"example.com"}, time.Hour)
	require.Nil(t, err)
	chain, err := utils_cert.GetCertificatePEMStr(crt.Certificate)
	require.Nil(t, err)
	key, err := utils_cert.GetPrivateKeyPEM(crt.PrivateKey)
	require.Nil(t, err)
	ready := &corev1.Secret{
		Metadata: &metav1.Metadata{Name: vutils.ClusterCertSecretName},
		Spec:     &corev1.Secret_Spec{}, Status: &corev1.Secret_Status{},
	}
	ucorev1.ToSecret(ready).SetCertificate(chain, string(key))
	for _, tc := range []struct {
		name      string
		mutate    func(*corev1.Secret)
		valid     bool
		nilServer bool
		err       error
	}{
		{name: "ready", valid: true},
		{name: "nilServer", nilServer: true},
		{name: "serverError", valid: true, err: fmt.Errorf("certificate update failed")},
		{name: "otherSecret", mutate: func(sec *corev1.Secret) { sec.Metadata.Name = "other" }},
		{name: "empty", mutate: func(sec *corev1.Secret) {
			sec.Spec = &corev1.Secret_Spec{}
			sec.Status = &corev1.Secret_Status{}
		}},
		{name: "invalidCertificate", mutate: func(sec *corev1.Secret) { ucorev1.ToSecret(sec).SetCertificate("invalid", string(key)) }},
		{name: "invalidKey", mutate: func(sec *corev1.Secret) { ucorev1.ToSecret(sec).SetCertificate(chain, "invalid") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sec := pbutils.Clone(ready).(*corev1.Secret)
			if tc.mutate != nil {
				tc.mutate(sec)
			}
			srv := &tstServer{err: tc.err}
			ctl := NewController(srv)
			if tc.nilServer {
				ctl = NewController(nil)
			}
			assert.ErrorIs(t, ctl.OnAdd(t.Context(), sec), tc.err)
			assert.ErrorIs(t, ctl.OnUpdate(t.Context(), sec, ready), tc.err)
			assert.ErrorIs(t, ctl.OnDelete(t.Context(), sec), tc.err)
			if tc.valid {
				require.Len(t, srv.certificates, 3)
				assert.Same(t, sec, srv.certificates[0])
				assert.Same(t, sec, srv.certificates[1])
				assert.Nil(t, srv.certificates[2])
			} else {
				assert.Empty(t, srv.certificates)
			}
		})
	}
}
