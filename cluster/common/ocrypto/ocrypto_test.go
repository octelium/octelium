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

package ocrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/stretchr/testify/assert"
)

func genCertSecret(t *testing.T) *corev1.Secret {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err, "%+v", err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	assert.Nil(t, err, "%+v", err)

	keyDER, err := x509.MarshalECPrivateKey(priv)
	assert.Nil(t, err, "%+v", err)

	ret := &corev1.Secret{
		Metadata: &metav1.Metadata{Name: "crt-ns-default"},
		Spec:     &corev1.Secret_Spec{},
		Status:   &corev1.Secret_Status{},
	}

	ucorev1.ToSecret(ret).SetCertificate(
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
	)

	return ret
}

func TestGetTLSCertificate(t *testing.T) {

	for _, sec := range []*corev1.Secret{
		nil,
		{},
		{Metadata: &metav1.Metadata{Name: "crt-ns-default"}},
		{
			Metadata: &metav1.Metadata{Name: "crt-ns-default"},
			Spec:     &corev1.Secret_Spec{},
		},
	} {
		crt, err := GetTLSCertificate(sec)
		assert.NotNil(t, err)
		assert.Nil(t, crt)
	}

	{
		crt, err := GetTLSCertificate(genCertSecret(t))
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, crt)
	}
}
