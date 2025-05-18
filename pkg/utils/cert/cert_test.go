// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils_cert

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateCARoot(t *testing.T) {
	ca, err := GenerateCARoot()
	assert.Nil(t, err)
	assert.True(t, ca.Certificate.IsCA)
	assert.True(t, ca.Certificate.BasicConstraintsValid)
	assert.True(t, time.Now().Add(-1*time.Minute).Before(ca.Certificate.NotBefore))
	assert.True(t, time.Now().After(ca.Certificate.NotBefore))
	assert.Equal(t, ca.Certificate.KeyUsage&x509.KeyUsageCertSign, x509.KeyUsageCertSign)
}

func TestParseX509LeafCertificateChainPEM(t *testing.T) {
	ca, err := GenerateCARoot()
	assert.Nil(t, err)

	caPEM, err := ca.GetCertPEM()
	assert.Nil(t, err)

	_, err = ParseX509LeafCertificateChainPEM([]byte(caPEM))
	assert.Nil(t, err)

}

func TestParsePrivateKeyPEM(t *testing.T) {
	ca, err := GenerateCARoot()
	assert.Nil(t, err)

	caPEM, err := ca.GetPrivateKeyPEM()
	assert.Nil(t, err)

	_, err = ParsePrivateKeyPEM([]byte(caPEM))
	assert.Nil(t, err)

}
