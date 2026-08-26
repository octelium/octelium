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

package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/stretchr/testify/assert"
)

type ekCertOpts struct {
	parent         *utils_cert.Cert
	pub            crypto.PublicKey
	manufacturer   string
	model          string
	version        string
	nonCriticalSAN bool
	noSAN          bool
	keyUsage       x509.KeyUsage
	noKeyUsage     bool
	extKeyUsage    []asn1.ObjectIdentifier
	noExtKeyUsage  bool
	isCA           bool
	notBefore      time.Time
	notAfter       time.Time
}

func generateEKCert(t *testing.T, o *ekCertOpts) *x509.Certificate {
	serialNumber, err := utils_cert.GenerateSerialNumber()
	assert.Nil(t, err)

	now := time.Now()

	notBefore := o.notBefore
	if notBefore.IsZero() {
		notBefore = now.Add(-time.Hour)
	}

	notAfter := o.notAfter
	if notAfter.IsZero() {
		notAfter = now.Add(time.Hour * 24 * 365)
	}

	keyUsage := o.keyUsage
	if keyUsage == 0 && !o.noKeyUsage {
		keyUsage = x509.KeyUsageKeyEncipherment
	}

	extKeyUsage := o.extKeyUsage
	if len(extKeyUsage) == 0 && !o.noExtKeyUsage {
		extKeyUsage = []asn1.ObjectIdentifier{oidTCGKPEKCertificate}
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		UnknownExtKeyUsage:    extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  o.isCA,
	}

	if o.isCA {
		tmpl.KeyUsage = tmpl.KeyUsage | x509.KeyUsageCertSign
	}

	if !o.noSAN {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions,
			generateEKCertSAN(t, o, !o.nonCriticalSAN))
	}

	pub := o.pub
	if pub == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.Nil(t, err)
		pub = &key.PublicKey
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl,
		o.parent.Certificate, pub, o.parent.PrivateKey)
	assert.Nil(t, err)

	ret, err := x509.ParseCertificate(der)
	assert.Nil(t, err)

	return ret
}

func generateEKCertSAN(t *testing.T, o *ekCertOpts, isCritical bool) pkix.Extension {
	utf8Value := func(arg string) asn1.RawValue {
		ret, err := asn1.MarshalWithParams(arg, "utf8")
		assert.Nil(t, err)
		return asn1.RawValue{FullBytes: ret}
	}

	rdns := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			{Type: oidTCGATTPMManufacturer, Value: utf8Value(o.manufacturer)},
			{Type: oidTCGATTPMModel, Value: utf8Value(o.model)},
			{Type: oidTCGATTPMVersion, Value: utf8Value(o.version)},
		},
	}

	rdnsDER, err := asn1.Marshal(rdns)
	assert.Nil(t, err)

	sanDER, err := asn1.Marshal([]asn1.RawValue{
		{
			Class:      asn1.ClassContextSpecific,
			Tag:        4,
			IsCompound: true,
			Bytes:      rdnsDER,
		},
	})
	assert.Nil(t, err)

	return pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: isCritical,
		Value:    sanDER,
	}
}

func newTestFactor(t *testing.T,
	mode corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_Mode,
	trustedCAs []*utils_cert.Cert, intermediateCAs []*utils_cert.Cert) *TPMFactor {

	getPEMs := func(certs []*utils_cert.Cert) []string {
		var ret []string
		for _, crt := range certs {
			pemStr, err := crt.GetCertPEM()
			assert.Nil(t, err)
			ret = append(ret, pemStr)
		}
		return ret
	}

	return &TPMFactor{
		cc: &corev1.ClusterConfig{
			Spec: &corev1.ClusterConfig_Spec{
				Authenticator: &corev1.ClusterConfig_Spec_Authenticator{
					Tpm: &corev1.ClusterConfig_Spec_Authenticator_TPM{
						EndorsementTrust: &corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust{
							Mode:            mode,
							TrustedCAs:      getPEMs(trustedCAs),
							IntermediateCAs: getPEMs(intermediateCAs),
						},
					},
				},
			},
		},
	}
}

func TestVerifyEKCertModes(t *testing.T) {
	rootCA, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	otherCA, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	ekCert := generateEKCert(t, &ekCertOpts{
		parent:       rootCA,
		manufacturer: "id:49465800",
		model:        "SLB9670",
		version:      "id:00070055",
	})

	untrustedEKCert := generateEKCert(t, &ekCertOpts{
		parent:       otherCA,
		manufacturer: "id:49465800",
		model:        "SLB9670",
		version:      "id:00070055",
	})

	rootSum := sha256.Sum256(rootCA.Certificate.Raw)
	ekCertSum := sha256.Sum256(ekCert.Raw)

	{
		fctr := newTestFactor(t,
			corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_DISABLED, nil, nil)

		endorsement, err := fctr.verifyEKCert(ekCert, nil)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_NOT_ATTEMPTED,
			endorsement.Verification)
		assert.Equal(t, ekCertSum[:], endorsement.CertificateSHA256)
		assert.Nil(t, endorsement.TrustedCASHA256)
		assert.Nil(t, endorsement.VerifiedAt)
	}

	{
		fctr := newTestFactor(t,
			corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_MODE_UNKNOWN, nil, nil)

		endorsement, err := fctr.verifyEKCert(ekCert, nil)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_NOT_ATTEMPTED,
			endorsement.Verification)
	}

	{
		fctr := newTestFactor(t,
			corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_DISABLED,
			[]*utils_cert.Cert{rootCA}, nil)

		endorsement, err := fctr.verifyEKCert(ekCert, nil)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_VERIFIED,
			endorsement.Verification)
		assert.Equal(t, rootSum[:], endorsement.TrustedCASHA256)
		assert.NotNil(t, endorsement.VerifiedAt)
	}

	{
		fctr := newTestFactor(t,
			corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_DISABLED,
			[]*utils_cert.Cert{rootCA}, nil)

		endorsement, err := fctr.verifyEKCert(untrustedEKCert, nil)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_FAILED,
			endorsement.Verification)
		assert.Nil(t, endorsement.TrustedCASHA256)
		assert.NotNil(t, endorsement.VerifiedAt)
	}

	for _, mode := range []corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_Mode{
		corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_VERIFY_IF_PRESENT,
		corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_REQUIRE_VERIFIED,
	} {
		{
			fctr := newTestFactor(t, mode, []*utils_cert.Cert{rootCA}, nil)

			endorsement, err := fctr.verifyEKCert(ekCert, nil)
			assert.Nil(t, err)
			assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_VERIFIED,
				endorsement.Verification)
			assert.Equal(t, rootSum[:], endorsement.TrustedCASHA256)
		}

		{
			fctr := newTestFactor(t, mode, []*utils_cert.Cert{rootCA}, nil)

			_, err := fctr.verifyEKCert(untrustedEKCert, nil)
			assert.NotNil(t, err)
		}

		{
			fctr := newTestFactor(t, mode, nil, nil)

			_, err := fctr.verifyEKCert(ekCert, nil)
			assert.NotNil(t, err)
		}
	}
}

func TestVerifyEKCertCriticalSAN(t *testing.T) {
	rootCA, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	ekCert := generateEKCert(t, &ekCertOpts{
		parent:       rootCA,
		manufacturer: "id:49465800",
		model:        "SLB9670",
		version:      "id:00070055",
	})

	assert.True(t, len(ekCert.UnhandledCriticalExtensions) > 0)

	{
		_, err := ekCert.Verify(x509.VerifyOptions{
			Roots:     mustPoolOf(t, rootCA),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		assert.NotNil(t, err)
	}

	fctr := newTestFactor(t,
		corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_REQUIRE_VERIFIED,
		[]*utils_cert.Cert{rootCA}, nil)

	endorsement, err := fctr.verifyEKCert(ekCert, nil)
	assert.Nil(t, err)
	assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_VERIFIED,
		endorsement.Verification)

	assert.Equal(t, uint32(1229346816), endorsement.ManufacturerID)
	assert.Equal(t, "Infineon", endorsement.Manufacturer)
	assert.Equal(t, "SLB9670", endorsement.Model)
	assert.Equal(t, "id:00070055", endorsement.Version)
}

func TestVerifyEKCertIntermediates(t *testing.T) {
	rootCA, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	interCA, err := utils_cert.GenerateIntermediateCATmp("Test Intermediate CA", rootCA)
	assert.Nil(t, err)

	ekCert := generateEKCert(t, &ekCertOpts{
		parent:       interCA,
		manufacturer: "id:49465800",
		model:        "SLB9670",
		version:      "id:00070055",
	})

	rootSum := sha256.Sum256(rootCA.Certificate.Raw)

	{
		fctr := newTestFactor(t,
			corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_REQUIRE_VERIFIED,
			[]*utils_cert.Cert{rootCA}, nil)

		_, err := fctr.verifyEKCert(ekCert, nil)
		assert.NotNil(t, err)
	}

	{
		fctr := newTestFactor(t,
			corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_REQUIRE_VERIFIED,
			[]*utils_cert.Cert{rootCA}, []*utils_cert.Cert{interCA})

		endorsement, err := fctr.verifyEKCert(ekCert, nil)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_VERIFIED,
			endorsement.Verification)
		assert.Equal(t, rootSum[:], endorsement.TrustedCASHA256)
	}

	{
		fctr := newTestFactor(t,
			corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_REQUIRE_VERIFIED,
			[]*utils_cert.Cert{rootCA}, nil)

		endorsement, err := fctr.verifyEKCert(ekCert,
			[][]byte{interCA.Certificate.Raw})
		assert.Nil(t, err)
		assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_VERIFIED,
			endorsement.Verification)
		assert.Equal(t, rootSum[:], endorsement.TrustedCASHA256)
	}
}

func TestVerifyEKCertUntrustedClientChain(t *testing.T) {
	rootCA, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	rogueCA, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	rogueEKCert := generateEKCert(t, &ekCertOpts{
		parent:       rogueCA,
		manufacturer: "id:49465800",
		model:        "SLB9670",
		version:      "id:00070055",
	})

	fctr := newTestFactor(t,
		corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_REQUIRE_VERIFIED,
		[]*utils_cert.Cert{rootCA}, nil)

	_, err = fctr.verifyEKCert(rogueEKCert, [][]byte{rogueCA.Certificate.Raw})
	assert.NotNil(t, err)
}

func TestVerifyEKCertProfile(t *testing.T) {
	rootCA, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	newFactor := func() *TPMFactor {
		return newTestFactor(t,
			corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_REQUIRE_VERIFIED,
			[]*utils_cert.Cert{rootCA}, nil)
	}

	{
		ekCert := generateEKCert(t, &ekCertOpts{
			parent:     rootCA,
			noKeyUsage: true,
			noSAN:      true,
		})

		endorsement, err := newFactor().verifyEKCert(ekCert, nil)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_VERIFIED,
			endorsement.Verification)
		assert.Equal(t, uint32(0), endorsement.ManufacturerID)
		assert.Equal(t, "", endorsement.Manufacturer)
	}

	{
		ekCert := generateEKCert(t, &ekCertOpts{
			parent:        rootCA,
			noExtKeyUsage: true,
			noSAN:         true,
		})

		endorsement, err := newFactor().verifyEKCert(ekCert, nil)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_VERIFIED,
			endorsement.Verification)
	}

	{
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		assert.Nil(t, err)

		ekCert := generateEKCert(t, &ekCertOpts{
			parent:   rootCA,
			pub:      &key.PublicKey,
			keyUsage: x509.KeyUsageKeyAgreement,
			noSAN:    true,
		})

		endorsement, err := newFactor().verifyEKCert(ekCert, nil)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_VERIFIED,
			endorsement.Verification)
	}

	{
		ekCert := generateEKCert(t, &ekCertOpts{
			parent:   rootCA,
			keyUsage: x509.KeyUsageDigitalSignature,
			noSAN:    true,
		})

		_, err := newFactor().verifyEKCert(ekCert, nil)
		assert.NotNil(t, err)
	}

	{
		ekCert := generateEKCert(t, &ekCertOpts{
			parent:      rootCA,
			extKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}},
			noSAN:       true,
		})

		_, err := newFactor().verifyEKCert(ekCert, nil)
		assert.NotNil(t, err)
	}

	{
		ekCert := generateEKCert(t, &ekCertOpts{
			parent: rootCA,
			isCA:   true,
			noSAN:  true,
		})

		_, err := newFactor().verifyEKCert(ekCert, nil)
		assert.NotNil(t, err)
	}

	{
		now := time.Now()
		ekCert := generateEKCert(t, &ekCertOpts{
			parent:    rootCA,
			notBefore: now.Add(-time.Hour * 48),
			notAfter:  now.Add(-time.Hour * 24),
			noSAN:     true,
		})

		_, err := newFactor().verifyEKCert(ekCert, nil)
		assert.NotNil(t, err)
	}
}

func TestParseTCGVendorID(t *testing.T) {
	assert.Equal(t, uint32(1229346816), parseTCGVendorID("id:49465800"))
	assert.Equal(t, uint32(1229346816), parseTCGVendorID("49465800"))
	assert.Equal(t, uint32(0), parseTCGVendorID(""))
	assert.Equal(t, uint32(0), parseTCGVendorID("id:"))
	assert.Equal(t, uint32(0), parseTCGVendorID("Infineon"))
	assert.Equal(t, uint32(0), parseTCGVendorID("id:FFFFFFFFFF"))
}

func TestParseEKCertSubjectAltName(t *testing.T) {
	rootCA, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	{
		ekCert := generateEKCert(t, &ekCertOpts{
			parent:         rootCA,
			manufacturer:   "id:414D4400",
			model:          "AMD",
			version:        "id:00030037",
			nonCriticalSAN: true,
		})

		manufacturerID, model, version := parseEKCertSubjectAltName(ekCert)
		assert.Equal(t, uint32(1095582720), manufacturerID)
		assert.Equal(t, "AMD", model)
		assert.Equal(t, "id:00030037", version)
	}

	{
		ekCert := generateEKCert(t, &ekCertOpts{
			parent: rootCA,
			noSAN:  true,
		})

		manufacturerID, model, version := parseEKCertSubjectAltName(ekCert)
		assert.Equal(t, uint32(0), manufacturerID)
		assert.Equal(t, "", model)
		assert.Equal(t, "", version)
	}
}

func TestTruncateEndorsementInfo(t *testing.T) {
	assert.Equal(t, "abc", truncateEndorsementInfo("abc"))
	assert.Equal(t, maxEndorsementInfoLen,
		len(truncateEndorsementInfo(string(make([]byte, maxEndorsementInfoLen+100)))))
}

func mustPoolOf(t *testing.T, certs ...*utils_cert.Cert) *x509.CertPool {
	ret := x509.NewCertPool()
	for _, crt := range certs {
		ret.AddCert(crt.Certificate)
	}
	return ret
}

func TestVerifyEKCertInvalidClientIntermediate(t *testing.T) {
	rootCA, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	ekCert := generateEKCert(t, &ekCertOpts{
		parent:       rootCA,
		manufacturer: "id:49465800",
		model:        "SLB9670",
		version:      "id:00070055",
	})

	{
		fctr := newTestFactor(t,
			corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_DISABLED,
			[]*utils_cert.Cert{rootCA}, nil)

		endorsement, err := fctr.verifyEKCert(ekCert, [][]byte{[]byte("not a certificate")})
		assert.Nil(t, err)
		assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_FAILED,
			endorsement.Verification)
	}

	{
		fctr := newTestFactor(t,
			corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_REQUIRE_VERIFIED,
			[]*utils_cert.Cert{rootCA}, nil)

		_, err := fctr.verifyEKCert(ekCert, [][]byte{[]byte("not a certificate")})
		assert.NotNil(t, err)
	}
}
