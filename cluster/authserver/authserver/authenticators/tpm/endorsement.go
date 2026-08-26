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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strconv"
	"strings"

	"github.com/google/go-attestation/attest"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var (
	oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTCGKPEKCertificate      = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	oidTCGATTPMManufacturer    = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTCGATTPMModel           = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTCGATTPMVersion         = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
)

const maxEndorsementInfoLen = 256

func (c *TPMFactor) getEndorsementTrust() *corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust {
	return c.cc.GetSpec().GetAuthenticator().GetTpm().GetEndorsementTrust()
}

func (c *TPMFactor) isEKCertRequired() bool {
	return c.getEndorsementTrust().GetMode() ==
		corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_REQUIRE_VERIFIED
}

func isEndorsementTrustEnforcing(mode corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_Mode) bool {
	switch mode {
	case corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_VERIFY_IF_PRESENT,
		corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_REQUIRE_VERIFIED:
		return true
	default:
		return false
	}
}

func (c *TPMFactor) verifyEKCert(ekCert *x509.Certificate,
	intermediatesDER [][]byte) (*corev1.Authenticator_Status_Info_TPM_Endorsement, error) {

	trust := c.getEndorsementTrust()

	ret := &corev1.Authenticator_Status_Info_TPM_Endorsement{}
	setEKCertInfo(ret, ekCert)

	if len(trust.GetTrustedCAs()) == 0 {
		if isEndorsementTrustEnforcing(trust.GetMode()) {
			return nil, errors.Errorf("No trustedCAs are set for the endorsement key certificates")
		}

		ret.Verification = corev1.Authenticator_Status_Info_TPM_Endorsement_NOT_ATTEMPTED
		return ret, nil
	}

	roots, err := parseEndorsementCAs(trust.GetTrustedCAs())
	if err != nil {
		return nil, errors.Errorf("Could not parse the trustedCAs: %+v", err)
	}

	intermediates, err := parseEndorsementCAs(trust.GetIntermediateCAs())
	if err != nil {
		return nil, errors.Errorf("Could not parse the intermediateCAs: %+v", err)
	}

	ret.VerifiedAt = pbutils.Now()

	trustedCA, err := verifyEKCertChain(ekCert, roots, intermediates, intermediatesDER)
	if err != nil {
		if isEndorsementTrustEnforcing(trust.GetMode()) {
			return nil, errors.Errorf("Could not verify the ekCert: %+v", err)
		}

		zap.L().Debug("Could not verify the ekCert", zap.Error(err))
		ret.Verification = corev1.Authenticator_Status_Info_TPM_Endorsement_FAILED
		return ret, nil
	}

	sum := sha256.Sum256(trustedCA.Raw)
	ret.TrustedCASHA256 = sum[:]
	ret.Verification = corev1.Authenticator_Status_Info_TPM_Endorsement_VERIFIED

	return ret, nil
}

func parseEndorsementCAs(caPEMs []string) (*x509.CertPool, error) {
	ret := x509.NewCertPool()

	for _, caPEM := range caPEMs {
		ca, err := utils_cert.ParseX509LeafCertificateChainPEM([]byte(caPEM))
		if err != nil {
			return nil, err
		}

		if !ca.IsCA {
			return nil, errors.Errorf("The CA %s is not a CA certificate", ca.Subject.String())
		}

		ret.AddCert(ca)
	}

	return ret, nil
}

func verifyEKCertChain(ekCert *x509.Certificate, roots *x509.CertPool,
	intermediates *x509.CertPool, intermediatesDER [][]byte) (*x509.Certificate, error) {

	if err := checkEKCertProfile(ekCert); err != nil {
		return nil, err
	}

	for _, der := range intermediatesDER {
		crt, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.Errorf("Could not parse an ekCert intermediate: %+v", err)
		}
		intermediates.AddCert(crt)
	}

	chains, err := withoutCriticalSAN(ekCert).Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, err
	}

	chain := chains[0]

	return chain[len(chain)-1], nil
}

func checkEKCertProfile(ekCert *x509.Certificate) error {
	if ekCert.IsCA {
		return errors.Errorf("The ekCert is a CA certificate")
	}

	if ekCert.KeyUsage != 0 &&
		ekCert.KeyUsage&(x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) == 0 {
		return errors.Errorf("The ekCert has an invalid keyUsage")
	}

	if len(ekCert.ExtKeyUsage) > 0 || len(ekCert.UnknownExtKeyUsage) > 0 {
		if !hasEKCertExtKeyUsage(ekCert) {
			return errors.Errorf("The ekCert has an invalid extKeyUsage")
		}
	}

	return nil
}

func hasEKCertExtKeyUsage(ekCert *x509.Certificate) bool {
	for _, eku := range ekCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageAny {
			return true
		}
	}

	for _, oid := range ekCert.UnknownExtKeyUsage {
		if oid.Equal(oidTCGKPEKCertificate) {
			return true
		}
	}

	return false
}

func withoutCriticalSAN(ekCert *x509.Certificate) *x509.Certificate {
	ret := *ekCert
	ret.UnhandledCriticalExtensions = nil

	for _, oid := range ekCert.UnhandledCriticalExtensions {
		if oid.Equal(oidExtensionSubjectAltName) {
			continue
		}
		ret.UnhandledCriticalExtensions = append(ret.UnhandledCriticalExtensions, oid)
	}

	return &ret
}

func setEKCertInfo(ret *corev1.Authenticator_Status_Info_TPM_Endorsement, ekCert *x509.Certificate) {
	sum := sha256.Sum256(ekCert.Raw)
	ret.CertificateSHA256 = sum[:]

	manufacturerID, model, version := parseEKCertSubjectAltName(ekCert)

	ret.ManufacturerID = manufacturerID
	ret.Manufacturer = attest.TCGVendorID(manufacturerID).String()
	ret.Model = model
	ret.Version = version
}

func parseEKCertSubjectAltName(ekCert *x509.Certificate) (uint32, string, string) {
	var manufacturerID uint32
	var model string
	var version string

	for _, ext := range ekCert.Extensions {
		if !ext.Id.Equal(oidExtensionSubjectAltName) {
			continue
		}

		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &seq); err != nil {
			continue
		}

		rest := seq.Bytes
		for len(rest) > 0 {
			var val asn1.RawValue
			var err error

			rest, err = asn1.Unmarshal(rest, &val)
			if err != nil {
				break
			}

			if val.Class != asn1.ClassContextSpecific || val.Tag != 4 {
				continue
			}

			var rdns pkix.RDNSequence
			if _, err := asn1.Unmarshal(val.Bytes, &rdns); err != nil {
				continue
			}

			for _, rdn := range rdns {
				for _, atv := range rdn {
					atvVal, ok := atv.Value.(string)
					if !ok {
						continue
					}

					switch {
					case atv.Type.Equal(oidTCGATTPMManufacturer):
						manufacturerID = parseTCGVendorID(atvVal)
					case atv.Type.Equal(oidTCGATTPMModel):
						model = truncateEndorsementInfo(atvVal)
					case atv.Type.Equal(oidTCGATTPMVersion):
						version = truncateEndorsementInfo(atvVal)
					}
				}
			}
		}
	}

	return manufacturerID, model, version
}

func parseTCGVendorID(arg string) uint32 {
	ret, err := strconv.ParseUint(strings.TrimPrefix(arg, "id:"), 16, 32)
	if err != nil {
		return 0
	}

	return uint32(ret)
}

func truncateEndorsementInfo(arg string) string {
	if len(arg) <= maxEndorsementInfoLen {
		return arg
	}

	return arg[:maxEndorsementInfoLen]
}
