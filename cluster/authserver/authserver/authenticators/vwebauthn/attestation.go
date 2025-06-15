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

package vwebauthn

import (
	"context"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func (c *WebAuthNFactor) verifyAttestation(ctx context.Context, r *protocol.ParsedCredentialCreationData, cred *webauthn.Credential) error {

	/*
		if c.mds == nil {
			return nil
		}


			aaguid, err := uuid.FromBytes(r.Response.AttestationObject.AuthData.AttData.AAGUID)
			if err != nil {
				return err
			}

			aaguidStr := aaguid.String()

			if len(profile.Spec.Authenticator.Webauthn.AllowedAAGUIDs) > 0 {
				if !slices.Contains(profile.Spec.Authenticator.Webauthn.AllowedAAGUIDs, aaguidStr) {
					return errors.Errorf("AAGUID is not allowed")
				}
			}

			if len(profile.Spec.Authenticator.Webauthn.DisallowedAAGUIDs) > 0 {
				if slices.Contains(profile.Spec.Authenticator.Webauthn.DisallowedAAGUIDs, aaguidStr) {
					return errors.Errorf("AAGUID is not allowed")
				}
			}

			switch r.Response.AttestationObject.Format {
			case "none":
				return errors.Errorf("None attestation format")
			case "tpm", "apple", "packed", "android-key", "android-safetynet", "fido-u2f":
			default:
				return errors.Errorf("Unknown attestation format: %s", r.Response.AttestationObject.Format)
			}

			if err := cred.Verify(c.mds); err != nil {
				return err
			}

			entry, err := c.mds.GetEntry(ctx, aaguid)
			if err != nil {
				return err
			}
			if entry == nil {
				return errors.Errorf("MDS Entry not found")
			}

			if !slices.ContainsFunc(entry.MetadataStatement.AuthenticatorGetInfo.Versions, func(arg string) bool {
				return strings.HasPrefix(strings.ToLower(arg), "fido_2")
			}) {
				return errors.Errorf("Not FIDO2")
			}

			if !slices.ContainsFunc(entry.MetadataStatement.KeyProtection, func(arg string) bool {
				switch strings.ToLower(arg) {
				case "hardware", "secure_element":
					return true
				default:
					return false
				}
			}) {
				return errors.Errorf("Not FIDO2")
			}

			if strings.ToLower(entry.MetadataStatement.ProtocolFamily) != "fido2" {
				return errors.Errorf("Not FIDO2")
			}

			if !slices.ContainsFunc(entry.StatusReports, func(arg metadata.StatusReport) bool {
				switch arg.Status {
				case metadata.FidoCertified,
					metadata.FidoCertifiedL1, metadata.FidoCertifiedL1plus,
					metadata.FidoCertifiedL2, metadata.FidoCertifiedL2plus,
					metadata.FidoCertifiedL3, metadata.FidoCertifiedL3plus:
					return true
				default:
					return false
				}
			}) {
				return errors.Errorf("Not FIDO certified")
			}
	*/

	/*
		switch c.factor.Spec.GetWebauthn().AuthenticatorType {
		case identityv1.AuthenticationProfile_Spec_Webauthn_PLATFORM:
			switch r.Response.AttestationObject.Format {
			case "tpm", "apple", "packed", "android-key", "android-safetynet":
			default:
				return errors.Errorf("Invalid attestation format for platform: %s", r.Response.AttestationObject.Format)
			}
		case identityv1.AuthenticationProfile_Spec_Webauthn_ROAMING:
			switch r.Response.AttestationObject.Format {
			case "packed", "fido-u2f":
			default:
				return errors.Errorf("Invalid attestation format roaming: %s", r.Response.AttestationObject.Format)
			}
		}
	*/

	/*
		if err := c.verifyAttestationPolicies(r, c.factor); err != nil {
			return errors.Errorf("Could not get the aik cert: %+v", err)
		}
	*/

	return nil
}

/*
func isResponsePlatform(r *protocol.ParsedCredentialCreationData) bool {
	switch r.Response.AttestationObject.Format {
	case "tpm", "apple", "android-key", "android-safetynet":
		return true
	default:
		return false
	}
}

func (c *WebAuthNFactor) verifyAttestationPolicies(r *protocol.ParsedCredentialCreationData,
	factor *identityv1.AuthenticationProfile) error {

	spec := factor.Spec.GetWebauthn()
	if spec == nil ||
		(len(spec.AllowedAttestationCAs) == 0 &&
			len(spec.DeniedAttestationCAs) == 0) {
		zap.S().Debugf("No attestation certs. Nothing to be done...")
		return nil
	}

	chain, err := c.getCertificateChain(r)
	if err != nil {
		return err
	}

	return c.doVerifyAttestation(chain, factor)
}

func (c *WebAuthNFactor) doVerifyAttestation(chain []*x509.Certificate,
	factor *identityv1.AuthenticationProfile) error {

	if len(chain) < 1 {
		return errors.Errorf("Empty chain")
	}

	aikCert := chain[0]

	var intermediatePool *x509.CertPool

	if len(chain) > 1 {
		intermediatePool = x509.NewCertPool()
		for _, crt := range chain[1:] {
			intermediatePool.AddCert(crt)
		}
	}

	spec := factor.Spec.GetWebauthn()

	if len(spec.AllowedAttestationCAs) > 0 {
		pool := x509.NewCertPool()
		for _, capPEM := range spec.AllowedAttestationCAs {

			caCert, err := utils_cert.ParseX509LeafCertificateChainPEM([]byte(capPEM))
			if err != nil {
				return errors.Errorf("Could not parse PEM cert: %+v", err)
			}
			pool.AddCert(caCert)
		}

		if _, err := aikCert.Verify(x509.VerifyOptions{
			Roots:         pool,
			Intermediates: intermediatePool,
		}); err != nil {
			return errors.Errorf("aikCert not issued by any allowed attestation Certificate")
		}
	}

	if len(spec.DeniedAttestationCAs) > 0 {
		pool := x509.NewCertPool()
		for _, capPEM := range spec.DeniedAttestationCAs {

			caCert, err := utils_cert.ParseX509LeafCertificateChainPEM([]byte(capPEM))
			if err != nil {
				return errors.Errorf("Could not parse PEM cert: %+v", err)
			}
			pool.AddCert(caCert)
		}

		if _, err := aikCert.Verify(x509.VerifyOptions{
			Roots:         pool,
			Intermediates: intermediatePool,
		}); err == nil {
			return errors.Errorf("aikCert was issued by one of the denied attestation Certificate")
		}
	}

	zap.L().Debug("Attestation verification for the aik cert passed successfully")

	return nil
}

func (c *WebAuthNFactor) getCertificateChain(r *protocol.ParsedCredentialCreationData) ([]*x509.Certificate, error) {

	if r.Response.AttestationObject.Format == "none" {
		return nil, errors.Errorf("None format")
	}

	if r.Response.AttestationObject.Format == "android-safetynet" {

		responseT, present := r.Response.AttestationObject.AttStatement["response"].([]byte)
		if !present {
			return nil, errors.Errorf("Could not find response field")
		}

		jwtTkn, err := jwt.Parse(string(responseT), func(token *jwt.Token) (any, error) {
			chain := token.Header["x5c"].([]any)
			o := make([]byte, base64.StdEncoding.DecodedLen(len(chain[0].(string))))
			n, err := base64.StdEncoding.Decode(o, []byte(chain[0].(string)))
			if err != nil {
				return nil, err
			}
			cert, err := x509.ParseCertificate(o[:n])
			return cert.PublicKey, err
		})
		if err != nil {
			return nil, err
		}

		chainIface, exists := jwtTkn.Header["x5c"]
		if !exists {
			return nil, errors.Errorf("could not find x5c field in the response jwt")
		}

		chain, ok := chainIface.([]any)
		if !ok {
			return nil, errors.Errorf("Could not get x5c")
		}

		var ret []*x509.Certificate
		for _, crtBytes := range chain {
			o := make([]byte, base64.StdEncoding.DecodedLen(len(crtBytes.(string))))
			n, err := base64.StdEncoding.Decode(o, []byte(crtBytes.(string)))
			if err != nil {
				return nil, err
			}

			crt, err := x509.ParseCertificate(o[:n])
			if err != nil {
				return nil, err
			}

			ret = append(ret, crt)
		}

		return ret, nil
	}

	zap.S().Debugf("AttStatement statement: %+v", r.Response.AttestationObject.AttStatement)

	x5c, ok := r.Response.AttestationObject.AttStatement["x5c"]
	if !ok {
		return nil, errors.Errorf("No x5c field in the attestation statement")
	}
	x5cArray, ok := x5c.([]any)
	if !ok {
		return nil, errors.Errorf("No x5c array")
	}
	if len(x5cArray) < 1 {
		return nil, errors.Errorf("Empty x5 array")
	}
	var ret []*x509.Certificate
	for _, crtBytes := range x5cArray {
		cert, ok := crtBytes.([]byte)
		if !ok {
			return nil, errors.Errorf("Could not parse x5c bytes")
		}
		var err error
		crt, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, errors.Errorf("Could not parse cert DER bytes")
		}
		ret = append(ret, crt)
	}

	return ret, nil
}
*/
