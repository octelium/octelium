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

package authserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/stretchr/testify/assert"
)

type tstAttestationCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTstAttestationCA(t *testing.T) *tstAttestationCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Attestation Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	assert.Nil(t, err)

	cert, err := x509.ParseCertificate(der)
	assert.Nil(t, err)

	return &tstAttestationCA{
		key:  key,
		cert: cert,
	}
}

func (c *tstAttestationCA) newLeaf(t *testing.T, aaguid uuid.UUID) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	aaguidExt, err := asn1.Marshal(aaguid[:])
	assert.Nil(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Octelium Test"},
			OrganizationalUnit: []string{"Authenticator Attestation"},
			CommonName:         "Test Attestation",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4},
				Value: aaguidExt,
			},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	assert.Nil(t, err)

	return key, der
}

type tstAttestationObject struct {
	Format    string         `json:"fmt"`
	Statement map[string]any `json:"attStmt"`
	AuthData  []byte         `json:"authData"`
}

func tstRewriteAttestation(t *testing.T, resp string, attachment string,
	fn func(obj *tstAttestationObject, clientDataJSON []byte)) string {
	t.Helper()

	body := map[string]any{}
	assert.Nil(t, json.Unmarshal([]byte(resp), &body))

	response := body["response"].(map[string]any)

	objBytes, err := base64.RawURLEncoding.DecodeString(response["attestationObject"].(string))
	assert.Nil(t, err)

	clientDataJSON, err := base64.RawURLEncoding.DecodeString(response["clientDataJSON"].(string))
	assert.Nil(t, err)

	obj := &tstAttestationObject{}
	assert.Nil(t, webauthncbor.Unmarshal(objBytes, obj))

	if fn != nil {
		fn(obj, clientDataJSON)
	}

	objBytes, err = webauthncbor.Marshal(obj)
	assert.Nil(t, err)

	response["attestationObject"] = base64.RawURLEncoding.EncodeToString(objBytes)

	if attachment != "" {
		body["authenticatorAttachment"] = attachment
	}

	ret, err := json.Marshal(body)
	assert.Nil(t, err)

	return string(ret)
}

func tstChainAttestation(t *testing.T, ca *tstAttestationCA,
	aaguid uuid.UUID) func(*tstAttestationObject, []byte) {
	t.Helper()

	return func(obj *tstAttestationObject, clientDataJSON []byte) {
		key, der := ca.newLeaf(t, aaguid)

		clientDataHash := sha256.Sum256(clientDataJSON)
		digest := sha256.Sum256(slices.Concat(obj.AuthData, clientDataHash[:]))

		sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		assert.Nil(t, err)

		obj.Format = "packed"
		obj.Statement = map[string]any{
			"alg": int64(-7),
			"sig": sig,
			"x5c": []any{der},
		}
	}
}

func tstNoneAttestation(obj *tstAttestationObject, _ []byte) {
	obj.Format = "none"
	obj.Statement = map[string]any{}
}

func newTstMDS(t *testing.T, entries ...*metadata.Entry) metadata.Provider {
	t.Helper()

	mds := make(map[uuid.UUID]*metadata.Entry, len(entries))
	for _, entry := range entries {
		mds[entry.AaGUID] = entry
	}

	ret, err := memory.New(
		memory.WithMetadata(mds),
		memory.WithValidateEntry(true),
		memory.WithValidateEntryPermitZeroAAGUID(false),
		memory.WithValidateTrustAnchor(true),
		memory.WithValidateStatus(true),
	)
	assert.Nil(t, err)

	return ret
}

func TestFIDOAttestationTrust(t *testing.T) {

	srv, tst, adminSrv := newWebAuthnTestEnv(t)

	ca := newTstAttestationCA(t)
	otherCA := newTstAttestationCA(t)

	newEntry := func(aaguid uuid.UUID, keyProtection, hints []string) *metadata.Entry {
		return &metadata.Entry{
			AaGUID: aaguid,
			MetadataStatement: metadata.Statement{
				Description: "Test Authenticator",
				AttestationTypes: metadata.AuthenticatorAttestationTypes{
					metadata.BasicFull,
					metadata.BasicSurrogate,
				},
				KeyProtection:               keyProtection,
				AttachmentHint:              hints,
				AttestationRootCertificates: []*x509.Certificate{ca.cert},
			},
		}
	}

	register := func(t *testing.T, aaguid uuid.UUID, opts virtualwebauthn.AuthenticatorOptions,
		attachment string, fn func(*tstAttestationObject, []byte)) (*corev1.Authenticator, error) {
		t.Helper()

		usrT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err, "%+v", err)

		authn := createFIDOAuthenticator(t, srv, usrT)

		d := newVirtualFIDO(srv.domain, usrT.Usr, opts)
		d.auth.Aaguid = aaguid

		req, err := beginFIDORegistration(t, srv, usrT, authn)
		assert.Nil(t, err, "%+v", err)

		if err := finishFIDORegistration(t, srv, usrT, authn,
			tstRewriteAttestation(t, d.attestation(t, req), attachment, fn)); err != nil {
			return nil, err
		}

		return srv.mustGetAuthenticator(t, authn), nil
	}

	hardware := []string{"hardware", "tee"}
	software := []string{"software"}
	internal := []string{"internal"}
	external := []string{"external", "wired"}

	platformID := uuid.New()
	roamingID := uuid.New()
	hybridID := uuid.New()
	softwareID := uuid.New()
	unhintedID := uuid.New()

	srv.mdsProvider = newTstMDS(t,
		newEntry(platformID, hardware, internal),
		newEntry(roamingID, hardware, external),
		newEntry(hybridID, hardware, []string{"internal", "wireless"}),
		newEntry(softwareID, software, internal),
		newEntry(unhintedID, hardware, nil),
	)

	t.Run("ChainPlatform", func(t *testing.T) {
		authn, err := register(t, platformID, virtualwebauthn.AuthenticatorOptions{},
			"cross-platform", tstChainAttestation(t, ca, platformID))
		assert.Nil(t, err, "%+v", err)

		fido := authn.Status.GetInfo().GetFido()
		assert.True(t, fido.IsAttestationVerified)
		assert.True(t, fido.IsHardware)
		assert.False(t, fido.IsSoftware)
		assert.Equal(t, corev1.Authenticator_Status_Info_FIDO_PLATFORM, fido.Type,
			"the metadata must override the type reported by the client")
		assert.Equal(t, "Test Authenticator", authn.Status.Description)
	})

	t.Run("ChainRoamingClaimingPlatform", func(t *testing.T) {
		authn, err := register(t, roamingID, virtualwebauthn.AuthenticatorOptions{},
			"platform", tstChainAttestation(t, ca, roamingID))
		assert.Nil(t, err, "%+v", err)

		fido := authn.Status.GetInfo().GetFido()
		assert.True(t, fido.IsAttestationVerified)
		assert.True(t, fido.IsHardware)
		assert.Equal(t, corev1.Authenticator_Status_Info_FIDO_ROAMING, fido.Type,
			"a roaming key must not become PLATFORM by claiming it")
	})

	t.Run("ChainAmbiguousAttachment", func(t *testing.T) {
		for _, aaguid := range []uuid.UUID{hybridID, unhintedID} {
			authn, err := register(t, aaguid, virtualwebauthn.AuthenticatorOptions{},
				"platform", tstChainAttestation(t, ca, aaguid))
			assert.Nil(t, err, "%+v", err)

			fido := authn.Status.GetInfo().GetFido()
			assert.True(t, fido.IsAttestationVerified)
			assert.Equal(t, corev1.Authenticator_Status_Info_FIDO_TYPE_UNKNOWN, fido.Type)
		}
	})

	t.Run("ChainSoftware", func(t *testing.T) {
		authn, err := register(t, softwareID, virtualwebauthn.AuthenticatorOptions{},
			"platform", tstChainAttestation(t, ca, softwareID))
		assert.Nil(t, err, "%+v", err)

		fido := authn.Status.GetInfo().GetFido()
		assert.True(t, fido.IsAttestationVerified)
		assert.True(t, fido.IsSoftware)
		assert.False(t, fido.IsHardware)
	})

	t.Run("SelfAttestation", func(t *testing.T) {
		authn, err := register(t, platformID, virtualwebauthn.AuthenticatorOptions{},
			"platform", nil)
		assert.Nil(t, err, "%+v", err)

		fido := authn.Status.GetInfo().GetFido()
		assert.False(t, fido.IsAttestationVerified,
			"a self-signed statement says nothing about the Authenticator's model")
		assert.False(t, fido.IsHardware)
		assert.Equal(t, corev1.Authenticator_Status_Info_FIDO_PLATFORM, fido.Type)
	})

	t.Run("NoneClaimingHardware", func(t *testing.T) {
		authn, err := register(t, platformID, virtualwebauthn.AuthenticatorOptions{},
			"platform", tstNoneAttestation)
		assert.Nil(t, err, "%+v", err)

		fido := authn.Status.GetInfo().GetFido()
		assert.False(t, fido.IsAttestationVerified)
		assert.False(t, fido.IsHardware, "an unattested AAGUID is only a claim")
		assert.Equal(t, "Test Authenticator", authn.Status.Description)
	})

	t.Run("NoneClaimingSoftware", func(t *testing.T) {
		authn, err := register(t, softwareID, virtualwebauthn.AuthenticatorOptions{},
			"", tstNoneAttestation)
		assert.Nil(t, err, "%+v", err)

		fido := authn.Status.GetInfo().GetFido()
		assert.False(t, fido.IsAttestationVerified)
		assert.True(t, fido.IsSoftware)
		assert.False(t, fido.IsHardware)
	})

	t.Run("UntrustedChain", func(t *testing.T) {
		_, err := register(t, platformID, virtualwebauthn.AuthenticatorOptions{},
			"platform", tstChainAttestation(t, otherCA, platformID))
		assert.NotNil(t, err)
	})

	t.Run("ChainClaimingAnotherAAGUID", func(t *testing.T) {
		_, err := register(t, platformID, virtualwebauthn.AuthenticatorOptions{},
			"platform", tstChainAttestation(t, ca, roamingID))
		assert.NotNil(t, err)
	})

	t.Run("NoMDS", func(t *testing.T) {
		mds := srv.mdsProvider
		srv.mdsProvider = nil
		t.Cleanup(func() {
			srv.mdsProvider = mds
		})

		authn, err := register(t, platformID, virtualwebauthn.AuthenticatorOptions{},
			"platform", tstChainAttestation(t, otherCA, platformID))
		assert.Nil(t, err, "%+v", err)

		fido := authn.Status.GetInfo().GetFido()
		assert.False(t, fido.IsAttestationVerified)
		assert.False(t, fido.IsHardware)
		assert.Equal(t, corev1.Authenticator_Status_Info_FIDO_PLATFORM, fido.Type)
	})
}

func TestFIDONotDeviceBound(t *testing.T) {

	ctx := context.Background()

	srv, tst, adminSrv := newWebAuthnTestEnv(t)

	ca := newTstAttestationCA(t)
	aaguid := uuid.New()

	srv.mdsProvider = newTstMDS(t, &metadata.Entry{
		AaGUID: aaguid,
		MetadataStatement: metadata.Statement{
			AttestationTypes:            metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
			KeyProtection:               []string{"hardware", "tee"},
			AttachmentHint:              []string{"internal"},
			AttestationRootCertificates: []*x509.Certificate{ca.cert},
		},
	})

	usrT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, usrT.Session.Status.DeviceRef)

	deviceRef := usrT.Session.Status.DeviceRef

	authn := createFIDOAuthenticator(t, srv, usrT)

	d := newVirtualFIDO(srv.domain, usrT.Usr, virtualwebauthn.AuthenticatorOptions{})
	d.auth.Aaguid = aaguid

	req, err := beginFIDORegistration(t, srv, usrT, authn)
	assert.Nil(t, err, "%+v", err)

	assert.Nil(t, finishFIDORegistration(t, srv, usrT, authn,
		tstRewriteAttestation(t, d.attestation(t, req), "platform", tstChainAttestation(t, ca, aaguid))))

	authn = srv.mustGetAuthenticator(t, authn)

	fido := authn.Status.GetInfo().GetFido()
	assert.True(t, fido.IsAttestationVerified)
	assert.True(t, fido.IsHardware)
	assert.Equal(t, corev1.Authenticator_Status_Info_FIDO_PLATFORM, fido.Type)
	assert.False(t, fido.BackupEligible)
	assert.Nil(t, authn.Status.DeviceRef,
		"the attestation proves the hardware and says nothing about which Device it is")

	authn.Status.DeviceRef = deviceRef
	authn, err = srv.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
	assert.Nil(t, err, "%+v", err)

	usrT.Session.Status.DeviceRef = nil
	usrT.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
	assert.Nil(t, err, "%+v", err)

	_, err = authenticateFIDO(t, srv, usrT, authn, d)
	assert.Nil(t, err, "%+v", err)

	sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
		Uid: usrT.Session.Metadata.Uid,
	})
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, sess.Status.DeviceRef, "a legacy DeviceRef must not reach a browser Session")
	assert.Equal(t, deviceRef.Uid, srv.mustGetAuthenticator(t, authn).Status.DeviceRef.GetUid())
}
