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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

type Cert struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
}

func EncodePEMCertificate(out io.Writer, c *x509.Certificate) error {
	return pem.Encode(out, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	})
}

func GetCertificatePEM(c *x509.Certificate) ([]byte, error) {
	caPEM := new(bytes.Buffer)
	err := EncodePEMCertificate(caPEM, c)
	if err != nil {
		return nil, err
	}

	return caPEM.Bytes(), nil
}

func GetCertificatePEMStr(c *x509.Certificate) (string, error) {
	ret, err := GetCertificatePEM(c)
	if err != nil {
		return "", err
	}
	return string(ret), nil
}

func GetPrivateKeyPEM(key crypto.Signer) ([]byte, error) {

	if k, ok := key.(*ecdsa.PrivateKey); ok {
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}

		out := &bytes.Buffer{}
		if err := pem.Encode(out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
			return nil, err
		}

		return out.Bytes(), nil
	} else if k, ok := key.(*rsa.PrivateKey); ok {
		b := x509.MarshalPKCS1PrivateKey(k)

		out := &bytes.Buffer{}
		if err := pem.Encode(out, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}); err != nil {
			return nil, err
		}

		return out.Bytes(), nil
	} else if k, ok := key.(ed25519.PrivateKey); ok {
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}

		out := &bytes.Buffer{}
		if err := pem.Encode(out, &pem.Block{Type: "PRIVATE KEY", Bytes: b}); err != nil {
			return nil, err
		}

		return out.Bytes(), nil
	} else {
		return nil, errors.Errorf("Invalid private key type")
	}
}

func GetPrivateKeyPEMStr(key crypto.Signer) (string, error) {
	ret, err := GetPrivateKeyPEM(key)
	if err != nil {
		return "", err
	}

	return string(ret), nil
}

func (c *Cert) GetCertPEM() (string, error) {
	return GetCertificatePEMStr(c.Certificate)
}

func (c *Cert) MustGetCertPEM() []byte {
	ret, err := c.GetCertPEM()
	if err != nil {
		return nil
	}
	return []byte(ret)
}

func (c *Cert) GetPrivateKeyPEM() (string, error) {

	return GetPrivateKeyPEMStr(c.PrivateKey)
}

func (c *Cert) MustGetPrivateKeyPEM() []byte {
	ret, err := c.GetPrivateKeyPEM()
	if err != nil {
		panic(err)
	}
	return []byte(ret)
}

func GenerateSerialNumber() (*big.Int, error) {
	serialNumLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialNumLimit)
	if err != nil {
		return nil, err
	}
	return serialNum, nil
}

func GenerateCARoot() (*Cert, error) {
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	now := time.Now()

	caCert := &x509.Certificate{

		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName: "Octelium Root CA",
		},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour * 24 * 3650 * 2),
		KeyUsage:  x509.KeyUsageCertSign,

		IsCA: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		return nil, err
	}
	caCert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	ret := &Cert{
		Certificate: caCert,
		PrivateKey:  certPrivKey,
	}

	pem, err := ret.GetCertPEM()
	if err != nil {
		return nil, err
	}
	crt, err := ParseX509LeafCertificateChainPEM([]byte(pem))
	if err != nil {
		return nil, err
	}

	ret.Certificate = crt

	return ret, nil
}

func GenerateCARootFromCert(caCert *x509.Certificate) (*Cert, error) {
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	now := time.Now()

	caCert.SerialNumber = serialNumber
	caCert.BasicConstraintsValid = true
	caCert.IsCA = true

	if caCert.KeyUsage == 0 {
		caCert.KeyUsage = x509.KeyUsageCertSign
	}

	if caCert.NotBefore.IsZero() {
		caCert.NotBefore = now
	}

	if caCert.NotAfter.IsZero() {
		caCert.NotAfter = now.Add(time.Hour * 24 * 365 * 8)
	}
	if caCert.Subject.CommonName == "" {
		caCert.Subject.CommonName = "Octelium Root CA"
	}

	der, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		return nil, err
	}
	caCert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	ret := &Cert{
		Certificate: caCert,
		PrivateKey:  certPrivKey,
	}

	pem, err := ret.GetCertPEM()
	if err != nil {
		return nil, err
	}
	crt, err := ParseX509LeafCertificateChainPEM([]byte(pem))
	if err != nil {
		return nil, err
	}

	ret.Certificate = crt

	return ret, nil
}

func GenerateCertificate(template *x509.Certificate, parent *x509.Certificate, caPrivateKey any, isRSA bool) (*Cert, error) {

	ret := &Cert{
		Certificate: template,
	}

	if isRSA {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		ret.PrivateKey = priv

		certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &priv.PublicKey, caPrivateKey)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		ret.Certificate = cert
	} else {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		ret.PrivateKey = priv

		certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &priv.PublicKey, caPrivateKey)
		if err != nil {
			return nil, err
		}

		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		ret.Certificate = cert
	}

	return ret, nil

}

func GenerateCertificateTmp(commonName string, parent *Cert, isRSA bool) (*Cert, error) {
	now := time.Now()

	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	temp := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour * 24 * 3650 * 2),
		KeyUsage:  x509.KeyUsageCertSign,
	}

	return GenerateCertificate(temp, parent.Certificate, parent.PrivateKey, isRSA)
}

func GenerateIntermediateCATmp(commonName string, parent *Cert) (*Cert, error) {
	now := time.Now()

	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	temp := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour * 24 * 3650 * 2),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	return GenerateCertificate(temp, parent.Certificate, parent.PrivateKey, false)
}

func ParsePrivateKeyPEM(keyBytes []byte) (crypto.Signer, error) {

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.Errorf("error decoding private key PEM block")
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, err
		}
		return signer, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		err = key.Validate()
		if err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, errors.Errorf("unknown private key type: %s", block.Type)
	}
}

func ParseX509CertificateChainPEM(certBytes []byte) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	var block *pem.Block

	for {
		block, certBytes = pem.Decode(certBytes)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.Errorf("error decoding certificate PEM block")
	}

	return certs, nil
}

func ParseX509LeafCertificateChainPEM(certBytes []byte) (*x509.Certificate, error) {
	certs, err := ParseX509CertificateChainPEM(certBytes)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}

func ParseBase64PEMCertificate(base64PEM string) (*x509.Certificate, error) {

	pem, err := base64.StdEncoding.DecodeString(base64PEM)
	if err != nil {
		return nil, err
	}
	return ParseX509LeafCertificateChainPEM(pem)

}

func ParsePEMCertificate(pem string) (*x509.Certificate, error) {
	return ParseX509LeafCertificateChainPEM([]byte(pem))
}

func ParsePEMCertificates(lst []string) ([]*x509.Certificate, error) {
	var ret []*x509.Certificate
	for _, basePEM := range lst {
		crt, err := ParsePEMCertificate(basePEM)
		if err != nil {
			return nil, err
		}
		ret = append(ret, crt)
	}

	return ret, nil
}

func ParseBase64PEMCertificates(lst []string) ([]*x509.Certificate, error) {
	var ret []*x509.Certificate
	for _, basePEM := range lst {
		crt, err := ParseBase64PEMCertificate(basePEM)
		if err != nil {
			return nil, err
		}
		ret = append(ret, crt)
	}

	return ret, nil
}

func GenerateSelfSignedCert(commonName string, sans []string, duration time.Duration) (*Cert, error) {

	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	now := time.Now()

	caCert := &x509.Certificate{
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: sans,

		NotBefore:   now,
		NotAfter:    now.Add(duration),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		return nil, err
	}

	caCert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	ret := &Cert{
		Certificate: caCert,
		PrivateKey:  certPrivKey,
	}

	pem, err := ret.GetCertPEM()
	if err != nil {
		return nil, err
	}
	crt, err := ParseX509LeafCertificateChainPEM([]byte(pem))
	if err != nil {
		return nil, err
	}

	ret.Certificate = crt

	return ret, nil
}
