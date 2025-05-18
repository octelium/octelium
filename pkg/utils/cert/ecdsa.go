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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

type ECDSAKey struct {
	PrivateKey *ecdsa.PrivateKey
}

func NewECDSAFromKey(key *ecdsa.PrivateKey) *ECDSAKey {
	return &ECDSAKey{
		PrivateKey: key,
	}
}

func GenerateECDSA() (*ECDSAKey, error) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDSAKey{
		PrivateKey: privateKey,
	}, nil
}

func LoadECDSA(privatePEM []byte) (*ECDSAKey, error) {
	privateKey, err := ParseECPrivateKeyFromPEM(privatePEM)
	if err != nil {
		return nil, err
	}
	return &ECDSAKey{
		PrivateKey: privateKey,
	}, nil
}

func (c *ECDSAKey) GetPrivateKeyPEM() (string, error) {

	b, err := x509.MarshalECPrivateKey(c.PrivateKey)
	if err != nil {
		return "", err
	}

	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})

	return out.String(), nil
}

func (c *ECDSAKey) GetPublicKeyPEM() (string, error) {

	b, err := x509.MarshalPKIXPublicKey(&c.PrivateKey.PublicKey)
	if err != nil {
		return "", err
	}

	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "EC PUBLIC KEY", Bytes: b})

	return out.String(), nil
}

func ParseECPublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, error) {
	var err error

	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.Errorf("Could not decode PEM")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *ecdsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
		return nil, errors.Errorf("Not a public ECDSA key")
	}

	return pkey, nil
}

func ParseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
	var err error

	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.Errorf("Could not decode PEM")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
		return nil, err
	}

	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, errors.Errorf("Not a private ECDSA key")
	}

	return pkey, nil
}
