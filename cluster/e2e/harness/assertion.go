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

package harness

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/octelium/octelium/pkg/utils/utilrand"
)

type AssertionIssuer struct {
	Key    *rsa.PrivateKey
	KeyID  string
	Issuer string
	JWKS   string
}

func NewAssertionIssuer(t *testing.T, issuer string) *AssertionIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Could not generate an RSA key for the assertion issuer: %+v", err)
	}

	keyID := utilrand.GetRandomStringCanonical(8)

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       key.Public(),
				KeyID:     keyID,
				Algorithm: string(jose.RS256),
				Use:       "sig",
			},
		},
	}

	b, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("Could not serialise the JWKS: %+v", err)
	}

	return &AssertionIssuer{
		Key:    key,
		KeyID:  keyID,
		Issuer: issuer,
		JWKS:   string(b),
	}
}

type AssertionClaims struct {
	Subject  string
	Audience string
	Issuer   string
	Expiry   time.Duration
}

func (a *AssertionIssuer) Token(t *testing.T, c AssertionClaims) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: a.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", a.KeyID))
	if err != nil {
		t.Fatalf("Could not build a JWT signer: %+v", err)
	}

	issuer := c.Issuer
	if issuer == "" {
		issuer = a.Issuer
	}

	expiry := c.Expiry
	if expiry == 0 {
		expiry = 5 * time.Minute
	}

	now := time.Now()

	claims := jwt.Claims{
		Subject:  c.Subject,
		Issuer:   issuer,
		Audience: jwt.Audience{c.Audience},
		Expiry:   jwt.NewNumericDate(now.Add(expiry)),
		IssuedAt: jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(func() time.Time {
			if expiry < 0 {
				return now.Add(expiry).Add(-time.Minute)
			}
			return now
		}()),
		ID: utilrand.GetRandomStringCanonical(12),
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Could not sign the assertion: %+v", err)
	}

	return raw
}
