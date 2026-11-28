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

package jwkctl

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/jwkctl/jwkutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protowire"
)

func newCacheTestSigner(t testing.TB, kind string) crypto.Signer {
	if kind == KindECDSAP256 {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		assert.Nil(t, err)
		return priv
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)
	return priv
}

func newCacheTestSecret(t testing.TB, uid string, signer crypto.Signer, createdAt time.Time) *corev1.Secret {
	keyPEM, err := utils_cert.GetPrivateKeyPEM(signer)
	assert.Nil(t, err)
	return &corev1.Secret{
		Metadata: &metav1.Metadata{
			Uid:          uid,
			CreatedAt:    pbutils.Timestamp(createdAt),
			SystemLabels: map[string]string{"octelium-root-secret": "true"},
		},
		Data: &corev1.Secret_Data{Type: &corev1.Secret_Data_ValueBytes{ValueBytes: keyPEM}},
	}
}

func newCacheTestController(t testing.TB, kind string) (*Controller, *corev1.Secret) {
	c := &Controller{
		opts:             &Opts{},
		accessTokenCache: newAccessTokenCache(accessTokenCacheMaxEntries),
		ctl:              &ctl{keyMap: make(map[string]*jwtKey)},
	}
	secret := newCacheTestSecret(t, vutils.UUIDv4(), newCacheTestSigner(t, kind), time.Now())
	assert.Nil(t, c.ctl.setKey(secret))
	return c, secret
}

func newCacheTestToken(t testing.TB, c *Controller, sess *corev1.Session) string {
	tknStr, err := c.CreateAccessToken(sess)
	assert.Nil(t, err)
	return tknStr
}

func signCacheTestToken(t testing.TB, key *jwtKey, content *authv1.TokenT0_Content) string {
	contentBytes, err := pbutils.Marshal(content)
	assert.Nil(t, err)
	var signature []byte
	switch key.kind {
	case KindEd25519:
		signature = ed25519.Sign(key.key.(ed25519.PrivateKey), contentBytes)
	default:
		signature, err = signECDSAP256(key.key.(*ecdsa.PrivateKey), contentBytes)
		assert.Nil(t, err)
	}
	tknBytes, err := pbutils.Marshal(&authv1.TokenT0{Content: content, Signature: signature})
	assert.Nil(t, err)
	return base64.RawURLEncoding.EncodeToString(append([]byte{0x1}, tknBytes...))
}

func assertSameAccessTokenVerification(t *testing.T, c *Controller, tknStr string) *AccessTokenClaims {
	t.Helper()
	want, wantErr := c.verifyToken(tknStr, authv1.TokenT0_Content_ACCESS_TOKEN)
	claims, err := c.VerifyAccessToken(tknStr)
	if wantErr != nil {
		assert.Nil(t, claims)
		if assert.NotNil(t, err) {
			assert.Equal(t, wantErr.Error(), err.Error())
		}
		return nil
	}

	assert.Nil(t, err)
	assert.Equal(t, &AccessTokenClaims{SessionUID: want.subject, TokenID: want.tokenID}, claims)
	return claims
}

func TestAccessTokenCache(t *testing.T) {
	now := time.Now()
	newEntry := func(ttl time.Duration) *accessTokenCacheEntry {
		return &accessTokenCacheEntry{
			claims:    AccessTokenClaims{SessionUID: vutils.UUIDv4(), TokenID: vutils.UUIDv4()},
			keyUID:    vutils.UUIDv4(),
			key:       &jwtKey{},
			expiresAt: now.Add(ttl),
			hasExpiry: true,
		}
	}

	t.Run("SetGetDelete", func(t *testing.T) {
		c := newAccessTokenCache(4)
		assert.Nil(t, c.get("token"))
		e1, e2 := newEntry(time.Hour), newEntry(time.Hour)
		c.set("token", e1, now)
		assert.Same(t, e1, c.get("token"))
		assert.Nil(t, c.get("toke"))
		assert.Nil(t, c.get("token2"))
		assert.Nil(t, c.get("TOKEN"))
		c.set("token", e2, now)
		assert.Same(t, e2, c.get("token"))
		assert.Equal(t, 1, c.len())
		c.delete("token", e1)
		assert.Same(t, e2, c.get("token"))
		c.delete("other", e2)
		assert.Equal(t, 1, c.len())
		c.delete("token", e2)
		assert.Nil(t, c.get("token"))
		assert.Equal(t, 0, c.len())
		c.delete("token", e2)
		assert.Equal(t, 0, c.len())
	})

	t.Run("KeyLength", func(t *testing.T) {
		c := newAccessTokenCache(4)
		for _, l := range []int{1, accessTokenCacheMaxKeyLength, accessTokenCacheMaxKeyLength + 1, 4096} {
			tknStr := strings.Repeat("a", l)
			e := newEntry(time.Hour)
			c.set(tknStr, e, now)
			if l > accessTokenCacheMaxKeyLength {
				assert.Nil(t, c.get(tknStr))
			} else {
				assert.Same(t, e, c.get(tknStr))
			}
		}
	})

	t.Run("Expiry", func(t *testing.T) {
		e := newEntry(0)
		assert.False(t, e.isExpired(now.Add(-time.Hour)))
		assert.False(t, e.isExpired(now.Add(-time.Nanosecond)))
		assert.False(t, e.isExpired(now))
		assert.True(t, e.isExpired(now.Add(time.Nanosecond)))
		assert.True(t, e.isExpired(now.Add(time.Hour)))
		e.hasExpiry = false
		assert.False(t, e.isExpired(now.Add(time.Nanosecond)))
		assert.False(t, e.isExpired(now.Add(100*365*24*time.Hour)))
		assert.False(t, (&accessTokenCacheEntry{}).isExpired(now))
	})

	t.Run("Capacity", func(t *testing.T) {
		c := newAccessTokenCache(4)
		entries := make(map[string]*accessTokenCacheEntry)
		for i := range 4 {
			tknStr := fmt.Sprintf("token-%d", i)
			entries[tknStr] = newEntry(time.Hour)
			c.set(tknStr, entries[tknStr], now)
		}
		assert.Equal(t, 4, c.len())
		for tknStr, e := range entries {
			c.set(tknStr, e, now)
		}
		assert.Equal(t, 4, c.len())
		for tknStr, e := range entries {
			assert.Same(t, e, c.get(tknStr))
		}

		c.set("token-4", newEntry(time.Hour), now)
		assert.Equal(t, 4, c.len())
		assert.NotNil(t, c.get("token-4"))
		remaining := 0
		for tknStr, e := range entries {
			if ret := c.get(tknStr); ret != nil {
				assert.Same(t, e, ret)
				remaining++
			}
		}
		assert.Equal(t, 3, remaining)

		for i := 5; i < 100; i++ {
			tknStr := fmt.Sprintf("token-%d", i)
			e := newEntry(time.Hour)
			c.set(tknStr, e, now)
			assert.Same(t, e, c.get(tknStr))
			assert.Equal(t, 4, c.len())
		}

		c = newAccessTokenCache(1)
		c.set("a", newEntry(time.Hour), now)
		c.set("b", newEntry(time.Hour), now)
		assert.Nil(t, c.get("a"))
		assert.NotNil(t, c.get("b"))
		assert.Equal(t, 1, c.len())
	})

	t.Run("EvictExpiredFirst", func(t *testing.T) {
		for range 100 {
			c := newAccessTokenCache(4)
			for i := range 4 {
				ttl := time.Hour
				if i == 2 {
					ttl = -time.Second
				}
				c.set(fmt.Sprintf("token-%d", i), newEntry(ttl), now)
			}
			c.set("token-4", newEntry(time.Hour), now)
			assert.Equal(t, 4, c.len())
			assert.Nil(t, c.get("token-2"))
			for _, tknStr := range []string{"token-0", "token-1", "token-3", "token-4"} {
				assert.NotNil(t, c.get(tknStr))
			}
		}

		for range 100 {
			c := newAccessTokenCache(2)
			c.set("a", newEntry(0), now)
			c.set("b", newEntry(-time.Nanosecond), now)
			c.set("c", newEntry(time.Hour), now)
			assert.NotNil(t, c.get("a"))
			assert.Nil(t, c.get("b"))
			assert.NotNil(t, c.get("c"))
		}

		for range 100 {
			c := newAccessTokenCache(2)
			e := newEntry(-time.Hour)
			e.hasExpiry = false
			c.set("a", e, now)
			c.set("b", newEntry(-time.Hour), now)
			c.set("c", newEntry(time.Hour), now)
			assert.NotNil(t, c.get("a"))
			assert.Nil(t, c.get("b"))
			assert.NotNil(t, c.get("c"))
		}
	})

	t.Run("EvictSampled", func(t *testing.T) {
		maxEntries := 4 * accessTokenCacheEvictSamples
		c := newAccessTokenCache(maxEntries)
		for i := range 1000 {
			tknStr := fmt.Sprintf("token-%d", i)
			e := newEntry(time.Hour)
			c.set(tknStr, e, now)
			assert.Same(t, e, c.get(tknStr))
			assert.Equal(t, min(i+1, maxEntries), c.len())
		}
	})

	t.Run("KeyCopy", func(t *testing.T) {
		c := newAccessTokenCache(4)
		hdr := "theme=dark; octelium_auth=" + strings.Repeat("t", 178) + "; " + strings.Repeat("x", 4096)
		start := strings.Index(hdr, "octelium_auth=") + len("octelium_auth=")
		tknStr := hdr[start : start+178]
		c.set(tknStr, newEntry(time.Hour), now)
		assert.NotNil(t, c.get(tknStr))
		hdrStart := uintptr(unsafe.Pointer(unsafe.StringData(hdr)))
		assert.Len(t, c.m, 1)
		for key := range c.m {
			assert.Equal(t, tknStr, key)
			keyStart := uintptr(unsafe.Pointer(unsafe.StringData(key)))
			assert.False(t, keyStart >= hdrStart && keyStart < hdrStart+uintptr(len(hdr)))
		}
	})
}

func TestVerifyAccessTokenCache(t *testing.T) {
	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		t.Run(kind, func(t *testing.T) {
			c, _ := newCacheTestController(t, kind)
			key, err := c.chooseJWK()
			assert.Nil(t, err)
			sess := newSession()
			tknStr := newCacheTestToken(t, c, sess)

			assert.Equal(t, 0, c.accessTokenCache.len())
			claims := assertSameAccessTokenVerification(t, c, tknStr)
			if !assert.NotNil(t, claims) {
				return
			}
			assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
			assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)
			assert.Equal(t, 1, c.accessTokenCache.len())

			e := c.accessTokenCache.get(tknStr)
			if !assert.NotNil(t, e) {
				return
			}
			tkn, err := c.parseToken(tknStr)
			assert.Nil(t, err)
			assert.Equal(t, *claims, e.claims)
			assert.Equal(t, key.uid, e.keyUID)
			assert.Same(t, key, e.key)
			assert.True(t, e.hasExpiry)
			assert.True(t, tkn.Content.ExpiresAt.AsTime().Equal(e.expiresAt))

			cached, ok := c.getCachedAccessToken(tknStr)
			assert.True(t, ok)
			assert.Same(t, e, cached)

			for range 4 {
				ret, err := c.VerifyAccessToken(tknStr)
				assert.Nil(t, err)
				assert.Equal(t, claims, ret)
				assert.NotSame(t, claims, ret)
				assert.NotSame(t, &e.claims, ret)
				ret.SessionUID, ret.TokenID = "", ""
				assert.Same(t, e, c.accessTokenCache.get(tknStr))
				assert.Equal(t, sess.Metadata.Uid, e.claims.SessionUID)
				assert.Equal(t, sess.Status.Authentication.TokenID, e.claims.TokenID)
			}
			assert.Equal(t, 1, c.accessTokenCache.len())

			fake := strings.Repeat("a", 178)
			fakeEntry := &accessTokenCacheEntry{
				claims: AccessTokenClaims{SessionUID: "session", TokenID: "token"},
				keyUID: key.uid,
				key:    key,
			}
			c.accessTokenCache.set(fake, fakeEntry, time.Now())
			ret, err := c.VerifyAccessToken(fake)
			assert.Nil(t, err)
			assert.Equal(t, &AccessTokenClaims{SessionUID: "session", TokenID: "token"}, ret)

			c.accessTokenCache.set(fake, &accessTokenCacheEntry{
				claims: fakeEntry.claims,
				keyUID: key.uid,
				key:    &jwtKey{kind: key.kind, key: key.key, publicKey: key.publicKey, createdAt: key.createdAt, uid: key.uid},
			}, time.Now())
			assertSameAccessTokenVerification(t, c, fake)
			assert.Nil(t, c.accessTokenCache.get(fake))

			c.accessTokenCache.set(fake, &accessTokenCacheEntry{
				claims:    fakeEntry.claims,
				keyUID:    key.uid,
				key:       key,
				expiresAt: time.Now().Add(-time.Second),
				hasExpiry: true,
			}, time.Now())
			assertSameAccessTokenVerification(t, c, fake)
			assert.Nil(t, c.accessTokenCache.get(fake))

			c.accessTokenCache.set(fake, &accessTokenCacheEntry{
				claims: fakeEntry.claims,
				keyUID: vutils.UUIDv4(),
				key:    key,
			}, time.Now())
			assertSameAccessTokenVerification(t, c, fake)
			assert.Nil(t, c.accessTokenCache.get(fake))
			assert.Equal(t, 1, c.accessTokenCache.len())

			refreshTkn, err := c.CreateRefreshToken(sess)
			assert.Nil(t, err)
			credTkn, err := c.CreateCredential(&corev1.Credential{
				Metadata: &metav1.Metadata{Uid: sess.Metadata.Uid},
				Spec:     &corev1.Credential_Spec{ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour))},
				Status:   &corev1.Credential_Status{TokenID: sess.Status.Authentication.TokenID},
			})
			assert.Nil(t, err)
			for _, other := range []string{refreshTkn, credTkn} {
				for range 2 {
					assert.Nil(t, assertSameAccessTokenVerification(t, c, other))
					assert.Nil(t, c.accessTokenCache.get(other))
				}
			}

			_, err = c.VerifyRefreshToken(tknStr)
			assert.NotNil(t, err)
			_, err = c.VerifyCredential(tknStr)
			assert.NotNil(t, err)
			refreshClaims, err := c.VerifyRefreshToken(refreshTkn)
			assert.Nil(t, err)
			assert.Equal(t, sess.Metadata.Uid, refreshClaims.SessionUID)
			credClaims, err := c.VerifyCredential(credTkn)
			assert.Nil(t, err)
			assert.Equal(t, sess.Metadata.Uid, credClaims.UID)
			assert.Equal(t, 1, c.accessTokenCache.len())
		})
	}
}

func TestVerifyAccessTokenCacheInvalidTokens(t *testing.T) {
	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		t.Run(kind, func(t *testing.T) {
			c, _ := newCacheTestController(t, kind)
			key, err := c.chooseJWK()
			assert.Nil(t, err)
			tknStr := newCacheTestToken(t, c, newSession())
			assert.NotNil(t, assertSameAccessTokenVerification(t, c, tknStr))

			data, err := base64.RawURLEncoding.DecodeString(tknStr)
			assert.Nil(t, err)
			var invalids []string
			for i := range data {
				for bit := range 8 {
					mutated := bytes.Clone(data)
					mutated[i] ^= 1 << bit
					invalids = append(invalids, base64.RawURLEncoding.EncodeToString(mutated))
				}
			}
			for i := range tknStr {
				invalids = append(invalids, tknStr[:i]+tknStr[i+1:], tknStr[:i]+"!"+tknStr[i+1:])
			}

			subject, err := c.uidToBytes(vutils.UUIDv4())
			assert.Nil(t, err)
			tokenID, err := c.uidToBytes(vutils.UUIDv4())
			assert.Nil(t, err)
			keyID, err := c.uidToBytes(key.uid)
			assert.Nil(t, err)
			for _, content := range []*authv1.TokenT0_Content{
				{Type: authv1.TokenT0_Content_TYPE_UNKNOWN, KeyID: keyID, Subject: subject, TokenID: tokenID},
				{Type: authv1.TokenT0_Content_REFRESH_TOKEN, KeyID: keyID, Subject: subject, TokenID: tokenID},
				{Type: authv1.TokenT0_Content_CREDENTIAL, KeyID: keyID, Subject: subject, TokenID: tokenID},
				{Type: authv1.TokenT0_Content_ACCESS_TOKEN, KeyID: keyID, Subject: subject, TokenID: tokenID,
					ExpiresAt: pbutils.Timestamp(time.Now().Add(-time.Second))},
				{Type: authv1.TokenT0_Content_ACCESS_TOKEN, KeyID: keyID, Subject: subject, TokenID: make([]byte, 16)},
				{Type: authv1.TokenT0_Content_ACCESS_TOKEN, KeyID: keyID, Subject: make([]byte, 16), TokenID: tokenID},
			} {
				invalids = append(invalids, signCacheTestToken(t, key, content))
			}

			invalids = append(invalids,
				"", " "+tknStr, tknStr+" ", tknStr+"\n", tknStr+"=", tknStr+"a", tknStr+tknStr,
				strings.ToUpper(tknStr), strings.ToLower(tknStr),
				strings.Repeat("a", 139), strings.Repeat("a", 140), strings.Repeat("a", 150),
				strings.Repeat("a", 220), strings.Repeat("a", 221), strings.Repeat("a", 300),
				strings.Repeat("a", 301), strings.Repeat("a", 4096), strings.Repeat("é", 100))

			for range 2 {
				for _, invalid := range invalids {
					if invalid == tknStr {
						continue
					}
					assert.Nil(t, assertSameAccessTokenVerification(t, c, invalid), invalid)
					assert.Nil(t, c.accessTokenCache.get(invalid))
				}
			}

			assert.Equal(t, 1, c.accessTokenCache.len())
			assert.NotNil(t, c.accessTokenCache.get(tknStr))
			assert.NotNil(t, assertSameAccessTokenVerification(t, c, tknStr))
		})
	}
}

func TestVerifyAccessTokenCacheAliases(t *testing.T) {
	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		t.Run(kind, func(t *testing.T) {
			c, secret := newCacheTestController(t, kind)
			sess := newSession()
			tknStr := newCacheTestToken(t, c, sess)
			data, err := base64.RawURLEncoding.DecodeString(tknStr)
			assert.Nil(t, err)

			var aliases []string
			for _, ch := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
				alias := tknStr[:len(tknStr)-1] + string(ch)
				if decoded, err := base64.RawURLEncoding.DecodeString(alias); err == nil && bytes.Equal(data, decoded) {
					aliases = append(aliases, alias)
				}
			}
			assert.Len(t, aliases, map[int]int{0: 1, 1: 16, 2: 4}[len(data)%3])
			assert.Contains(t, aliases, tknStr)

			for range 2 {
				for _, alias := range aliases {
					claims := assertSameAccessTokenVerification(t, c, alias)
					if assert.NotNil(t, claims) {
						assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
						assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)
					}
					assert.Equal(t, alias == tknStr, c.accessTokenCache.get(alias) != nil)
					assert.Equal(t, alias == tknStr, IsCanonicalToken(alias))
				}
			}
			assert.Equal(t, 1, c.accessTokenCache.len())

			assert.Nil(t, c.ctl.onDeleteSecret(context.Background(), secret))
			for _, alias := range aliases {
				assert.Nil(t, assertSameAccessTokenVerification(t, c, alias))
				assert.Nil(t, c.accessTokenCache.get(alias))
			}
			assert.Equal(t, 0, c.accessTokenCache.len())
		})
	}
}

func TestVerifyAccessTokenCacheNonCanonical(t *testing.T) {
	encode := func(fields ...[]byte) string {
		return base64.RawURLEncoding.EncodeToString(append([]byte{0x1}, bytes.Join(fields, nil)...))
	}
	bytesField := func(num protowire.Number, v []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, num, protowire.BytesType), v)
	}
	varintField := func(num protowire.Number, v uint64) []byte {
		return protowire.AppendVarint(protowire.AppendTag(nil, num, protowire.VarintType), v)
	}
	nonMinimalVarint := func(v uint64) []byte {
		ret := protowire.AppendVarint(nil, v)
		ret[len(ret)-1] |= 0x80
		return append(ret, 0)
	}

	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		t.Run(kind, func(t *testing.T) {
			c, secret := newCacheTestController(t, kind)
			sess := newSession()
			tknStr := newCacheTestToken(t, c, sess)
			tkn, err := c.parseToken(tknStr)
			assert.Nil(t, err)
			assert.True(t, isCanonicalToken(tknStr, tkn))
			assert.True(t, IsCanonicalToken(tknStr))

			contentBytes, err := pbutils.Marshal(tkn.Content)
			assert.Nil(t, err)
			expiresAtBytes, err := pbutils.Marshal(tkn.Content.ExpiresAt)
			assert.Nil(t, err)
			signatureField := bytesField(1, tkn.Signature)
			contentField := bytesField(2, contentBytes)
			content := func(fields ...[]byte) []byte {
				return bytesField(2, bytes.Join(fields, nil))
			}
			assert.Equal(t, tknStr, encode(signatureField, contentField))

			variants := []string{
				encode(signatureField, contentField, varintField(15, 0)),
				encode(signatureField, contentField, varintField(15, 1)),
				encode(signatureField, contentField, varintField(15, 1<<62)),
				encode(signatureField, contentField, protowire.AppendFixed32(protowire.AppendTag(nil, 3, protowire.Fixed32Type), 1)),
				encode(signatureField, contentField, protowire.AppendFixed64(protowire.AppendTag(nil, 100, protowire.Fixed64Type), 1)),
				encode(signatureField, contentField, bytesField(4, []byte("unknown"))),
				encode(varintField(15, 0), signatureField, contentField),
				encode(signatureField, varintField(15, 0), contentField),
				encode(contentField, signatureField),
				encode(bytesField(1, []byte("signature")), signatureField, contentField),
				encode(signatureField, bytesField(2, nil), contentField),
				encode(signatureField, contentField, bytesField(2, nil)),
				encode(nonMinimalVarint(uint64(protowire.EncodeTag(1, protowire.BytesType))),
					protowire.AppendBytes(nil, tkn.Signature), contentField),
				encode(signatureField, protowire.AppendTag(nil, 2, protowire.BytesType),
					nonMinimalVarint(uint64(len(contentBytes))), contentBytes),
				encode(signatureField, content(varintField(1, 0), contentBytes)),
				encode(signatureField, content(bytesField(3, make([]byte, 16)), contentBytes)),
				encode(signatureField, content(contentBytes, bytesField(5, varintField(2, 0)))),
				encode(signatureField, content(bytesField(5, expiresAtBytes), bytesField(4, tkn.Content.TokenID),
					bytesField(3, tkn.Content.Subject), bytesField(2, tkn.Content.KeyID), varintField(1, uint64(tkn.Content.Type)))),
			}

			for i, variant := range variants {
				assert.NotEqual(t, tknStr, variant)
				assert.NotContains(t, variants[:i], variant)
				assert.LessOrEqual(t, len(variant), 220)
				variantTkn, err := c.parseToken(variant)
				if assert.Nil(t, err, variant) {
					assert.False(t, isCanonicalToken(variant, variantTkn), variant)
				}
				assert.False(t, IsCanonicalToken(variant), variant)
			}

			assertVariants := func() {
				t.Helper()
				for range 2 {
					for _, variant := range variants {
						claims := assertSameAccessTokenVerification(t, c, variant)
						if assert.NotNil(t, claims, variant) {
							assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
							assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)
						}
						assert.Nil(t, c.accessTokenCache.get(variant))
					}
				}
			}

			assertVariants()
			assert.Equal(t, 0, c.accessTokenCache.len())
			assert.NotNil(t, assertSameAccessTokenVerification(t, c, tknStr))
			e := c.accessTokenCache.get(tknStr)
			assert.NotNil(t, e)
			assertVariants()
			assert.Equal(t, 1, c.accessTokenCache.len())
			assert.Same(t, e, c.accessTokenCache.get(tknStr))

			c.accessTokenCache = newAccessTokenCache(1)
			assert.NotNil(t, assertSameAccessTokenVerification(t, c, tknStr))
			e = c.accessTokenCache.get(tknStr)
			assert.NotNil(t, e)
			for i := range 64 {
				assert.NotNil(t, assertSameAccessTokenVerification(t, c,
					encode(signatureField, contentField, varintField(15, uint64(i)))))
			}
			assert.Equal(t, 1, c.accessTokenCache.len())
			assert.Same(t, e, c.accessTokenCache.get(tknStr))

			assert.Nil(t, c.ctl.onDeleteSecret(context.Background(), secret))
			for _, variant := range append(variants, tknStr) {
				assert.Nil(t, assertSameAccessTokenVerification(t, c, variant))
				_, err := c.VerifyAccessToken(variant)
				assert.ErrorContains(t, err, "Cannot find key of kid")
			}
			assert.Equal(t, 0, c.accessTokenCache.len())
		})
	}
}

func TestIsCanonicalToken(t *testing.T) {
	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		t.Run(kind, func(t *testing.T) {
			c, _ := newCacheTestController(t, kind)
			tknStr := newCacheTestToken(t, c, newSession())
			assert.True(t, IsCanonicalToken(tknStr))
			data, err := base64.RawURLEncoding.DecodeString(tknStr)
			assert.Nil(t, err)

			for _, invalid := range []string{
				"",
				"!" + tknStr[1:],
				tknStr + "=",
				tknStr[:len(tknStr)-1],
				base64.RawURLEncoding.EncodeToString(append([]byte{0x2}, data[1:]...)),
				base64.RawURLEncoding.EncodeToString(data[1:]),
				base64.RawURLEncoding.EncodeToString(data[:len(data)-1]),
				base64.RawURLEncoding.EncodeToString(append(bytes.Clone(data), 0)),
				base64.RawURLEncoding.EncodeToString([]byte{0x1, 0xff}),
				base64.URLEncoding.EncodeToString(data) + "=",
			} {
				assert.False(t, IsCanonicalToken(invalid), invalid)
			}
		})
	}
}

func TestVerifyAccessTokenCacheKeyChanges(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		t.Run(kind, func(t *testing.T) {
			c, secret := newCacheTestController(t, kind)
			sess := newSession()
			tknStr := newCacheTestToken(t, c, sess)
			assertValid := func(tknStr string) {
				t.Helper()
				claims := assertSameAccessTokenVerification(t, c, tknStr)
				if assert.NotNil(t, claims) {
					assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
				}
				e := c.accessTokenCache.get(tknStr)
				if assert.NotNil(t, e) {
					c.ctl.RLock()
					assert.Same(t, c.ctl.keyMap[e.keyUID], e.key)
					c.ctl.RUnlock()
				}
			}
			assertInvalid := func(tknStr string, errStr string) {
				t.Helper()
				for range 2 {
					assert.Nil(t, assertSameAccessTokenVerification(t, c, tknStr))
					_, err := c.VerifyAccessToken(tknStr)
					assert.ErrorContains(t, err, errStr)
					assert.Nil(t, c.accessTokenCache.get(tknStr))
				}
			}

			assertValid(tknStr)
			e := c.accessTokenCache.get(tknStr)

			newSecret := newCacheTestSecret(t, vutils.UUIDv4(), newCacheTestSigner(t, KindEd25519), time.Now().Add(time.Hour))
			assert.Nil(t, c.ctl.onAddSecret(ctx, newSecret))
			assertValid(tknStr)
			assert.Same(t, e, c.accessTokenCache.get(tknStr))
			newTknStr := newCacheTestToken(t, c, sess)
			assert.NotEqual(t, tknStr, newTknStr)
			assertValid(newTknStr)
			assert.Equal(t, newSecret.Metadata.Uid, c.accessTokenCache.get(newTknStr).keyUID)
			assert.Equal(t, secret.Metadata.Uid, c.accessTokenCache.get(tknStr).keyUID)

			assert.Nil(t, c.ctl.onUpdateSecret(ctx, secret, secret))
			_, ok := c.getCachedAccessToken(tknStr)
			assert.False(t, ok)
			assertValid(tknStr)
			assert.NotSame(t, e, c.accessTokenCache.get(tknStr))
			_, ok = c.getCachedAccessToken(tknStr)
			assert.True(t, ok)
			_, ok = c.getCachedAccessToken(newTknStr)
			assert.True(t, ok)

			assert.Nil(t, c.ctl.onUpdateSecret(ctx, &corev1.Secret{Metadata: &metav1.Metadata{Uid: secret.Metadata.Uid}}, secret))
			assert.Nil(t, c.ctl.onDeleteSecret(ctx, &corev1.Secret{Metadata: &metav1.Metadata{Uid: secret.Metadata.Uid}}))
			_, ok = c.getCachedAccessToken(tknStr)
			assert.True(t, ok)

			assert.Nil(t, c.ctl.onDeleteSecret(ctx, secret))
			assertInvalid(tknStr, "Cannot find key of kid")
			assertValid(newTknStr)

			assert.Nil(t, c.ctl.onAddSecret(ctx, secret))
			assertValid(tknStr)

			for _, replacementKind := range []string{KindEd25519, KindECDSAP256} {
				replacement := newCacheTestSecret(t, secret.Metadata.Uid,
					newCacheTestSigner(t, replacementKind), secret.Metadata.CreatedAt.AsTime())
				assert.Nil(t, c.ctl.onUpdateSecret(ctx, replacement, secret))
				assertInvalid(tknStr, "Invalid signature")
				assertValid(newTknStr)
			}

			assert.Nil(t, c.ctl.onUpdateSecret(ctx, secret, secret))
			assertValid(tknStr)

			assert.Nil(t, c.ctl.onDeleteSecret(ctx, newSecret))
			assertInvalid(newTknStr, "Cannot find key of kid")
			assertValid(tknStr)
			assert.Equal(t, 1, c.accessTokenCache.len())
		})
	}
}

func TestVerifyAccessTokenCacheStaleKey(t *testing.T) {
	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		t.Run(kind, func(t *testing.T) {
			c, secret := newCacheTestController(t, kind)
			key, err := c.chooseJWK()
			assert.Nil(t, err)
			tknStr := newCacheTestToken(t, c, newSession())

			claims, err := c.verifyToken(tknStr, authv1.TokenT0_Content_ACCESS_TOKEN)
			assert.Nil(t, err)
			assert.Same(t, key, claims.key)
			assert.Nil(t, c.ctl.setKey(newCacheTestSecret(t, secret.Metadata.Uid,
				newCacheTestSigner(t, kind), secret.Metadata.CreatedAt.AsTime())))
			c.setCachedAccessToken(tknStr, claims)
			assert.Same(t, key, c.accessTokenCache.get(tknStr).key)
			_, ok := c.getCachedAccessToken(tknStr)
			assert.False(t, ok)
			assert.Nil(t, assertSameAccessTokenVerification(t, c, tknStr))
			assert.Nil(t, c.accessTokenCache.get(tknStr))

			assert.Nil(t, c.ctl.setKey(secret))
			claims, err = c.verifyToken(tknStr, authv1.TokenT0_Content_ACCESS_TOKEN)
			assert.Nil(t, err)
			assert.Nil(t, c.ctl.setKey(secret))
			c.setCachedAccessToken(tknStr, claims)
			_, ok = c.getCachedAccessToken(tknStr)
			assert.False(t, ok)
			assert.NotNil(t, assertSameAccessTokenVerification(t, c, tknStr))
			_, ok = c.getCachedAccessToken(tknStr)
			assert.True(t, ok)

			claims, err = c.verifyToken(tknStr, authv1.TokenT0_Content_ACCESS_TOKEN)
			assert.Nil(t, err)
			assert.Nil(t, c.ctl.onDeleteSecret(context.Background(), secret))
			c.setCachedAccessToken(tknStr, claims)
			_, ok = c.getCachedAccessToken(tknStr)
			assert.False(t, ok)
			assert.Nil(t, assertSameAccessTokenVerification(t, c, tknStr))
			assert.Nil(t, c.accessTokenCache.get(tknStr))
		})
	}
}

func TestVerifyAccessTokenCacheKeyUID(t *testing.T) {
	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		t.Run(kind, func(t *testing.T) {
			c, _ := newCacheTestController(t, kind)
			key, err := c.chooseJWK()
			assert.Nil(t, err)
			alias := vutils.UUIDv4()
			c.ctl.keyMap[alias] = key

			sess := newSession()
			subject, err := c.uidToBytes(sess.Metadata.Uid)
			assert.Nil(t, err)
			tokenID, err := c.uidToBytes(sess.Status.Authentication.TokenID)
			assert.Nil(t, err)
			keyID, err := c.uidToBytes(alias)
			assert.Nil(t, err)
			tknStr := signCacheTestToken(t, key, &authv1.TokenT0_Content{
				Type: authv1.TokenT0_Content_ACCESS_TOKEN, KeyID: keyID, Subject: subject, TokenID: tokenID,
				ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour)),
			})

			claims := assertSameAccessTokenVerification(t, c, tknStr)
			if assert.NotNil(t, claims) {
				assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
			}
			if e := c.accessTokenCache.get(tknStr); assert.NotNil(t, e) {
				assert.Equal(t, alias, e.keyUID)
				assert.Same(t, key, e.key)
			}

			delete(c.ctl.keyMap, alias)
			assert.Nil(t, assertSameAccessTokenVerification(t, c, tknStr))
			assert.Nil(t, c.accessTokenCache.get(tknStr))
		})
	}
}

func TestVerifyAccessTokenCacheExpiry(t *testing.T) {
	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, _ := newCacheTestController(t, kind)
				sess := newSession()
				sess.Status.Authentication.AccessTokenDuration = &metav1.Duration{
					Type: &metav1.Duration_Seconds{Seconds: 10},
				}
				tknStr := newCacheTestToken(t, c, sess)
				tkn, err := c.parseToken(tknStr)
				assert.Nil(t, err)
				expiresAt := tkn.Content.ExpiresAt.AsTime()
				assert.True(t, expiresAt.Equal(time.Now().Add(10*time.Second)))

				assert.NotNil(t, assertSameAccessTokenVerification(t, c, tknStr))
				e := c.accessTokenCache.get(tknStr)
				if !assert.NotNil(t, e) {
					return
				}
				assert.True(t, e.hasExpiry)
				assert.True(t, expiresAt.Equal(e.expiresAt))

				time.Sleep(5 * time.Second)
				assert.NotNil(t, assertSameAccessTokenVerification(t, c, tknStr))
				assert.Same(t, e, c.accessTokenCache.get(tknStr))

				time.Sleep(time.Until(expiresAt))
				assert.True(t, time.Now().Equal(expiresAt))
				assert.NotNil(t, assertSameAccessTokenVerification(t, c, tknStr))
				assert.Same(t, e, c.accessTokenCache.get(tknStr))

				time.Sleep(time.Nanosecond)
				_, ok := c.getCachedAccessToken(tknStr)
				assert.False(t, ok)
				assert.Nil(t, assertSameAccessTokenVerification(t, c, tknStr))
				_, err = c.VerifyAccessToken(tknStr)
				assert.ErrorContains(t, err, "Token is expired")
				assert.Nil(t, c.accessTokenCache.get(tknStr))
				assert.Equal(t, 0, c.accessTokenCache.len())

				subject, err := c.uidToBytes(sess.Metadata.Uid)
				assert.Nil(t, err)
				tokenID, err := c.uidToBytes(sess.Status.Authentication.TokenID)
				assert.Nil(t, err)
				noExpiry, err := c.createToken(&authv1.TokenT0_Content{
					Type: authv1.TokenT0_Content_ACCESS_TOKEN, Subject: subject, TokenID: tokenID,
				})
				assert.Nil(t, err)
				assert.NotNil(t, assertSameAccessTokenVerification(t, c, noExpiry))
				e = c.accessTokenCache.get(noExpiry)
				if !assert.NotNil(t, e) {
					return
				}
				assert.False(t, e.hasExpiry)
				assert.True(t, e.expiresAt.IsZero())

				time.Sleep(100 * 365 * 24 * time.Hour)
				assert.NotNil(t, assertSameAccessTokenVerification(t, c, noExpiry))
				assert.Same(t, e, c.accessTokenCache.get(noExpiry))
			})
		})
	}
}

func TestVerifyAccessTokenCacheCapacity(t *testing.T) {
	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		t.Run(kind, func(t *testing.T) {
			c, secret := newCacheTestController(t, kind)
			c.accessTokenCache = newAccessTokenCache(8)
			var sessions []*corev1.Session
			var tknStrs []string
			for range 64 {
				sess := newSession()
				sessions = append(sessions, sess)
				tknStrs = append(tknStrs, newCacheTestToken(t, c, sess))
			}

			for round := range 2 {
				for i, tknStr := range tknStrs {
					claims := assertSameAccessTokenVerification(t, c, tknStr)
					if assert.NotNil(t, claims) {
						assert.Equal(t, sessions[i].Metadata.Uid, claims.SessionUID)
						assert.Equal(t, sessions[i].Status.Authentication.TokenID, claims.TokenID)
					}
					assert.NotNil(t, c.accessTokenCache.get(tknStr))
					if round == 0 {
						assert.Equal(t, min(i+1, 8), c.accessTokenCache.len())
					} else {
						assert.Equal(t, 8, c.accessTokenCache.len())
					}
				}
			}
			assert.Equal(t, 8, c.accessTokenCache.len())

			assert.Nil(t, c.ctl.onDeleteSecret(context.Background(), secret))
			for _, tknStr := range tknStrs {
				assert.Nil(t, assertSameAccessTokenVerification(t, c, tknStr))
				assert.Nil(t, c.accessTokenCache.get(tknStr))
			}
			assert.Equal(t, 0, c.accessTokenCache.len())
		})
	}
}

func TestVerifyAccessTokenCacheConcurrent(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		t.Run(kind, func(t *testing.T) {
			c, secret := newCacheTestController(t, kind)
			c.accessTokenCache = newAccessTokenCache(8)
			var sessions []*corev1.Session
			var tknStrs []string
			for range 32 {
				sess := newSession()
				sessions = append(sessions, sess)
				tknStrs = append(tknStrs, newCacheTestToken(t, c, sess))
			}

			verifyAll := func(isValid bool) {
				var wg sync.WaitGroup
				for i := range 8 {
					wg.Go(func() {
						for j := range 64 {
							idx := (i*7 + j) % len(tknStrs)
							claims, err := c.VerifyAccessToken(tknStrs[idx])
							if isValid {
								assert.Nil(t, err)
								if assert.NotNil(t, claims) {
									assert.Equal(t, sessions[idx].Metadata.Uid, claims.SessionUID)
									assert.Equal(t, sessions[idx].Status.Authentication.TokenID, claims.TokenID)
								}
							} else {
								assert.NotNil(t, err)
								assert.Nil(t, claims)
							}
						}
					})
				}
				wg.Wait()
			}

			verifyAll(true)

			var wg sync.WaitGroup
			done := make(chan struct{})
			wg.Go(func() {
				other := newCacheTestSecret(t, vutils.UUIDv4(), newCacheTestSigner(t, KindEd25519), time.Now().Add(-time.Hour))
				for {
					select {
					case <-done:
						return
					default:
					}
					assert.Nil(t, c.ctl.onUpdateSecret(ctx, secret, secret))
					assert.Nil(t, c.ctl.onAddSecret(ctx, other))
					assert.Nil(t, c.ctl.onDeleteSecret(ctx, other))
				}
			})
			verifyAll(true)
			close(done)
			wg.Wait()

			assert.Nil(t, c.ctl.setKey(newCacheTestSecret(t, secret.Metadata.Uid,
				newCacheTestSigner(t, kind), secret.Metadata.CreatedAt.AsTime())))
			verifyAll(false)
			assert.Nil(t, c.ctl.onDeleteSecret(ctx, secret))
			verifyAll(false)
			assert.Nil(t, c.ctl.onAddSecret(ctx, secret))
			verifyAll(true)

			var isDeleted atomic.Bool
			for i := range 8 {
				wg.Go(func() {
					for j, after := 0, 0; after < 64; j++ {
						deleted := isDeleted.Load()
						idx := (i*7 + j) % len(tknStrs)
						claims, err := c.VerifyAccessToken(tknStrs[idx])
						if deleted {
							assert.NotNil(t, err)
							assert.Nil(t, claims)
							after++
						} else if err == nil {
							assert.Equal(t, sessions[idx].Metadata.Uid, claims.SessionUID)
						}
					}
				})
			}
			assert.Nil(t, c.ctl.onDeleteSecret(ctx, secret))
			isDeleted.Store(true)
			wg.Wait()
			assert.Equal(t, 0, c.accessTokenCache.len())
		})
	}
}

func waitForKeyLockWaiters(deadline time.Time, funcNames ...string) bool {
	buf := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		stacks := strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n")
		waiting := 0
		for _, funcName := range funcNames {
			for _, stack := range stacks {
				if strings.Contains(stack, "sync.(*RWMutex).RLock") && strings.Contains(stack, funcName) {
					waiting++
					break
				}
			}
		}
		if waiting == len(funcNames) {
			return true
		}
		runtime.Gosched()
	}

	return false
}

func TestVerifyAccessTokenCacheKeyLockWait(t *testing.T) {
	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		t.Run(kind, func(t *testing.T) {
			c, secret := newCacheTestController(t, kind)
			key, err := c.chooseJWK()
			assert.Nil(t, err)
			sess := newSession()
			subject, err := c.uidToBytes(sess.Metadata.Uid)
			assert.Nil(t, err)
			tokenID, err := c.uidToBytes(sess.Status.Authentication.TokenID)
			assert.Nil(t, err)
			keyID, err := c.uidToBytes(key.uid)
			assert.Nil(t, err)
			expiresAt := time.Now().Add(500 * time.Millisecond)
			expiring := signCacheTestToken(t, key, &authv1.TokenT0_Content{
				Type: authv1.TokenT0_Content_ACCESS_TOKEN, KeyID: keyID, Subject: subject, TokenID: tokenID,
				ExpiresAt: pbutils.Timestamp(expiresAt),
			})
			tknStr := newCacheTestToken(t, c, sess)

			verifyWhileLocked := func(tknStr string, deadline time.Time, fn func()) error {
				t.Helper()
				assert.NotNil(t, assertSameAccessTokenVerification(t, c, tknStr))
				_, ok := c.getCachedAccessToken(tknStr)
				assert.True(t, ok)

				var claims *AccessTokenClaims
				var err, wantErr error
				var wg sync.WaitGroup
				c.ctl.Lock()
				wg.Go(func() {
					claims, err = c.VerifyAccessToken(tknStr)
				})
				wg.Go(func() {
					_, wantErr = c.verifyToken(tknStr, authv1.TokenT0_Content_ACCESS_TOKEN)
				})
				isWaiting := waitForKeyLockWaiters(deadline, "getCachedAccessToken", "findKeyByUID")
				if isWaiting {
					fn()
				}
				c.ctl.Unlock()
				wg.Wait()
				if !isWaiting {
					t.Fatal("Verifications did not wait for the key lock")
				}

				if wantErr == nil {
					assert.Nil(t, err)
					assert.Equal(t, &AccessTokenClaims{
						SessionUID: sess.Metadata.Uid,
						TokenID:    sess.Status.Authentication.TokenID,
					}, claims)
					return nil
				}

				assert.Nil(t, claims)
				if assert.NotNil(t, err) {
					assert.Equal(t, wantErr.Error(), err.Error())
				}
				assert.Nil(t, c.accessTokenCache.get(tknStr))
				return err
			}

			assert.ErrorContains(t, verifyWhileLocked(expiring, expiresAt, func() {
				time.Sleep(time.Until(expiresAt) + 10*time.Millisecond)
			}), "Token is expired")

			deadline := time.Now().Add(time.Minute)
			assert.Nil(t, verifyWhileLocked(tknStr, deadline, func() {}))
			e := c.accessTokenCache.get(tknStr)
			assert.Nil(t, verifyWhileLocked(tknStr, deadline, func() {}))
			assert.Same(t, e, c.accessTokenCache.get(tknStr))

			reset := &jwtKey{kind: key.kind, key: key.key, publicKey: key.publicKey, createdAt: key.createdAt, uid: key.uid}
			assert.Nil(t, verifyWhileLocked(tknStr, deadline, func() {
				c.ctl.keyMap[key.uid] = reset
			}))
			assert.NotSame(t, e, c.accessTokenCache.get(tknStr))
			assert.Same(t, reset, c.accessTokenCache.get(tknStr).key)

			replacement := newCacheTestSigner(t, kind)
			assert.ErrorContains(t, verifyWhileLocked(tknStr, deadline, func() {
				c.ctl.keyMap[key.uid] = &jwtKey{
					kind: kind, key: replacement, publicKey: replacement.Public(), createdAt: key.createdAt, uid: key.uid,
				}
			}), "Invalid signature")

			assert.Nil(t, c.ctl.setKey(secret))
			assert.ErrorContains(t, verifyWhileLocked(tknStr, deadline, func() {
				delete(c.ctl.keyMap, key.uid)
			}), "Cannot find key of kid")
			assert.Equal(t, 0, c.accessTokenCache.len())
		})
	}
}

func TestAccessTokenCacheSecretWatcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	signCtl, err := NewJWKController(ctx, tst.C.OcteliumC, nil)
	assert.Nil(t, err)
	verifyCtl, err := NewJWKController(ctx, tst.C.OcteliumC, &Opts{IsVerificationMode: true})
	assert.Nil(t, err)
	assert.Nil(t, verifyCtl.Run(ctx))
	assert.Equal(t, accessTokenCacheMaxEntries, verifyCtl.accessTokenCache.maxEntries)
	assert.Equal(t, accessTokenCacheMaxEntries, signCtl.accessTokenCache.maxEntries)

	waitForKey := func(uid string, isFound bool) {
		t.Helper()
		assert.Eventually(t, func() bool {
			_, err := verifyCtl.findKeyByUID(uid)
			return (err == nil) == isFound
		}, 10*time.Second, 20*time.Millisecond)
	}

	sec2, err := jwkutils.CreateJWKSecret(ctx, tst.C.OcteliumC)
	assert.Nil(t, err)
	waitForKey(sec2.Metadata.Uid, true)

	sess := newSession()
	tknStr, err := signCtl.CreateAccessToken(sess)
	assert.Nil(t, err)
	claims, err := verifyCtl.VerifyAccessToken(tknStr)
	assert.Nil(t, err)
	assert.Equal(t, &AccessTokenClaims{SessionUID: sess.Metadata.Uid, TokenID: sess.Status.Authentication.TokenID}, claims)
	e := verifyCtl.accessTokenCache.get(tknStr)
	if !assert.NotNil(t, e) {
		return
	}
	assert.NotEqual(t, sec2.Metadata.Uid, e.keyUID)
	_, ok := verifyCtl.getCachedAccessToken(tknStr)
	assert.True(t, ok)

	sec3, err := jwkutils.CreateJWKSecret(ctx, tst.C.OcteliumC)
	assert.Nil(t, err)
	waitForKey(sec3.Metadata.Uid, true)
	claims, err = verifyCtl.VerifyAccessToken(tknStr)
	assert.Nil(t, err)
	assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
	assert.Same(t, e, verifyCtl.accessTokenCache.get(tknStr))

	sec1, err := tst.C.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Uid: e.keyUID})
	assert.Nil(t, err)
	sec1.Metadata.SystemLabels["key-rotated"] = "true"
	_, err = tst.C.OcteliumC.CoreC().UpdateSecret(ctx, sec1)
	assert.Nil(t, err)
	assert.Eventually(t, func() bool {
		verifyCtl.ctl.RLock()
		defer verifyCtl.ctl.RUnlock()
		return verifyCtl.ctl.keyMap[e.keyUID] != e.key
	}, 10*time.Second, 20*time.Millisecond)
	_, ok = verifyCtl.getCachedAccessToken(tknStr)
	assert.False(t, ok)
	claims, err = verifyCtl.VerifyAccessToken(tknStr)
	assert.Nil(t, err)
	assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
	e2 := verifyCtl.accessTokenCache.get(tknStr)
	if assert.NotNil(t, e2) {
		assert.NotSame(t, e, e2)
		assert.Equal(t, e.keyUID, e2.keyUID)
	}
	_, ok = verifyCtl.getCachedAccessToken(tknStr)
	assert.True(t, ok)

	_, err = tst.C.OcteliumC.CoreC().DeleteSecret(ctx, &rmetav1.DeleteOptions{Uid: e.keyUID})
	assert.Nil(t, err)
	waitForKey(e.keyUID, false)
	_, err = verifyCtl.VerifyAccessToken(tknStr)
	assert.ErrorContains(t, err, "Cannot find key of kid")
	assert.Nil(t, verifyCtl.accessTokenCache.get(tknStr))
	_, err = verifyCtl.VerifyAccessToken(tknStr)
	assert.ErrorContains(t, err, "Cannot find key of kid")
	_, err = signCtl.VerifyAccessToken(tknStr)
	assert.Nil(t, err)
}

func BenchmarkVerifyAccessToken(b *testing.B) {
	for _, kind := range []string{KindEd25519, KindECDSAP256} {
		c, _ := newCacheTestController(b, kind)
		tknStr := newCacheTestToken(b, c, newSession())
		otherTknStr := newCacheTestToken(b, c, newSession())

		b.Run(kind+"/uncached", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := c.verifyToken(tknStr, authv1.TokenT0_Content_ACCESS_TOKEN); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(kind+"/cached", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := c.VerifyAccessToken(tknStr); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(kind+"/cachedParallel", func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := c.VerifyAccessToken(tknStr); err != nil {
						b.Fatal(err)
					}
				}
			})
		})

		b.Run(kind+"/miss", func(b *testing.B) {
			c.accessTokenCache = newAccessTokenCache(1)
			tknStrs := []string{tknStr, otherTknStr}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if _, err := c.VerifyAccessToken(tknStrs[i%2]); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	}
}
