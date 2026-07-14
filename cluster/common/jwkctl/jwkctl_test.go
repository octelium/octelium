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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/jwkctl/jwkutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	jwkCtl, err := NewJWKController(ctx, tst.C.OcteliumC, nil)
	assert.Nil(t, err)

	uidBytes := func(uid string) []byte {
		b, err := jwkCtl.uidToBytes(uid)
		assert.Nil(t, err)
		return b
	}

	marshalTknPrefix := func(prefix byte, tkn *authv1.TokenT0) string {
		tknBytes, err := pbutils.Marshal(tkn)
		assert.Nil(t, err)

		totalTknBytes := make([]byte, len(tknBytes)+1)
		copy(totalTknBytes[1:], tknBytes)
		totalTknBytes[0] = prefix
		return base64.RawURLEncoding.EncodeToString(totalTknBytes)
	}

	marshalTkn := func(tkn *authv1.TokenT0) string {
		return marshalTknPrefix(0x1, tkn)
	}

	{
		_, err = jwkCtl.parseToken("")
		assert.NotNil(t, err)

		_, err = jwkCtl.parseToken(utilrand.GetRandomString(32))
		assert.NotNil(t, err)

		_, err = jwkCtl.parseToken(utilrand.GetRandomString(300))
		assert.NotNil(t, err)

		_, err = jwkCtl.parseToken(utilrand.GetRandomString(3000))
		assert.NotNil(t, err)

		_, err = jwkCtl.parseToken(utilrand.GetRandomString(200))
		assert.NotNil(t, err)

		_, err = jwkCtl.parseToken(utilrand.GetRandomString(20))
		assert.NotNil(t, err)

		_, err = jwkCtl.parseToken(utilrand.GetRandomString(2000))
		assert.NotNil(t, err)
	}
	{
		tkn := &authv1.TokenT0{}
		_, err = jwkCtl.parseToken(marshalTkn(tkn))
		assert.NotNil(t, err)
	}
	{
		tkn := &authv1.TokenT0{
			Signature: utilrand.GetRandomBytesMust(64),
		}
		_, err = jwkCtl.parseToken(marshalTkn(tkn))
		assert.NotNil(t, err)
	}

	{
		tkn := &authv1.TokenT0{
			Content: &authv1.TokenT0_Content{},
		}
		_, err = jwkCtl.parseToken(marshalTkn(tkn))
		assert.NotNil(t, err)
	}
	{
		tkn := &authv1.TokenT0{
			Content:   &authv1.TokenT0_Content{},
			Signature: utilrand.GetRandomBytesMust(64),
		}
		_, err = jwkCtl.parseToken(marshalTkn(tkn))
		assert.NotNil(t, err)
	}
	{
		tkn := &authv1.TokenT0{
			Content: &authv1.TokenT0_Content{
				KeyID: uidBytes(vutils.UUIDv4()),
			},
			Signature: utilrand.GetRandomBytesMust(64),
		}
		_, err = jwkCtl.parseToken(marshalTkn(tkn))
		assert.NotNil(t, err)
	}
	{
		k, err := jwkCtl.chooseJWK()
		assert.Nil(t, err)
		tkn := &authv1.TokenT0{
			Content: &authv1.TokenT0_Content{
				KeyID: uidBytes(k.uid),
			},
			Signature: utilrand.GetRandomBytesMust(64),
		}
		_, err = jwkCtl.parseToken(marshalTkn(tkn))
		assert.NotNil(t, err)
	}
	{
		k, err := jwkCtl.chooseJWK()
		assert.Nil(t, err)
		tkn := &authv1.TokenT0{
			Content: &authv1.TokenT0_Content{
				KeyID:   uidBytes(k.uid),
				Subject: uidBytes(vutils.UUIDv4()),
				TokenID: uidBytes(vutils.UUIDv4()),
			},
			Signature: utilrand.GetRandomBytesMust(64),
		}
		_, err = jwkCtl.parseToken(marshalTkn(tkn))
		assert.NotNil(t, err)
	}
	{
		k, err := jwkCtl.chooseJWK()
		assert.Nil(t, err)
		tkn := &authv1.TokenT0{
			Content: &authv1.TokenT0_Content{
				KeyID:   uidBytes(k.uid),
				Subject: uidBytes(vutils.UUIDv4()),
				TokenID: uidBytes(vutils.UUIDv4()),
				Type:    authv1.TokenT0_Content_ACCESS_TOKEN,
			},
			Signature: utilrand.GetRandomBytesMust(64),
		}
		_, err = jwkCtl.parseToken(marshalTkn(tkn))
		assert.NotNil(t, err)
	}
	{
		k, err := jwkCtl.chooseJWK()
		assert.Nil(t, err)
		tkn := &authv1.TokenT0{
			Content: &authv1.TokenT0_Content{
				KeyID:     uidBytes(k.uid),
				Subject:   uidBytes(vutils.UUIDv4()),
				TokenID:   uidBytes(vutils.UUIDv4()),
				Type:      authv1.TokenT0_Content_ACCESS_TOKEN,
				ExpiresAt: pbutils.Timestamp(time.Now().Add(4 * time.Hour)),
			},
			Signature: utilrand.GetRandomBytesMust(64),
		}
		_, err = jwkCtl.parseToken(marshalTkn((tkn)))
		assert.NotNil(t, err)
	}

	{

		content := &authv1.TokenT0_Content{
			Subject:   uidBytes(vutils.UUIDv4()),
			TokenID:   uidBytes(vutils.UUIDv4()),
			Type:      authv1.TokenT0_Content_ACCESS_TOKEN,
			ExpiresAt: pbutils.Timestamp(time.Now().Add(4 * time.Hour)),
		}

		tknStr, err := jwkCtl.createToken(content)
		assert.Nil(t, err)
		assert.Equal(t, 16, len(content.KeyID))

		tkn, err := jwkCtl.parseToken(tknStr)
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(tkn.Content, content))
	}

	{
		content := &authv1.TokenT0_Content{
			Subject:   uidBytes(vutils.UUIDv4()),
			TokenID:   uidBytes(vutils.UUIDv4()),
			Type:      authv1.TokenT0_Content_ACCESS_TOKEN,
			ExpiresAt: pbutils.Timestamp(time.Now().Add(2 * time.Second)),
		}

		tknStr, err := jwkCtl.createToken(content)
		assert.Nil(t, err)

		_, err = jwkCtl.parseToken(tknStr)
		assert.Nil(t, err)

		time.Sleep(3 * time.Second)

		_, err = jwkCtl.parseToken(tknStr)
		assert.NotNil(t, err)
	}

	{
		content := &authv1.TokenT0_Content{
			Subject: uidBytes(vutils.UUIDv4()),
			TokenID: uidBytes(vutils.UUIDv4()),
			Type:    authv1.TokenT0_Content_ACCESS_TOKEN,
		}

		tknStr, err := jwkCtl.createToken(content)
		assert.Nil(t, err)

		_, err = jwkCtl.parseToken(tknStr)
		assert.Nil(t, err)
	}

	{
		sess := &corev1.Session{
			Metadata: &metav1.Metadata{
				Uid: vutils.UUIDv4(),
			},
			Spec: &corev1.Session_Spec{},
			Status: &corev1.Session_Status{
				Authentication: &corev1.Session_Status_Authentication{
					SetAt:   pbutils.Now(),
					TokenID: vutils.UUIDv4(),
					AccessTokenDuration: &metav1.Duration{
						Type: &metav1.Duration_Hours{
							Hours: 4,
						},
					},
					RefreshTokenDuration: &metav1.Duration{
						Type: &metav1.Duration_Hours{
							Hours: 4,
						},
					},
				},
			},
		}

		{
			tknStr, err := jwkCtl.CreateAccessToken(sess)
			assert.Nil(t, err)

			tkn, err := jwkCtl.verifyToken(tknStr, authv1.TokenT0_Content_ACCESS_TOKEN)
			assert.Nil(t, err)

			assert.Equal(t, tkn.tkn.Content.ExpiresAt.GetSeconds(),
				pbutils.Timestamp(sess.Status.Authentication.SetAt.AsTime().Add(
					umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToGo())).GetSeconds())

			claims, err := jwkCtl.VerifyAccessToken(tknStr)
			assert.Nil(t, err)
			assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
			assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)
		}

		{
			tknStr, err := jwkCtl.CreateRefreshToken(sess)
			assert.Nil(t, err)

			tkn, err := jwkCtl.verifyToken(tknStr, authv1.TokenT0_Content_REFRESH_TOKEN)
			assert.Nil(t, err)

			assert.Equal(t, tkn.tkn.Content.ExpiresAt.GetSeconds(),
				pbutils.Timestamp(sess.Status.Authentication.SetAt.AsTime().Add(
					umetav1.ToDuration(sess.Status.Authentication.RefreshTokenDuration).ToGo())).GetSeconds())

			claims, err := jwkCtl.VerifyRefreshToken(tknStr)
			assert.Nil(t, err)
			assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
			assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)
		}

	}

	{
		cred := &corev1.Credential{
			Metadata: &metav1.Metadata{
				Uid: vutils.UUIDv4(),
			},
			Spec: &corev1.Credential_Spec{
				ExpiresAt: pbutils.Timestamp(time.Now().Add(4 * time.Hour)),
			},
			Status: &corev1.Credential_Status{
				TokenID: vutils.UUIDv4(),
			},
		}

		tknStr, err := jwkCtl.CreateCredential(cred)
		assert.Nil(t, err)

		tkn, err := jwkCtl.verifyToken(tknStr, authv1.TokenT0_Content_CREDENTIAL)
		assert.Nil(t, err)

		assert.Equal(t, tkn.tkn.Content.ExpiresAt.GetSeconds(),
			cred.Spec.ExpiresAt.GetSeconds())

		claims, err := jwkCtl.VerifyCredential(tknStr)
		assert.Nil(t, err)
		assert.Equal(t, cred.Metadata.Uid, claims.UID)
		assert.Equal(t, cred.Status.TokenID, claims.TokenID)
	}

	{
		sess := &corev1.Session{
			Metadata: &metav1.Metadata{
				Uid: vutils.UUIDv4(),
			},
			Spec: &corev1.Session_Spec{},
			Status: &corev1.Session_Status{
				Authentication: &corev1.Session_Status_Authentication{
					SetAt:   pbutils.Now(),
					TokenID: vutils.UUIDv4(),
					AccessTokenDuration: &metav1.Duration{
						Type: &metav1.Duration_Hours{
							Hours: 4,
						},
					},
					RefreshTokenDuration: &metav1.Duration{
						Type: &metav1.Duration_Hours{
							Hours: 4,
						},
					},
				},
			},
		}

		tknStr, err := jwkCtl.CreateAccessToken(sess)
		assert.Nil(t, err)

		{

			tknBytes, err := base64.RawURLEncoding.DecodeString(tknStr)
			assert.Nil(t, err)

			tkn := &authv1.TokenT0{}
			err = pbutils.Unmarshal(tknBytes[1:], tkn)
			assert.Nil(t, err)

			tkn.Signature = utilrand.GetRandomBytesMust(64)

			invalidTknStr := marshalTkn(tkn)

			_, err = jwkCtl.VerifyAccessToken(invalidTknStr)
			assert.NotNil(t, err)
		}

		{

			tknBytes, err := base64.RawURLEncoding.DecodeString(tknStr)
			assert.Nil(t, err)

			tkn := &authv1.TokenT0{}
			err = pbutils.Unmarshal(tknBytes[1:], tkn)
			assert.Nil(t, err)

			_, err = jwkCtl.VerifyAccessToken(marshalTknPrefix(0, tkn))
			assert.NotNil(t, err)
		}

		{

			tknBytes, err := base64.RawURLEncoding.DecodeString(tknStr)
			assert.Nil(t, err)

			tkn := &authv1.TokenT0{}
			err = pbutils.Unmarshal(tknBytes[1:], tkn)
			assert.Nil(t, err)

			_, err = jwkCtl.VerifyAccessToken(marshalTknPrefix(1, tkn))
			assert.Nil(t, err)
		}
	}

	{
		for i := 0; i < 10000; i++ {

			sess := &corev1.Session{
				Metadata: &metav1.Metadata{
					Uid: vutils.UUIDv4(),
				},
				Spec: &corev1.Session_Spec{},
				Status: &corev1.Session_Status{
					Authentication: &corev1.Session_Status_Authentication{
						SetAt:   pbutils.Now(),
						TokenID: vutils.UUIDv4(),
						AccessTokenDuration: &metav1.Duration{
							Type: &metav1.Duration_Weeks{
								Weeks: uint32(utilrand.GetRandomRangeMath(4, 1000)),
							},
						},
						RefreshTokenDuration: &metav1.Duration{
							Type: &metav1.Duration_Weeks{
								Weeks: uint32(utilrand.GetRandomRangeMath(1000, 2000)),
							},
						},
					},
				},
			}

			tknStr, err := jwkCtl.CreateAccessToken(sess)
			assert.Nil(t, err)

			assert.True(t, len(tknStr) < 300)
			assert.True(t, len(tknStr) > 150)
		}
	}

	{
		{
			_, err = jwkCtl.getUID(nil)
			assert.NotNil(t, err)
		}
		{
			_, err = jwkCtl.getUID([]byte{})
			assert.NotNil(t, err)
		}
		{
			_, err = jwkCtl.getUID(utilrand.GetRandomBytesMust(8))
			assert.NotNil(t, err)
		}
		{
			_, err = jwkCtl.getUID(utilrand.GetRandomBytesMust(16))
			assert.NotNil(t, err)
		}
		{
			uid, err := uuid.NewV7()
			assert.Nil(t, err)
			uidBytes, err := uid.MarshalBinary()
			assert.Nil(t, err)
			_, err = jwkCtl.getUID(uidBytes)
			assert.NotNil(t, err)
		}
		{
			uid, err := uuid.NewV6()
			assert.Nil(t, err)
			uidBytes, err := uid.MarshalBinary()
			assert.Nil(t, err)
			_, err = jwkCtl.getUID(uidBytes)
			assert.NotNil(t, err)
		}

		{
			uid := uuid.New()
			uidBytes, err := uid.MarshalBinary()
			assert.Nil(t, err)
			res, err := jwkCtl.getUID(uidBytes)
			assert.Nil(t, err)
			assert.Equal(t, res, uid.String())
		}

	}

}

func TestRegexTokenT0(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		invalids := []string{
			"",
			utilrand.GetRandomString(100),
			utilrand.GetRandomString(10),
			utilrand.GetRandomString(1000),
			utilrand.GetRandomString(250),
		}

		for _, tkn := range invalids {
			assert.False(t, rgxT0.MatchString(tkn))
		}
	}

	assert.True(t, rgxT0.MatchString(utilrand.GetRandomString(178)))
}

func TestChooseJWK(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	jwkCtl, err := NewJWKController(ctx, tst.C.OcteliumC, nil)
	assert.Nil(t, err)

	{
		assert.True(t, len(jwkCtl.ctl.keyMap) > 0)
	}

	{
		k1, err := jwkCtl.chooseJWK()
		assert.Nil(t, err)
		time.Sleep(1 * time.Second)

		sec2, err := jwkutils.CreateJWKSecret(ctx, jwkCtl.octeliumC)
		assert.Nil(t, err)

		err = jwkCtl.ctl.setKey(sec2)
		assert.Nil(t, err)

		k2, err := jwkCtl.chooseJWK()
		assert.Nil(t, err)

		assert.Equal(t, k2.uid, sec2.Metadata.Uid)

		time.Sleep(1 * time.Second)

		sec3, err := jwkutils.CreateJWKSecret(ctx, jwkCtl.octeliumC)
		assert.Nil(t, err)

		err = jwkCtl.ctl.setKey(sec3)
		assert.Nil(t, err)

		k3, err := jwkCtl.chooseJWK()
		assert.Nil(t, err)

		assert.Equal(t, k3.uid, sec3.Metadata.Uid)

		err = jwkCtl.ctl.onDeleteSecret(ctx, sec2)
		assert.Nil(t, err)

		k31, err := jwkCtl.chooseJWK()
		assert.Nil(t, err)

		assert.Equal(t, k31.uid, sec3.Metadata.Uid)

		err = jwkCtl.ctl.onDeleteSecret(ctx, sec3)
		assert.Nil(t, err)

		k11, err := jwkCtl.chooseJWK()
		assert.Nil(t, err)

		assert.Equal(t, k11.uid, k1.uid)
	}
}

func TestMulti(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	jwkCtl, err := NewJWKController(ctx, tst.C.OcteliumC, nil)
	assert.Nil(t, err)

	uidBytes := func(uid string) []byte {
		b, err := jwkCtl.uidToBytes(uid)
		assert.Nil(t, err)
		return b
	}

	var sec1 *corev1.Secret
	{
		assert.Equal(t, 1, len(jwkCtl.ctl.keyMap))
		for _, v := range jwkCtl.ctl.keyMap {
			sec1, err = jwkCtl.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
				Uid: v.uid,
			})
			assert.Nil(t, err)
		}
	}

	{

		content := &authv1.TokenT0_Content{
			Subject: uidBytes(vutils.UUIDv4()),
			TokenID: uidBytes(vutils.UUIDv4()),
			Type:    authv1.TokenT0_Content_CREDENTIAL,
		}

		tknStr, err := jwkCtl.createToken(content)
		assert.Nil(t, err)

		t0, err := jwkCtl.parseToken(tknStr)
		assert.Nil(t, err)

		kUID, err := jwkCtl.getUID(t0.Content.KeyID)
		assert.Nil(t, err)
		assert.Equal(t, sec1.Metadata.Uid, kUID)
	}

	{
		time.Sleep(1 * time.Second)
		sec2, err := jwkutils.CreateJWKSecret(ctx, jwkCtl.octeliumC)
		assert.Nil(t, err)

		err = jwkCtl.ctl.setKey(sec2)
		assert.Nil(t, err)

		assert.Equal(t, 2, len(jwkCtl.ctl.keyMap))

		content := &authv1.TokenT0_Content{
			Subject: uidBytes(vutils.UUIDv4()),
			TokenID: uidBytes(vutils.UUIDv4()),
			Type:    authv1.TokenT0_Content_CREDENTIAL,
		}

		tknStr, err := jwkCtl.createToken(content)
		assert.Nil(t, err)

		t0, err := jwkCtl.parseToken(tknStr)
		assert.Nil(t, err)

		kUID, err := jwkCtl.getUID(t0.Content.KeyID)
		assert.Nil(t, err)
		assert.Equal(t, sec2.Metadata.Uid, kUID)

		{
			_, err := jwkCtl.parseToken(tknStr)
			assert.Nil(t, err)
		}

		err = jwkCtl.ctl.onDeleteSecret(ctx, sec2)
		assert.Nil(t, err)

		assert.Equal(t, 1, len(jwkCtl.ctl.keyMap))

		_, err = jwkCtl.parseToken(tknStr)
		assert.NotNil(t, err)
	}

	{
		content := &authv1.TokenT0_Content{
			Subject: uidBytes(vutils.UUIDv4()),
			TokenID: uidBytes(vutils.UUIDv4()),
			Type:    authv1.TokenT0_Content_CREDENTIAL,
		}

		tknStr, err := jwkCtl.createToken(content)
		assert.Nil(t, err)

		t0, err := jwkCtl.parseToken(tknStr)
		assert.Nil(t, err)

		kUID, err := jwkCtl.getUID(t0.Content.KeyID)
		assert.Nil(t, err)
		assert.Equal(t, sec1.Metadata.Uid, kUID)
	}
}

func newSession() *corev1.Session {
	return &corev1.Session{
		Metadata: &metav1.Metadata{
			Uid: vutils.UUIDv4(),
		},
		Spec: &corev1.Session_Spec{},
		Status: &corev1.Session_Status{
			Authentication: &corev1.Session_Status_Authentication{
				SetAt:   pbutils.Now(),
				TokenID: vutils.UUIDv4(),
				AccessTokenDuration: &metav1.Duration{
					Type: &metav1.Duration_Hours{
						Hours: 4,
					},
				},
				RefreshTokenDuration: &metav1.Duration{
					Type: &metav1.Duration_Hours{
						Hours: 4,
					},
				},
			},
		},
	}
}

func TestVerificationMode(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	signCtl, err := NewJWKController(ctx, tst.C.OcteliumC, nil)
	assert.Nil(t, err)

	verifyCtl, err := NewJWKController(ctx, tst.C.OcteliumC, &Opts{IsVerificationMode: true})
	assert.Nil(t, err)

	{
		verifyCtl.ctl.RLock()
		assert.True(t, len(verifyCtl.ctl.keyMap) > 0)
		for _, k := range verifyCtl.ctl.keyMap {
			assert.Nil(t, k.key)
			assert.NotNil(t, k.publicKey)
			assert.NotEmpty(t, k.kind)
		}
		verifyCtl.ctl.RUnlock()

		signCtl.ctl.RLock()
		assert.True(t, len(signCtl.ctl.keyMap) > 0)
		for _, k := range signCtl.ctl.keyMap {
			assert.NotNil(t, k.key)
			assert.NotNil(t, k.publicKey)
			assert.NotEmpty(t, k.kind)
		}
		signCtl.ctl.RUnlock()
	}

	sess := newSession()

	{
		tknStr, err := signCtl.CreateAccessToken(sess)
		assert.Nil(t, err)

		claims, err := verifyCtl.VerifyAccessToken(tknStr)
		assert.Nil(t, err)
		assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
		assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)
	}

	{
		tknStr, err := signCtl.CreateRefreshToken(sess)
		assert.Nil(t, err)

		claims, err := verifyCtl.VerifyRefreshToken(tknStr)
		assert.Nil(t, err)
		assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
		assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)
	}

	{
		_, err := verifyCtl.CreateAccessToken(sess)
		assert.NotNil(t, err)

		_, err = verifyCtl.CreateRefreshToken(sess)
		assert.NotNil(t, err)

		cred := &corev1.Credential{
			Metadata: &metav1.Metadata{
				Uid: vutils.UUIDv4(),
			},
			Spec: &corev1.Credential_Spec{
				ExpiresAt: pbutils.Timestamp(time.Now().Add(4 * time.Hour)),
			},
			Status: &corev1.Credential_Status{
				TokenID: vutils.UUIDv4(),
			},
		}
		_, err = verifyCtl.CreateCredential(cred)
		assert.NotNil(t, err)

		subject, err := verifyCtl.uidToBytes(vutils.UUIDv4())
		assert.Nil(t, err)
		tokenID, err := verifyCtl.uidToBytes(vutils.UUIDv4())
		assert.Nil(t, err)
		_, err = verifyCtl.createToken(&authv1.TokenT0_Content{
			Subject: subject,
			TokenID: tokenID,
			Type:    authv1.TokenT0_Content_ACCESS_TOKEN,
		})
		assert.NotNil(t, err)
	}

	{
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		assert.Nil(t, err)

		uid := vutils.UUIDv4()

		signCtl.ctl.Lock()
		signCtl.ctl.keyMap[uid] = &jwtKey{
			kind:      KindECDSAP256,
			key:       priv,
			publicKey: &priv.PublicKey,
			createdAt: time.Now().Add(time.Hour),
			uid:       uid,
		}
		signCtl.ctl.Unlock()

		verifyCtl.ctl.Lock()
		verifyCtl.ctl.keyMap[uid] = &jwtKey{
			kind:      KindECDSAP256,
			publicKey: &priv.PublicKey,
			createdAt: time.Now().Add(time.Hour),
			uid:       uid,
		}
		verifyCtl.ctl.Unlock()

		tknStr, err := signCtl.CreateAccessToken(sess)
		assert.Nil(t, err)

		t0, err := signCtl.parseToken(tknStr)
		assert.Nil(t, err)
		kid, err := signCtl.getUID(t0.Content.KeyID)
		assert.Nil(t, err)
		assert.Equal(t, uid, kid)

		claims, err := verifyCtl.VerifyAccessToken(tknStr)
		assert.Nil(t, err)
		assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
		assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)
	}
}

func TestECDSAToken(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	jwkCtl, err := NewJWKController(ctx, tst.C.OcteliumC, nil)
	assert.Nil(t, err)

	uidBytes := func(uid string) []byte {
		b, err := jwkCtl.uidToBytes(uid)
		assert.Nil(t, err)
		return b
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	uid := vutils.UUIDv4()

	jwkCtl.ctl.Lock()
	jwkCtl.ctl.keyMap[uid] = &jwtKey{
		kind:      KindECDSAP256,
		key:       priv,
		publicKey: &priv.PublicKey,
		createdAt: time.Now().Add(time.Hour),
		uid:       uid,
	}
	jwkCtl.ctl.Unlock()

	{
		k, err := jwkCtl.chooseJWK()
		assert.Nil(t, err)
		assert.Equal(t, uid, k.uid)
		assert.Equal(t, KindECDSAP256, k.kind)
	}

	{
		content := &authv1.TokenT0_Content{
			Subject:   uidBytes(vutils.UUIDv4()),
			TokenID:   uidBytes(vutils.UUIDv4()),
			Type:      authv1.TokenT0_Content_ACCESS_TOKEN,
			ExpiresAt: pbutils.Timestamp(time.Now().Add(4 * time.Hour)),
		}

		tknStr, err := jwkCtl.createToken(content)
		assert.Nil(t, err)
		assert.Equal(t, 16, len(content.KeyID))
		assert.True(t, len(tknStr) < 300)
		assert.True(t, len(tknStr) > 150)

		kid, err := jwkCtl.getUID(content.KeyID)
		assert.Nil(t, err)
		assert.Equal(t, uid, kid)

		tkn, err := jwkCtl.parseToken(tknStr)
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(tkn.Content, content))
		assert.Equal(t, 64, len(tkn.Signature))
	}

	{
		sess := newSession()

		tknStr, err := jwkCtl.CreateAccessToken(sess)
		assert.Nil(t, err)

		claims, err := jwkCtl.VerifyAccessToken(tknStr)
		assert.Nil(t, err)
		assert.Equal(t, sess.Metadata.Uid, claims.SessionUID)
		assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)
	}

	{
		content := &authv1.TokenT0_Content{
			Subject: uidBytes(vutils.UUIDv4()),
			TokenID: uidBytes(vutils.UUIDv4()),
			Type:    authv1.TokenT0_Content_ACCESS_TOKEN,
		}

		tknStr, err := jwkCtl.createToken(content)
		assert.Nil(t, err)

		tknBytes, err := base64.RawURLEncoding.DecodeString(tknStr)
		assert.Nil(t, err)

		tkn := &authv1.TokenT0{}
		err = pbutils.Unmarshal(tknBytes[1:], tkn)
		assert.Nil(t, err)

		tkn.Signature = utilrand.GetRandomBytesMust(64)

		tamperedBytes, err := pbutils.Marshal(tkn)
		assert.Nil(t, err)

		finalBytes := make([]byte, len(tamperedBytes)+1)
		finalBytes[0] = 0x1
		copy(finalBytes[1:], tamperedBytes)

		_, err = jwkCtl.parseToken(base64.RawURLEncoding.EncodeToString(finalBytes))
		assert.NotNil(t, err)
	}
}

func TestECDSASignVerify(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	content := utilrand.GetRandomBytesMust(128)

	sig, err := signECDSAP256(priv, content)
	assert.Nil(t, err)
	assert.Equal(t, 64, len(sig))

	assert.True(t, verifyECDSAP256(&priv.PublicKey, content, sig))

	assert.False(t, verifyECDSAP256(&priv.PublicKey, utilrand.GetRandomBytesMust(128), sig))

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)
	assert.False(t, verifyECDSAP256(&other.PublicKey, content, sig))

	assert.False(t, verifyECDSAP256(&priv.PublicKey, content, sig[:63]))
	assert.False(t, verifyECDSAP256(&priv.PublicKey, content, append(sig, 0x0)))

	assert.False(t, verifyECDSAP256(&priv.PublicKey, content, make([]byte, 64)))

	{
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		n := priv.Curve.Params().N
		highS := new(big.Int).Sub(n, s)

		malleable := make([]byte, 64)
		r.FillBytes(malleable[:32])
		highS.FillBytes(malleable[32:])

		assert.True(t, s.Cmp(highS) != 0)
		assert.False(t, verifyECDSAP256(&priv.PublicKey, content, malleable))
	}
}
