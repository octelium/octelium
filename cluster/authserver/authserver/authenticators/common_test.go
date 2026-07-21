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

package authenticators

import (
	"context"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestEncryptDecryptData(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		plaintext := utilrand.GetRandomBytesMust(128)

		enc, err := EncryptData(ctx, fakeC.OcteliumC, plaintext)
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, enc)
		assert.NotNil(t, enc.KeySecretRef)
		assert.Equal(t, 12, len(enc.Nonce))
		assert.True(t, len(enc.Ciphertext) > 0)
		assert.NotEqual(t, plaintext, enc.Ciphertext)

		dec, err := DecryptData(ctx, fakeC.OcteliumC, enc)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, plaintext, dec)
	}

	{
		plaintext := []byte{}

		enc, err := EncryptData(ctx, fakeC.OcteliumC, plaintext)
		assert.Nil(t, err)

		dec, err := DecryptData(ctx, fakeC.OcteliumC, enc)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(dec))
	}

	{
		plaintext := utilrand.GetRandomBytesMust(64 * 1024)

		enc, err := EncryptData(ctx, fakeC.OcteliumC, plaintext)
		assert.Nil(t, err)

		dec, err := DecryptData(ctx, fakeC.OcteliumC, enc)
		assert.Nil(t, err)
		assert.Equal(t, plaintext, dec)
	}

	{
		plaintext := utilrand.GetRandomBytesMust(64)

		enc1, err := EncryptData(ctx, fakeC.OcteliumC, plaintext)
		assert.Nil(t, err)

		enc2, err := EncryptData(ctx, fakeC.OcteliumC, plaintext)
		assert.Nil(t, err)

		assert.NotEqual(t, enc1.Nonce, enc2.Nonce)
		assert.NotEqual(t, enc1.Ciphertext, enc2.Ciphertext)
	}

	{
		_, err := DecryptData(ctx, fakeC.OcteliumC, nil)
		assert.NotNil(t, err)
	}

	{
		_, err := DecryptData(ctx, fakeC.OcteliumC, &corev1.Authenticator_Status_EncryptedData{})
		assert.NotNil(t, err)
	}

	{
		enc, err := EncryptData(ctx, fakeC.OcteliumC, utilrand.GetRandomBytesMust(64))
		assert.Nil(t, err)

		enc.KeySecretRef = nil
		_, err = DecryptData(ctx, fakeC.OcteliumC, enc)
		assert.NotNil(t, err)
	}

	{
		enc, err := EncryptData(ctx, fakeC.OcteliumC, utilrand.GetRandomBytesMust(64))
		assert.Nil(t, err)

		enc.Ciphertext = nil
		_, err = DecryptData(ctx, fakeC.OcteliumC, enc)
		assert.NotNil(t, err)
	}

	{
		enc, err := EncryptData(ctx, fakeC.OcteliumC, utilrand.GetRandomBytesMust(64))
		assert.Nil(t, err)

		enc.Nonce = nil
		_, err = DecryptData(ctx, fakeC.OcteliumC, enc)
		assert.NotNil(t, err)
	}

	{
		enc, err := EncryptData(ctx, fakeC.OcteliumC, utilrand.GetRandomBytesMust(64))
		assert.Nil(t, err)

		enc.Nonce = utilrand.GetRandomBytesMust(11)
		_, err = DecryptData(ctx, fakeC.OcteliumC, enc)
		assert.NotNil(t, err)
	}

	{
		enc, err := EncryptData(ctx, fakeC.OcteliumC, utilrand.GetRandomBytesMust(64))
		assert.Nil(t, err)

		enc.Ciphertext[0] = enc.Ciphertext[0] ^ 0xff
		_, err = DecryptData(ctx, fakeC.OcteliumC, enc)
		assert.NotNil(t, err)
	}

	{
		enc, err := EncryptData(ctx, fakeC.OcteliumC, utilrand.GetRandomBytesMust(64))
		assert.Nil(t, err)

		enc.Nonce = utilrand.GetRandomBytesMust(12)
		_, err = DecryptData(ctx, fakeC.OcteliumC, enc)
		assert.NotNil(t, err)
	}

	{
		enc, err := EncryptData(ctx, fakeC.OcteliumC, utilrand.GetRandomBytesMust(64))
		assert.Nil(t, err)

		enc.KeySecretRef = &metav1.ObjectReference{
			Name: utilrand.GetRandomStringCanonical(8),
		}
		_, err = DecryptData(ctx, fakeC.OcteliumC, enc)
		assert.NotNil(t, err)
	}
}

func TestErrInvalidAuth(t *testing.T) {

	{
		err := ErrInvalidAuthMsg("something went wrong")
		assert.NotNil(t, err)
		assert.True(t, IsErrInvalidAuth(err))
		assert.Contains(t, err.Error(), "something went wrong")
	}

	{
		err := ErrInvalidAuth(errors.Errorf("inner failure"))
		assert.NotNil(t, err)
		assert.True(t, IsErrInvalidAuth(err))
		assert.Contains(t, err.Error(), "inner failure")
	}

	{
		assert.False(t, IsErrInvalidAuth(nil))
		assert.False(t, IsErrInvalidAuth(errors.Errorf("plain error")))
	}

	{
		wrapped := errors.Wrap(ErrInvalidAuthMsg("inner"), "outer")
		assert.False(t, IsErrInvalidAuth(wrapped))
	}

	{
		err := ErrInvalidAuthMsg("")
		assert.True(t, IsErrInvalidAuth(err))
		assert.NotEqual(t, "", err.Error())
	}
}

func TestGetDisplayName(t *testing.T) {

	newAuthn := func(name, displayName string) *corev1.Authenticator {
		return &corev1.Authenticator{
			Metadata: &metav1.Metadata{
				Name:        name,
				DisplayName: displayName,
			},
			Spec:   &corev1.Authenticator_Spec{},
			Status: &corev1.Authenticator_Status{},
		}
	}

	newUsr := func(email string) *corev1.User {
		return &corev1.User{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.User_Spec{
				Email: email,
			},
		}
	}

	{
		ret := GetDisplayName(newAuthn("authn-1", "My Key"), newUsr("usr@example.com"))
		assert.Equal(t, fmt.Sprintf("%s (%s)", "usr@example.com", "My Key"), ret)
	}

	{
		ret := GetDisplayName(newAuthn("authn-1", "My Key"), newUsr(""))
		assert.Equal(t, "My Key", ret)
	}

	{
		ret := GetDisplayName(newAuthn("authn-1", "My Key"), nil)
		assert.Equal(t, "My Key", ret)
	}

	{
		ret := GetDisplayName(newAuthn("authn-1", ""), newUsr("usr@example.com"))
		assert.Equal(t, "usr@example.com", ret)
	}

	{
		ret := GetDisplayName(newAuthn("authn-1", ""), newUsr(""))
		assert.Equal(t, "authn-1", ret)
	}

	{
		ret := GetDisplayName(newAuthn("authn-1", ""), nil)
		assert.Equal(t, "authn-1", ret)
	}
}
