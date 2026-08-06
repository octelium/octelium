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

package opkce

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewVerifier(t *testing.T) {

	verifier, err := NewVerifier()
	assert.Nil(t, err)
	assert.Equal(t, VerifierLen, len(verifier))

	other, err := NewVerifier()
	assert.Nil(t, err)
	assert.NotEqual(t, verifier, other)
}

func TestGetChallenge(t *testing.T) {

	verifier, err := NewVerifier()
	assert.Nil(t, err)

	challenge := GetChallenge(verifier)
	assert.Equal(t, ChallengeLen, len(challenge))

	sum := sha256.Sum256(verifier)
	assert.Equal(t, sum[:], challenge)

	assert.Equal(t, challenge, GetChallenge(verifier))
}

func TestVerify(t *testing.T) {

	verifier, err := NewVerifier()
	assert.Nil(t, err)

	challenge := GetChallenge(verifier)

	assert.True(t, Verify(challenge, verifier))

	{
		other, err := NewVerifier()
		assert.Nil(t, err)
		assert.False(t, Verify(challenge, other))
	}

	{
		assert.False(t, Verify(nil, verifier))
		assert.False(t, Verify(challenge, nil))
		assert.False(t, Verify(nil, nil))
	}

	{
		assert.False(t, Verify(challenge[:ChallengeLen-1], verifier))
		assert.False(t, Verify(challenge, verifier[:VerifierLen-1]))
		assert.False(t, Verify(challenge, append(verifier, 0x0)))
	}

	{
		flipped := make([]byte, VerifierLen)
		copy(flipped, verifier)
		flipped[0] = flipped[0] ^ 0x1
		assert.False(t, Verify(challenge, flipped))
	}
}
