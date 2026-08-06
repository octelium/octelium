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
	"crypto/rand"
	"crypto/sha256"

	"github.com/octelium/octelium/pkg/utils"
	"github.com/pkg/errors"
)

const (
	VerifierLen  = 32
	ChallengeLen = sha256.Size
)

func NewVerifier() ([]byte, error) {
	ret := make([]byte, VerifierLen)
	if _, err := rand.Read(ret); err != nil {
		return nil, errors.Errorf("Could not generate a code verifier: %+v", err)
	}

	return ret, nil
}

func GetChallenge(verifier []byte) []byte {
	ret := sha256.Sum256(verifier)
	return ret[:]
}

func Verify(challenge, verifier []byte) bool {
	if len(challenge) != ChallengeLen || len(verifier) != VerifierLen {
		return false
	}

	return utils.SecureBytesEqual(challenge, GetChallenge(verifier))
}
