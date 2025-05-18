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

package utilrand

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
)

func GetRandomString(n int) string {
	return newString(n)
}

func GetRandomStringLowercase(n int) string {
	return newStringChars(n, lowerCaseChars)
}

func GetRandomStringHex(n int) string {
	return newStringChars(n, hexChars)
}

func GetRandomStringAlphabetLC(n int) string {
	return newStringChars(n, lowerCaseAlphabetChars)
}

func GetRandomStringCanonical(n int) string {
	if n < 1 {
		return ""
	}
	if n == 1 {
		return GetRandomStringAlphabetLC(1)
	}

	return fmt.Sprintf("%s%s",
		GetRandomStringAlphabetLC(1),
		GetRandomStringLowercase(n-1),
	)
}

func GetRandomIPIndex() (uint32, error) {

	doGet := func() (uint32, error) {
		nBig, err := rand.Int(rand.Reader, big.NewInt(65535))
		if err != nil {
			return 0, err
		}

		return uint32(nBig.Int64()), nil
	}

	for i := 0; i < 100000; i++ {
		ret, err := doGet()
		if err != nil {
			return 0, err
		}
		if ret == 0 || ret%256 == 0 {
			continue
		}

		return ret, nil
	}

	return 0, errors.Errorf("Could not generate a random number")
}

func GetRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func GetRandomBytesMust(n int) []byte {
	ret, err := GetRandomBytes(n)
	if err != nil {
		panic(err)
	}
	return ret
}

func GetRandomRangeMath(min, max int) int {
	if max <= min {
		return 0
	}

	ret, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))

	return int(ret.Int64()) + min
}
