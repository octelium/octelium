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

package utils

import (
	"crypto/subtle"
	"os"
	"time"
)

func SecureBytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func SecureStringEqual(a, b string) bool {
	return SecureBytesEqual([]byte(a), []byte(b))
}

func MustParseTime(arg string) time.Time {
	ret, _ := time.Parse(time.RFC3339Nano, arg)
	return ret
}

func IsInsecureTLS() bool {
	return os.Getenv("OCTELIUM_INSECURE_TLS") == "true"
}
