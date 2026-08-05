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

package octelium

import (
	"fmt"
	"os"
)

type environmentIdentity struct {
	authenticator Authenticator
	provider      AccessTokenProvider
}

func identityFromEnvironment() (*environmentIdentity, error) {
	if token := os.Getenv("OCTELIUM_ACCESS_TOKEN"); token != "" {
		return &environmentIdentity{provider: StaticAccessToken(token)}, nil
	}

	if path := os.Getenv("OCTELIUM_ASSERTION_FILE"); path != "" {
		return &environmentIdentity{authenticator: AssertionFromFile(path)}, nil
	}

	if assertion := os.Getenv("OCTELIUM_ASSERTION"); assertion != "" {
		return &environmentIdentity{authenticator: StaticAssertion(assertion)}, nil
	}

	if token := os.Getenv("OCTELIUM_AUTH_TOKEN"); token != "" {
		return &environmentIdentity{authenticator: AuthenticationToken(token)}, nil
	}

	return nil, fmt.Errorf(
		"%w: use WithAuthenticator, WithAccessTokenProvider, OCTELIUM_ACCESS_TOKEN, OCTELIUM_ASSERTION_FILE, OCTELIUM_ASSERTION or OCTELIUM_AUTH_TOKEN",
		ErrNoCredentials,
	)
}
