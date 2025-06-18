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

package authcommon

import (
	"context"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/pkg/errors"
)

func Authenticate(ctx context.Context, req *authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest) (*authv1.ChallengeResponse, error) {
	switch req.Type.(type) {

	case *authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_Totp:
		return totpAuthenticate(ctx, req)
	case *authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_Tpm:
		return tpmAuthenticate(ctx, req)
	default:
		return nil, errors.Errorf("Unknown authenticator challenge request type")
	}
}

func Register(ctx context.Context, req *authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest) (*authv1.ChallengeResponse, error) {
	switch req.Type.(type) {
	case *authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_Totp:
		return totpRegister(ctx, req)
	case *authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_Tpm:
		return tpmRegister(ctx, req)
	default:
		return nil, errors.Errorf("Unknown authenticator challenge request type")
	}
}

func GetPreChallenge(ctx context.Context, authn *authv1.Authenticator) (*authv1.RegisterAuthenticatorBeginRequest_PreChallenge, error) {
	switch authn.Status.Type {
	case authv1.Authenticator_Status_TPM:
		return tpmGetPreChallenge(ctx)
	default:
		return nil, nil
	}
}
