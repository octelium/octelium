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

//go:build !linux && !windows

package authcommon

import (
	"context"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/pkg/errors"
)

func tpmAuthenticate(ctx context.Context, req *authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest) (*authv1.ChallengeResponse, error) {

	return nil, errors.Errorf("TPM Authenticator is not supported on this platform")
}

func tpmRegister(ctx context.Context, req *authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest) (*authv1.ChallengeResponse, error) {
	return nil, errors.Errorf("TPM Authenticator is not supported on this platform")
}

func tpmGetPreChallenge(ctx context.Context) (*authv1.RegisterAuthenticatorBeginRequest_PreChallenge, error) {
	return nil, nil
}
