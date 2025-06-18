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

	"github.com/manifoldco/promptui"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/pkg/errors"
)

func totpRegister(ctx context.Context, reqi *authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest) (*authv1.ChallengeResponse, error) {

	return nil, errors.Errorf("Cannot Register TOTP Authenticators via the CLI")
}

func totpAuthenticate(ctx context.Context, reqi *authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest) (*authv1.ChallengeResponse, error) {
	return totpGetResponse()
}

func totpGetResponse() (*authv1.ChallengeResponse, error) {
	prompt := promptui.Prompt{
		Label: "Enter the OTP",
	}

	res, err := prompt.Run()
	if err != nil {
		return nil, err
	}

	ret := &authv1.ChallengeResponse{
		Type: &authv1.ChallengeResponse_Totp{
			Totp: &authv1.ChallengeResponse_TOTP{
				Response: res,
			},
		},
	}

	return ret, nil

}
