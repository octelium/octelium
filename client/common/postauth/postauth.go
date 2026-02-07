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

package postauth

import (
	"context"
	"fmt"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/commands/auth/authenticator"
	"github.com/octelium/octelium/client/common/commands/auth/device/register"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"go.uber.org/zap"
)

type DoPostAuthReq struct {
	Domain              string
	DoNotRegisterDevice bool
}
type DoPostAuthResp struct {
	Status *userv1.GetStatusResponse
}

func DoPostAuth(ctx context.Context, r *DoPostAuthReq) (*DoPostAuthResp, error) {

	ret := &DoPostAuthResp{}

	if ldflags.IsProduction() {
		return ret, nil
	}

	conn, err := client.GetGRPCClientConn(ctx, r.Domain)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := userv1.NewMainServiceClient(conn)

	st, err := client.GetStatus(ctx, &userv1.GetStatusRequest{})
	if err != nil {
		return nil, err
	}
	ret.Status = st

	{
		arg := st.User.Metadata.Name
		if st.User.Metadata.DisplayName != "" {
			arg = fmt.Sprintf("%s (%s)", arg, st.User.Metadata.DisplayName)
		}

		cliutils.LineInfo("You are now authenticated as %s\n", arg)
	}

	if !r.DoNotRegisterDevice &&
		st.User.Spec != nil &&
		st.User.Spec.Type == userv1.GetStatusResponse_User_Spec_HUMAN {
		if err := register.DoRegister(ctx, r.Domain); err != nil {
			zap.L().Debug("Could not register Device", zap.Error(err))
		}

		authC, err := cliutils.NewAuthClient(ctx, r.Domain, nil)
		if err != nil {
			return nil, err
		}
		defer authC.Close()

		if resp, err := authC.C().GetAvailableAuthenticator(ctx,
			&authv1.GetAvailableAuthenticatorRequest{}); err == nil {
			if resp.MainAuthenticator != nil {
				zap.L().Debug("Found main Authenticator", zap.Any("authn", resp.MainAuthenticator))
				if err := authenticator.DoAuthenticate(ctx,
					r.Domain, authC, umetav1.GetObjectReference(resp.MainAuthenticator)); err != nil {
					return nil, err
				}
			}
		}
	}

	return ret, nil
}
