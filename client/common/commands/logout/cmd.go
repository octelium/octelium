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

package logout

import (
	"context"
	"os"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var Cmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out from a Cluster",
	Example: `
octeliumctl logout
	`,

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if os.Getenv("OCTELIUM_AUTH_PROXY_SOCKET") != "" {
			return errors.Errorf("Cannot use logout command in proxy mode")
		}
		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

func init() {
	cobra.EnableTraverseRunHooks = true
}

func doCmd(cmd *cobra.Command, args []string) error {

	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Second)
	defer cancel()

	c, err := cliutils.NewAuthClient(ctx, i.Domain, nil)
	if err != nil {
		return err
	}

	defer func() {
		if err := cliutils.GetDB().Delete(i.Domain); err != nil {
			if !cliutils.GetDB().ErrorIsNotFound(err) {
				zap.L().Debug("Could not delete db state", zap.Error(err))
			}
		}
	}()

	if _, err := c.C().Logout(ctx, &authv1.LogoutRequest{}); err != nil {
		zap.L().Warn("Could not call logout", zap.Error(err))
	}

	cliutils.LineInfo("You are now logged out.\n")

	return nil
}
