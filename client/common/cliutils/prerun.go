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

package cliutils

import (
	"context"
	"os"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils/vhome"
	"github.com/octelium/octelium/client/common/components"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func PreRun(cmd *cobra.Command, args []string) error {

	if err := components.InitComponent(); err != nil {
		return err
	}

	cmd.SetContext(context.Background())

	if cmd.Flags() != nil && cmd.Flags().Lookup("homedir") != nil && cmd.Flags().Lookup("homedir").Value.String() != "" {
		if err := OpenDB(cmd.Flags().Lookup("homedir").Value.String()); err != nil {
			return err
		}
	} else {

		octeliumHome, err := vhome.GetOcteliumHome()
		if err != nil {
			return err
		}

		if err := OpenDB(octeliumHome); err != nil {
			return err
		}

	}

	if err := dbC.Migrate(); err != nil {
		return err
	}

	return nil
}

func PostRun(cmd *cobra.Command, args []string) error {

	if os.Getenv("OCTELIUM_LOGOUT") == "true" ||
		(cmd.Flags() != nil && cmd.Flags().Lookup("logout") != nil && cmd.Flags().Lookup("logout").Value.String() == "true") {
		zap.L().Debug("Starting a post run logout")
		i, err := GetCLIInfo(cmd, args)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		c, err := NewAuthClient(ctx, i.Domain, nil)
		if err != nil {
			return err
		}

		if _, err := c.C().Logout(ctx, &authv1.LogoutRequest{}); err != nil {
			return err
		}

		LineInfo("You are now logged out.\n")
	}

	if err := CloseDB(); err != nil {
		return err
	}

	return nil
}
