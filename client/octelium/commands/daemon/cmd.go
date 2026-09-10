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

package daemon

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/octelium/octelium/client/octelium/commands/daemon/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type args struct {
	ListenAddress string
	StateDir      string
}

var cmdArgs args

var example = `
# Run the Octelium daemon. It is normally run as an OS service as opposed to
# being run manually.
octelium daemon

# Run the daemon at a specific local API address and state directory
octelium daemon --listen /var/run/octelium/daemon.sock --state-dir /var/lib/octelium
`

var Cmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run the Octelium client daemon",
	Long: `Run the privileged Octelium client daemon which owns the authentication
credentials, the Connections and the host networking configuration of all the
local OS principals and which serves the local client API to the local frontends
such as the Octelium CLI itself and the Octelium desktop application.`,
	Example: example,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

func init() {
	Cmd.PersistentFlags().StringVar(&cmdArgs.ListenAddress, "listen", "",
		`The address of the local API. This is the path of the Unix domain socket on
Linux and macOS and the name of the named pipe on Windows. By default the daemon
uses the standard address of the platform.`)
	Cmd.PersistentFlags().StringVar(&cmdArgs.StateDir, "state-dir", "",
		`The root directory of the daemon-owned state. The credentials and the settings
of every OS principal are stored in a separate sub-directory of it that is only
accessible by the daemon itself. By default the daemon uses the standard
directory of the platform.`)
}

func doCmd(cmd *cobra.Command, args []string) error {
	ctx, cancelFn := context.WithCancel(cmd.Context())
	defer cancelFn()

	srv, err := server.New(&server.Opts{
		ListenAddress: cmdArgs.ListenAddress,
		StateDir:      cmdArgs.StateDir,
	})
	if err != nil {
		return err
	}

	if err := srv.Run(ctx); err != nil {
		return err
	}

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalCh)

	select {
	case <-signalCh:
		zap.L().Debug("Received shutdown signal")
	case <-ctx.Done():
	}

	return srv.Close()
}
