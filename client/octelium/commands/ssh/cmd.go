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

package ssh

import (
	"net"
	"os"

	"al.essio.dev/pkg/shellescape"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type args struct {
	LocalForwards   []string
	DynamicForwards []string
	NoCommand       bool
}

var cmdArgs args

func init() {
	Cmd.Flags().StringArrayVarP(&cmdArgs.LocalForwards, "local", "L", nil,
		"Local port forward: [bind_addr:]port:host:hostport")
	Cmd.Flags().StringArrayVarP(&cmdArgs.DynamicForwards, "dynamic", "D", nil,
		"Dynamic (SOCKS5) forward: [bind_addr:]port")
	Cmd.Flags().BoolVarP(&cmdArgs.NoCommand, "no-command", "N", false,
		"Do not execute a remote command (useful for port forwarding only)")
}

var Cmd = &cobra.Command{
	Use:   "ssh <session-name> [-- command [args...]]",
	Short: "Open an SSH session to a connected Octelium session",
	Long: `Open an interactive SSH session or execute a remote command on a connected
Octelium Session using its name.

A remote command and its arguments can be passed after a double-dash (--).
If no command is given, an interactive shell is opened.`,
	Example: `
  # Open an interactive shell
  octelium ssh john-abcdef

  # Run a single remote command
  octelium ssh john-abcdef -- uptime

  # Run a shell pipeline
  octelium ssh john-abcdef -- sh -c "ps aux | grep python"

  # Local port forward: forward local :5432 to remote localhost:5432
  octelium ssh john-abcdef -L 5432:localhost:5432

  # Multiple port forwards, no interactive shell
  octelium ssh john-abcdef -N \
    -L 5432:localhost:5432 \
    -L 6379:localhost:6379

  # Dynamic SOCKS5 proxy on local port 1080
  octelium ssh john-abcdef -D 1080 -N`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
	Args: cobra.MinimumNArgs(1),
}

func doCmd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	sessionName := args[0]

	var remoteCommand []string
	if len(args) > 1 {
		remoteCommand = args[1:]
	}

	{
		conn, err := client.GetGRPCClientConn(ctx, i.Domain)
		if err != nil {
			return err
		}
		defer conn.Close()

		c := userv1.NewMainServiceClient(conn)

		resp, err := c.GetStatus(ctx, &userv1.GetStatusRequest{})
		if err != nil {
			return err
		}

		if !resp.Session.Status.IsConnected {
			return errors.Errorf(
				`You must be connected to the Cluster. Please use "octelium connect" before running this command.`)
		}
	}

	sshCfg := &ssh.ClientConfig{
		User:            sessionName,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := net.JoinHostPort("essh.octelium", "22")
	sshClient, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return errors.Errorf("Could not connect to session %q at %s: %+v", sessionName, addr, err)
	}
	defer sshClient.Close()

	for _, spec := range cmdArgs.LocalForwards {
		lf, err := parseForwardSpec(spec)
		if err != nil {
			return errors.Errorf("Invalid -L value %q: %+v", spec, err)
		}
		go runLocalForward(ctx, sshClient, lf)
	}

	for _, spec := range cmdArgs.DynamicForwards {
		go runDynamicForward(ctx, sshClient, spec)
	}

	if cmdArgs.NoCommand {
		<-ctx.Done()
		return nil
	}

	sess, err := sshClient.NewSession()
	if err != nil {
		return errors.Errorf("Could not open SSH session: %+v", err)
	}
	defer sess.Close()

	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr
	sess.Stdin = os.Stdin

	if len(remoteCommand) > 0 {
		if err := sess.Start(shellescape.QuoteCommand(remoteCommand)); err != nil {
			return errors.Errorf("Could not start remote command: %+v", err)
		}
		return sess.Wait()
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		if err := sess.Shell(); err != nil {
			return errors.Errorf("Could not start remote shell: %+v", err)
		}
		return sess.Wait()
	}

	w, h, err := term.GetSize(fd)
	if err != nil {
		w, h = 80, 24
	}

	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := sess.RequestPty(termType, h, w, modes); err != nil {
		return errors.Errorf("Could not request PTY: %+v", err)
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return errors.Errorf("Could not set terminal to raw mode: %+v", err)
	}
	defer term.Restore(fd, oldState)

	if err := sess.Shell(); err != nil {
		return errors.Errorf("Could not start remote shell: %+v", err)
	}

	go watchResize(ctx, fd, sess)

	return sess.Wait()
}
