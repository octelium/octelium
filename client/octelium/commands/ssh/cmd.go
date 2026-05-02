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
	"context"
	"net"
	"os"
	"strconv"
	"strings"

	"al.essio.dev/pkg/shellescape"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
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

	return DoCommand(ctx, &DoCommandOpts{
		Domain:          i.Domain,
		Service:         "essh.octelium",
		SSHUser:         sessionName,
		Command:         remoteCommand,
		NoCommand:       cmdArgs.NoCommand,
		DynamicForwards: cmdArgs.DynamicForwards,
		LocalForwards:   cmdArgs.LocalForwards,
	})
}

type DoCommandOpts struct {
	Domain          string
	SSHUser         string
	LocalForwards   []string
	DynamicForwards []string
	Command         []string
	NoCommand       bool
	Service         string
}

func DoCommand(ctx context.Context, o *DoCommandOpts) error {
	conn, err := client.GetGRPCClientConn(ctx, o.Domain)
	if err != nil {
		return err
	}
	defer conn.Close()

	sessionName := o.SSHUser
	remoteCommand := o.Command

	c := userv1.NewMainServiceClient(conn)

	resp, err := c.GetStatus(ctx, &userv1.GetStatusRequest{})
	if err != nil {
		return err
	}

	if !resp.Session.Status.IsConnected {
		return errors.Errorf(
			`You must be connected to the Cluster. Please use "octelium connect" before running this command.`)
	}

	cfg, err := c.SetServiceConfigs(ctx, &userv1.SetServiceConfigsRequest{
		Name: o.Service,
	})
	if err != nil {
		return err
	}

	hostKeyCallback, err := func() (ssh.HostKeyCallback, error) {
		if len(cfg.Configs) < 1 ||
			cfg.Configs[0].GetSsh() == nil ||
			len(cfg.Configs[0].GetSsh().KnownHosts) == 0 {
			return nil, errors.Errorf("Could not get Service knownHosts")
		}

		f, err := os.CreateTemp("", "known_hosts_*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())

		if _, err := f.WriteString(strings.Join(cfg.Configs[0].GetSsh().KnownHosts, "\n")); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()

		return knownhosts.New(f.Name())
	}()
	if err != nil {
		return err
	}

	sshCfg := &ssh.ClientConfig{
		User:            sessionName,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: hostKeyCallback,
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port)))
	sshClient, err := ssh.Dial(func() string {
		switch cfg.L3Mode {
		case userv1.SetServiceConfigsResponse_V6:
			return "tcp6"
		default:
			return "tcp"
		}
	}(), addr, sshCfg)
	if err != nil {
		return errors.Errorf("Could not connect to session %q at %s: %+v", sessionName, addr, err)
	}
	defer sshClient.Close()

	for _, spec := range o.LocalForwards {
		lf, err := parseForwardSpec(spec)
		if err != nil {
			return errors.Errorf("Invalid -L value %q: %+v", spec, err)
		}
		go runLocalForward(ctx, sshClient, lf)
	}

	for _, spec := range o.DynamicForwards {
		go runDynamicForward(ctx, sshClient, spec)
	}

	if o.NoCommand {
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
