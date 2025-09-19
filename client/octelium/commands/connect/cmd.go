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

package connect

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/octelium/octelium/client/common/authenticator"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/cliutils/vhome"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type args struct {
	L3Mode    string
	IgnoreDNS bool
	Token     string

	ServeServices      []string
	ServeAll           bool
	Detached           bool
	DBHome             string
	PublishServices    []string
	ImplementationMode string

	UseESSH  bool
	ESSHUser string

	Assertion string
	Scopes    []string

	UseLocalDNS        bool
	LocalDNSListenAddr string

	TunnelMode string
}

var example = `
# Connect to a Cluster
octelium connect
# OR via the detached mode in background
octelium connect -d

# Publish/map the Service svc1 to localhost:8080
octelium connect -p svc1:8080

# Publish multiple Services
octelium connect -p svc1:8080 -p svc2:3000 -p svc3:ns1:9090

# Publish the Service svc1 to 0.0.0.0:8080 of the host
octelium connect -p svc1:0.0.0.0:8080


# Serve the Service svc1
octelium connect --serve svc1
# Serve multiple Services
octelium connect --serve svc1 --serve svc2 --serve svc3.ns1
# Serve all available Services for the User
octelium connect --serve-all

# Serve embedded SSH Services
octelium connect --essh

# Connect with an Authentication Token
octelium connect --detach --auth-token <AUTHENTICATION_TOKEN>

# Connect using IPv4 only and skip using the Cluster DNS
octelium connect --ip-mode v4 --no-dns
`

var Cmd = &cobra.Command{
	Use:     "connect",
	Short:   "Connect to a Cluster",
	Example: example,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVar(&cmdArgs.L3Mode, "ip-mode", "",
		"Set the IP/Layer-3 networking mode. `v4` for IPv4-only networking, `v6` for IPv6-only networking, `both` for both modes are valid")
	Cmd.PersistentFlags().BoolVar(&cmdArgs.IgnoreDNS, "no-dns", false, "Skip setting the Cluster private DNS")
	Cmd.PersistentFlags().StringVar(&cmdArgs.Token, "auth-token", "",
		"Connect using an authentication Token without having to be logged in")
	Cmd.PersistentFlags().BoolVar(&cmdArgs.ServeAll, "serve-all", false,
		"Serve all services assigned to the User")
	Cmd.PersistentFlags().StringSliceVar(&cmdArgs.ServeServices, "serve", nil,
		"Select the service names assigned to this user to be served")
	Cmd.PersistentFlags().StringSliceVarP(&cmdArgs.PublishServices, "publish", "p", nil,
		`Publish a Service to a host port. For example you can map the Service "svc1"
in the Namespace "ns1" to the host port "8080" as "svc1.ns1:8080".
For Services in the "default" Namespace you can simply use the format "service:port".
By default the listener host address is set to localhost. But you can explicitly set a specific listener address
in the format "service:host:port" (e.g. "svc1:0.0.0.0:8000", "svc1.ns1:0.0.0.0:8001")`)
	Cmd.PersistentFlags().BoolVarP(&cmdArgs.Detached, "detach", "d", false,
		"Run in the background")

	Cmd.PersistentFlags().BoolVar(&cmdArgs.UseESSH, "essh", false, "Enable serving SSH Services via embedded SSH")
	Cmd.PersistentFlags().StringVar(&cmdArgs.ESSHUser, "essh-user", "", "Force a host user to be used for eSSH sessions. This only works if Octelium is running as root")
	Cmd.PersistentFlags().StringVar(&cmdArgs.ImplementationMode, "implementation", "",
		`Force implementation mode. Current values are "kernel" which is the kernel mode and currently works for WireGuard on Linux,
"tun" which is the TUN device mode and "gvisor" which is a pure userspace implementation. By default, Octelium would try
to find the best mode performance-wise and only resorts to the gvisor implementation if it does not have enough OS permissions.`)

	Cmd.PersistentFlags().StringVar(&cmdArgs.Assertion, "assertion", "", "Authenticate using assertion. Refer to the docs for more details.")

	Cmd.PersistentFlags().StringSliceVar(&cmdArgs.Scopes, "scope", nil,
		`
Scope is a way to limit the access to certain Services and Octelium APIs that works similarly to OAuth2.
This flag is used ONLY while authenticating using the --auth-token or --assertion flags.
You can use this flag also using the login subcommand.
For example, you can only limit the Session to access the Service "svc1.ns1" only using the scope "service:svc1.ns1"
You can also limit yourself to access only Services belonging to the Namespace "ns2" using the scope "service:ns2/*"
You can also use multiple scopes in the same command as follows "--scope service:svc1 --scope service:ns3/*"
`)

	Cmd.PersistentFlags().BoolVar(&cmdArgs.UseLocalDNS, "localdns", false, "Enable local DNS server")
	Cmd.PersistentFlags().StringVar(&cmdArgs.LocalDNSListenAddr, "localdns-addr", "",
		`Local DNS server listen address. By default it is set to "127.0.0.100:53"`)
	Cmd.PersistentFlags().StringVar(&cmdArgs.TunnelMode, "tunnel-mode", "",
		`
	The tunneling mode for the  connection. The current available values are "wg", "wireguard" which use WireGuard (i.e. the default tunneling mode)
	and "quicv0" which uses QUIC. Currently "quicv0" is experimental and not suitable for production environments`)
}

func doCmd(cmd *cobra.Command, args []string) error {
	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	domain := i.Domain

	ctx := context.Background()

	authOpts := &authenticator.AuthenticateOpts{
		Domain:    domain,
		AuthToken: cmdArgs.Token,
		Scopes:    cmdArgs.Scopes,
	}
	if cmdArgs.Assertion != "" {
		authOpts.Assertion = &authenticator.AuthenticateOptsAssertion{
			Arg: cmdArgs.Assertion,
		}
	}

	if err := authenticator.Authenticate(ctx, authOpts); err != nil {
		return err
	}

	if cmdArgs.Detached {
		return runDetached(cmd, domain)
	}

	authenticator.StartGetAccessToken(ctx, domain)

	if err := doConnect(ctx, domain); err != nil {
		return err
	}

	return nil
}

func runDetached(cmd *cobra.Command, domain string) error {

	args := []string{"connect", fmt.Sprintf("--domain=%s", domain)}

	cmd.Flags().VisitAll(func(f *pflag.Flag) {

		if f.Value.Type() == "bool" && f.Value.String() == "false" {
			return
		}
		if f.Value.Type() == "string" && f.Value.String() == "" {
			return
		}
		if f.Value.Type() == "stringSlice" && f.Value.String() == "[]" {
			return
		}
		switch f.Name {
		case "detach", "homedir", "domain":
			return
		}

		args = append(args, fmt.Sprintf("--%s=%s", f.Name, f.Value.String()))
	})

	if cmd.Flags() != nil && cmd.Flags().Lookup("homedir") != nil && cmd.Flags().Lookup("homedir").Value.String() != "" {
		args = append(args, "--homedir", cmd.Flags().Lookup("homedir").Value.String())
	} else {
		vHome, err := vhome.GetOcteliumHome()
		if err != nil {
			return err
		}
		args = append(args, "--homedir", vHome)
	}

	if err := doRunDetached(args); err != nil {
		return err
	}

	cliutils.LineNotify("Octelium has started running in detached mode.\n")

	return nil
}

func getDetachedModeEnvVars() map[string]string {
	ret := make(map[string]string)

	env := os.Environ()

	for _, envVar := range env {
		if !strings.HasPrefix(envVar, "OCTELIUM_") {
			continue
		}

		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 2 {
			ret[parts[0]] = parts[1]
		}
	}

	return ret
}
