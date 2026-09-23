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

package liboctelium

import (
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/client/octelium/commands/connect"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"golang.org/x/net/idna"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	minMTU = 576
	maxMTU = 1500
)

func getConnectOpts(o *daemonv1.ConnectionOptions) (*connect.Opts, error) {
	if o == nil {
		o = &daemonv1.ConnectionOptions{}
	}

	if err := validateConnectionOptions(o); err != nil {
		return nil, err
	}

	ret := &connect.Opts{
		L3Mode: "v6",
		MTU:    o.GetMtu(),
	}

	switch o.L3Mode {
	case daemonv1.ConnectionOptions_V4:
		ret.L3Mode = "v4"
	case daemonv1.ConnectionOptions_BOTH:
		ret.L3Mode = "both"
	}

	switch o.TunnelMode {
	case daemonv1.ConnectionOptions_WIREGUARD:
		ret.TunnelMode = "wg"
	case daemonv1.ConnectionOptions_QUICV0:
		ret.TunnelMode = "quicv0"
	}

	switch o.GetDns().GetMode() {
	case daemonv1.ConnectionOptions_DNS_DISABLED:
		ret.IgnoreDNS = true
	case daemonv1.ConnectionOptions_DNS_FULL:
		ret.UseFullDNS = true
	}

	return ret, nil
}

func validateConnectionOptions(o *daemonv1.ConnectionOptions) error {
	if _, ok := daemonv1.ConnectionOptions_L3Mode_name[int32(o.L3Mode)]; !ok {
		return status.Errorf(codes.InvalidArgument, "Unsupported l3Mode: %d", o.L3Mode)
	}

	if _, ok := daemonv1.ConnectionOptions_TunnelMode_name[int32(o.TunnelMode)]; !ok {
		return status.Errorf(codes.InvalidArgument, "Unsupported tunnelMode: %d", o.TunnelMode)
	}

	switch o.ImplementationMode {
	case daemonv1.ConnectionOptions_IMPLEMENTATION_MODE_UNSPECIFIED, daemonv1.ConnectionOptions_TUN:
	default:
		return status.Errorf(codes.InvalidArgument,
			"Unsupported implementationMode on this platform: %d", o.ImplementationMode)
	}

	if o.GetDns() != nil {
		if _, ok := daemonv1.ConnectionOptions_DNS_Mode_name[int32(o.GetDns().GetMode())]; !ok {
			return status.Errorf(codes.InvalidArgument,
				"Unsupported DNS mode: %d", o.GetDns().GetMode())
		}

		if o.GetDns().GetEnableLocalServer() || o.GetDns().GetLocalServerListenAddress() != "" {
			return status.Errorf(codes.InvalidArgument,
				"The local DNS server is not supported on this platform")
		}
	}

	if svcOpts := o.GetServiceOptions(); svcOpts.GetServeAll() ||
		len(svcOpts.GetServe()) > 0 ||
		len(svcOpts.GetPublish()) > 0 ||
		svcOpts.GetEnableEmbeddedSSH() ||
		svcOpts.GetEnableEmbeddedSOCKS5() {
		return status.Errorf(codes.InvalidArgument,
			"Serving and publishing Services are not supported on this platform")
	}

	if o.Mtu != 0 && (o.Mtu < minMTU || o.Mtu > maxMTU) {
		return status.Errorf(codes.InvalidArgument,
			"The MTU must be between %d and %d", minMTU, maxMTU)
	}

	return nil
}

func normalizeConnectionOptions(o *daemonv1.ConnectionOptions) *daemonv1.ConnectionOptions {
	ret := &daemonv1.ConnectionOptions{}
	if o != nil {
		ret = pbutils.Clone(o).(*daemonv1.ConnectionOptions)
	}

	if ret.Dns == nil {
		ret.Dns = &daemonv1.ConnectionOptions_DNS{}
	}

	if ret.Dns.Mode == daemonv1.ConnectionOptions_DNS_MODE_UNSPECIFIED {
		ret.Dns.Mode = daemonv1.ConnectionOptions_DNS_DEFAULT
	}

	return ret
}

func setConnectionStatusFromConnection(st *daemonv1.ConnectionStatus, connCfg *cliconfigv1.Connection) {
	if connCfg == nil {
		return
	}

	prefs := connCfg.GetPreferences()

	st.Mtu = prefs.GetMtu()
	st.Addresses = connCfg.GetConnection().GetAddresses()
	st.ImplementationMode = daemonv1.ConnectionOptions_TUN

	switch prefs.GetConnectionType() {
	case cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0:
		st.TunnelMode = daemonv1.ConnectionOptions_QUICV0
	default:
		st.TunnelMode = daemonv1.ConnectionOptions_WIREGUARD
	}

	st.Dns = &daemonv1.ConnectionStatus_DNS{
		Mode: func() daemonv1.ConnectionOptions_DNS_Mode {
			switch {
			case prefs.GetIgnoreDNS():
				return daemonv1.ConnectionOptions_DNS_DISABLED
			case prefs.GetFullDNS():
				return daemonv1.ConnectionOptions_DNS_FULL
			default:
				return daemonv1.ConnectionOptions_DNS_DEFAULT
			}
		}(),
		IsConfigured: !prefs.GetIgnoreDNS() && len(connCfg.GetConnection().GetDns().GetServers()) > 0,
		Servers:      connCfg.GetConnection().GetDns().GetServers(),
	}
}

func canonicalizeDomain(domain string) (string, error) {
	invalidErr := status.Errorf(codes.InvalidArgument, "Invalid Cluster domain: %s", domain)

	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", status.Error(codes.InvalidArgument, "The Cluster domain is not set")
	}

	domain = strings.TrimSuffix(domain, ".")

	ret, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", invalidErr
	}

	ret = strings.ToLower(ret)

	if len(ret) > 253 || !strings.Contains(ret, ".") ||
		govalidator.IsIP(ret) || !govalidator.IsDNSName(ret) {
		return "", invalidErr
	}

	return ret, nil
}
