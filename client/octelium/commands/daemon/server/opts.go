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

package server

import (
	"fmt"
	"net"
	"strconv"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octelium/commands/connect"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	rootPrincipalID    = "0"
	privilegedPortEdge = 1024
	defaultDNSPort     = 53
	minMTU             = 576
	maxMTU             = 1500
)

func getConnectOpts(o *daemonv1.ConnectionOptions, p *principal) (*connect.Opts, error) {
	if o == nil {
		o = &daemonv1.ConnectionOptions{}
	}

	if err := validateConnectionOptions(o); err != nil {
		return nil, err
	}

	svcOpts := o.GetServiceOptions()

	if svcOpts.GetServeAll() && len(svcOpts.GetServe()) > 0 {
		return nil, status.Error(codes.InvalidArgument,
			"serveAll and serve are mutually exclusive")
	}

	ret := &connect.Opts{
		ServeAll:           svcOpts.GetServeAll(),
		UseESSH:            svcOpts.GetEnableEmbeddedSSH(),
		ESSHUser:           p.name,
		UseESOCKS5:         svcOpts.GetEnableEmbeddedSOCKS5(),
		UseLocalDNS:        o.GetDns().GetEnableLocalServer(),
		LocalDNSListenAddr: o.GetDns().GetLocalServerListenAddress(),
		UserHome:           p.homeDir,
		MTU:                o.GetMtu(),
	}

	if ret.UseESSH && ret.ESSHUser == "" {
		return nil, status.Error(codes.FailedPrecondition,
			"The OS user of the owner of the daemon could not be resolved")
	}

	switch o.L3Mode {
	case daemonv1.ConnectionOptions_V4:
		ret.L3Mode = "v4"
	case daemonv1.ConnectionOptions_V6:
		ret.L3Mode = "v6"
	case daemonv1.ConnectionOptions_BOTH:
		ret.L3Mode = "both"
	}

	switch o.TunnelMode {
	case daemonv1.ConnectionOptions_WIREGUARD:
		ret.TunnelMode = "wg"
	case daemonv1.ConnectionOptions_QUICV0:
		ret.TunnelMode = "quicv0"
	}

	switch o.ImplementationMode {
	case daemonv1.ConnectionOptions_KERNEL:
		ret.ImplementationMode = "kernel"
	case daemonv1.ConnectionOptions_TUN:
		ret.ImplementationMode = "tun"
	case daemonv1.ConnectionOptions_GVISOR:
		ret.ImplementationMode = "gvisor"
	}

	switch o.GetDns().GetMode() {
	case daemonv1.ConnectionOptions_DNS_DISABLED:
		ret.IgnoreDNS = true
	case daemonv1.ConnectionOptions_DNS_FULL:
		ret.UseFullDNS = true
	}

	if ret.LocalDNSListenAddr != "" {
		addr, err := getLocalDNSListenAddr(ret.LocalDNSListenAddr, p.id)
		if err != nil {
			return nil, err
		}
		ret.LocalDNSListenAddr = addr
	}

	for _, svc := range svcOpts.GetServe() {
		name, err := getServiceName(svc)
		if err != nil {
			return nil, err
		}
		ret.ServeServices = append(ret.ServeServices, name)
	}

	for _, svc := range svcOpts.GetPublish() {
		name, err := getServiceName(svc.GetService())
		if err != nil {
			return nil, err
		}

		if svc.Port < 1 || svc.Port > 65535 {
			return nil, status.Errorf(codes.InvalidArgument,
				"Invalid published Service port: %d", svc.Port)
		}

		if svc.Port < privilegedPortEdge && p.id != rootPrincipalID {
			return nil, status.Errorf(codes.PermissionDenied,
				"You are not allowed to publish a Service at the privileged port %d", svc.Port)
		}

		addr := svc.Address
		switch addr {
		case "", "localhost":
			addr = "localhost"
		default:
			if !govalidator.IsIP(addr) {
				return nil, status.Errorf(codes.InvalidArgument,
					"Invalid published Service address: %s", addr)
			}
		}

		ret.PublishServices = append(ret.PublishServices, &connect.PublishedService{
			Name:    name,
			Address: addr,
			Port:    int(svc.Port),
		})
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

	if _, ok := daemonv1.ConnectionOptions_ImplementationMode_name[int32(o.ImplementationMode)]; !ok {
		return status.Errorf(codes.InvalidArgument,
			"Unsupported implementationMode: %d", o.ImplementationMode)
	}

	if o.GetDns() != nil {
		if _, ok := daemonv1.ConnectionOptions_DNS_Mode_name[int32(o.GetDns().GetMode())]; !ok {
			return status.Errorf(codes.InvalidArgument,
				"Unsupported DNS mode: %d", o.GetDns().GetMode())
		}
	}

	if o.Mtu != 0 && (o.Mtu < minMTU || o.Mtu > maxMTU) {
		return status.Errorf(codes.InvalidArgument,
			"The MTU must be between %d and %d", minMTU, maxMTU)
	}

	return nil
}

func getServiceName(svc *daemonv1.ConnectionOptions_ServiceReference) (string, error) {
	if svc.GetName() == "" {
		return "", status.Error(codes.InvalidArgument, "The Service name is not set")
	}

	name := svc.GetName()
	if svc.GetNamespace() != "" {
		name = fmt.Sprintf("%s.%s", svc.GetName(), svc.GetNamespace())
	}

	if _, err := cliutils.ParseServiceNamespace(name); err != nil {
		return "", status.Error(codes.InvalidArgument, err.Error())
	}

	return name, nil
}

func getLocalDNSListenAddr(arg, principalID string) (string, error) {
	if govalidator.IsIP(arg) {
		return net.JoinHostPort(arg, strconv.Itoa(defaultDNSPort)), nil
	}

	host, portStr, err := net.SplitHostPort(arg)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument,
			"Invalid local DNS server listen address: %s", arg)
	}

	if host != "" && host != "localhost" && !govalidator.IsIP(host) {
		return "", status.Errorf(codes.InvalidArgument,
			"Invalid local DNS server listen address: %s", arg)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", status.Errorf(codes.InvalidArgument,
			"Invalid local DNS server listen port: %s", portStr)
	}

	if port != defaultDNSPort && port < privilegedPortEdge && principalID != rootPrincipalID {
		return "", status.Errorf(codes.PermissionDenied,
			"You are not allowed to run the local DNS server at the privileged port %d", port)
	}

	return arg, nil
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

	if ret.Dns.Mode == daemonv1.ConnectionOptions_DNS_FULL {
		ret.Dns.EnableLocalServer = true
	}

	return ret
}

func setConnectionStatusFromConnection(st *daemonv1.ConnectionStatus, connCfg *cliconfigv1.Connection) {
	if connCfg == nil {
		return
	}

	prefs := connCfg.GetPreferences()

	st.DeviceName = prefs.GetDeviceName()
	st.Mtu = prefs.GetMtu()
	st.Addresses = connCfg.GetConnection().GetAddresses()

	switch prefs.GetConnectionType() {
	case cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0:
		st.TunnelMode = daemonv1.ConnectionOptions_QUICV0
	default:
		st.TunnelMode = daemonv1.ConnectionOptions_WIREGUARD
	}

	if prefs.GetLinuxPrefs() != nil {
		switch prefs.GetLinuxPrefs().GetImplementationMode() {
		case cliconfigv1.Connection_Preferences_Linux_WG_KERNEL:
			st.ImplementationMode = daemonv1.ConnectionOptions_KERNEL
		case cliconfigv1.Connection_Preferences_Linux_WG_USERSPACE:
			st.ImplementationMode = daemonv1.ConnectionOptions_TUN
		case cliconfigv1.Connection_Preferences_Linux_WG_NETSTACK:
			st.ImplementationMode = daemonv1.ConnectionOptions_GVISOR
		}
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
		IsConfigured:             !prefs.GetIgnoreDNS(),
		Servers:                  connCfg.GetConnection().GetDns().GetServers(),
		LocalServerListenAddress: prefs.GetLocalDNS().GetListenAddress(),
	}
}
