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
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octelium/commands/connect/controller"
	"github.com/octelium/octelium/client/octelium/commands/connect/l3mode"
	"github.com/octelium/octelium/client/octelium/commands/connect/pprofsrv"
	"github.com/octelium/octelium/client/octelium/commands/connect/proxy"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const defaultESSHPort = 22022

func sendInitializeRequest(streamC userv1.MainService_ConnectClient,
	publishedServices []*cliconfigv1.Connection_Preferences_PublishedService) error {

	l3Mode, err := l3mode.GetL3Mode(cmdArgs.L3Mode)
	if err != nil {
		return err
	}

	var servedServices []*userv1.ConnectRequest_Initialize_ServiceOptions_Service
	for _, svcStr := range cmdArgs.ServeServices {
		_, err := cliutils.ParseServiceNamespace(svcStr)
		if err != nil {
			return err
		}

		servedServices = append(servedServices, &userv1.ConnectRequest_Initialize_ServiceOptions_Service{
			Name: cliutils.GetServiceFullNameFromName(svcStr),
		})
	}

	req := &userv1.ConnectRequest{
		Type: &userv1.ConnectRequest_Initialize_{
			Initialize: &userv1.ConnectRequest_Initialize{
				ConnectionType: func() userv1.ConnectRequest_Initialize_ConnectionType {
					if cmdArgs.TunnelMode == "quicv0" || os.Getenv("OCTELIUM_QUIC") == "true" {
						return userv1.ConnectRequest_Initialize_QUICV0
					}
					return userv1.ConnectRequest_Initialize_UNSET
				}(),
				L3Mode: l3Mode,
				PublishedServices: func() []*userv1.ConnectRequest_Initialize_PublishedService {
					var ret []*userv1.ConnectRequest_Initialize_PublishedService
					for _, svc := range publishedServices {
						ret = append(ret, &userv1.ConnectRequest_Initialize_PublishedService{
							Name:    svc.Name,
							Port:    uint32(svc.HostPort),
							Address: svc.HostAddress,
						})
					}
					return ret
				}(),

				IgnoreDNS: cmdArgs.IgnoreDNS,

				ServiceOptions: func() *userv1.ConnectRequest_Initialize_ServiceOptions {
					if cmdArgs.ServeAll {
						return &userv1.ConnectRequest_Initialize_ServiceOptions{
							ServeAll:  true,
							PortStart: int32(utilrand.GetRandomRangeMath(20000, 24000)),
						}
					}

					if len(cmdArgs.ServeServices) > 0 {
						return &userv1.ConnectRequest_Initialize_ServiceOptions{
							Services:  servedServices,
							PortStart: int32(utilrand.GetRandomRangeMath(20000, 24000)),
						}
					}

					return nil
				}(),
				ESSHEnable: cmdArgs.UseESSH || os.Getenv("OCTELIUM_ESSH") == "true",
				ESSHPort: func() int32 {
					if port, err := strconv.ParseInt(os.Getenv("OCTELIUM_ESSH_PORT"), 10, 32); err == nil {
						return int32(port)
					}

					return defaultESSHPort
				}(),
			},
		},
	}

	zap.L().Debug("Sending init request", zap.Any("req", req))

	return streamC.Send(req)
}

func getStateMsg(ctx context.Context, streamC userv1.MainService_ConnectClient) (*userv1.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	errCh := make(chan error, 10)
	resCh := make(chan *userv1.ConnectionState, 10)

	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				msg, err := streamC.Recv()
				if err != nil {
					errCh <- err
					return
				}

				if msg.GetState() != nil {
					resCh <- msg.GetState()
					return
				}

				zap.L().Debug("Found an initial msg that is not state", zap.Any("msg", msg))
			}
		}
	}(ctx)
	select {
	case <-ctx.Done():
		return nil, errors.Errorf("Could not get initial state message after a timeout")
	case res := <-resCh:
		return res, nil
	case err := <-errCh:
		return nil, err
	}
}

func getConnectionConfig(ctx context.Context,
	c userv1.MainServiceClient,
	streamC userv1.MainService_ConnectClient,
	publishedSevices []*cliconfigv1.Connection_Preferences_PublishedService,
	domain string) (*cliconfigv1.Connection, error) {

	resp, err := getStateMsg(ctx, streamC)
	if err != nil {
		return nil, err
	}

	connCfg := &cliconfigv1.Connection{
		Connection: resp,
		CreatedAt:  pbutils.Now(),
		Info: &cliconfigv1.Connection_Info{
			Cluster: &cliconfigv1.Connection_Info_Cluster{
				Domain: domain,
			},
		},

		Preferences: &cliconfigv1.Connection_Preferences{
			RuntimeMode: cliconfigv1.Connection_Preferences_MACHINE,
			DeviceName:  fmt.Sprintf("octelium-%s", utilrand.GetRandomStringLowercase(6)),

			ConnectionType: func() cliconfigv1.Connection_Preferences_ConnectionType {
				if cmdArgs.TunnelMode == "quicv0" || os.Getenv("OCTELIUM_QUIC") == "true" {
					return cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0
				}
				return cliconfigv1.Connection_Preferences_CONNECTION_TYPE_UNSET
			}(),

			IgnoreDNS:         cmdArgs.IgnoreDNS,
			PublishedServices: publishedSevices,
			KeepAliveSeconds: func() int32 {
				ka, err := strconv.ParseInt(os.Getenv("OCTELIUM_KEEPALIVE"), 10, 32)
				if err != nil {
					return 0
				}
				if ka < 0 {
					return 0
				}
				return int32(ka)
			}(),
			Mtu: func() int32 {
				mtu, err := strconv.ParseInt(os.Getenv("OCTELIUM_MTU"), 10, 32)
				if err != nil {
					return 0
				}
				if mtu < 0 || mtu > 1500 {
					return 0
				}
				return int32(mtu)
			}(),

			L3Mode: func() cliconfigv1.Connection_Preferences_L3Mode {
				switch resp.L3Mode {
				case userv1.ConnectionState_V4:
					return cliconfigv1.Connection_Preferences_V4
				case userv1.ConnectionState_V6:
					return cliconfigv1.Connection_Preferences_V6
				default:
					return cliconfigv1.Connection_Preferences_BOTH
				}
			}(),

			ServeOpts: &cliconfigv1.Connection_Preferences_ServeOpts{
				IsEnabled: func() bool {
					if cmdArgs.ServeAll || len(cmdArgs.ServeServices) > 0 {
						return true
					}
					return false
				}(),
				ProxyMode: cliconfigv1.Connection_Preferences_ServeOpts_USERSPACE,
			},
			ESSH: &cliconfigv1.Connection_Preferences_ESSH{
				IsEnabled: cmdArgs.UseESSH || os.Getenv("OCTELIUM_ESSH") == "true",
				User: func() string {
					if cmdArgs.ESSHUser != "" {
						return cmdArgs.ESSHUser
					}
					if val := os.Getenv("OCTELIUM_ESSH_USER"); val != "" {
						return val
					}

					return ""
				}(),
				Port: func() int32 {
					if port, err := strconv.ParseInt(os.Getenv("OCTELIUM_ESSH_PORT"), 10, 32); err == nil {
						return int32(port)
					}

					return defaultESSHPort
				}(),

				ListenIPAddresses: func() []string {
					ipAddrsStr := os.Getenv("OCTELIUM_ESSH_IP_ADDRS")
					if ipAddrsStr == "" {
						return nil
					}

					ipStrs := strings.Split(ipAddrsStr, ",")

					var ret []string
					for _, ipStr := range ipStrs {
						ret = append(ret, strings.TrimSpace(ipStr))
					}
					return ret
				}(),
			},

			LocalDNS: &cliconfigv1.Connection_Preferences_LocalDNS{
				IsEnabled: cmdArgs.UseLocalDNS || os.Getenv("OCTELIUM_LOCAL_DNS_SERVER") == "true" ||
					os.Getenv("OCTELIUM_CONTAINER_MODE") == "true",
				ListenAddress: func() string {
					if cmdArgs.LocalDNSListenAddr != "" {
						if _, _, err := net.SplitHostPort(cmdArgs.LocalDNSListenAddr); err == nil {
							return cmdArgs.LocalDNSListenAddr
						}
						if govalidator.IsIP(cmdArgs.LocalDNSListenAddr) {
							return net.JoinHostPort(cmdArgs.LocalDNSListenAddr, "53")
						}
						return ""
					}
					return "127.0.0.100:53"
				}(),
			},
		},
	}

	if connCfg.Preferences.LocalDNS.IsEnabled && connCfg.Preferences.LocalDNS.ListenAddress == "" {
		return nil, errors.Errorf("Invalid local DNS server listen address: %s", cmdArgs.LocalDNSListenAddr)
	}

	if connCfg.Preferences.KeepAliveSeconds == 0 {
		connCfg.Preferences.KeepAliveSeconds = 30
	}

	switch runtime.GOOS {
	case "linux":
		connCfg.Preferences.LinuxPrefs = &cliconfigv1.Connection_Preferences_Linux{
			ImplementationMode: func() cliconfigv1.Connection_Preferences_Linux_ImplementationMode {
				switch cmdArgs.ImplementationMode {
				case "kernel":
					return cliconfigv1.Connection_Preferences_Linux_WG_KERNEL
				case "tun":
					return cliconfigv1.Connection_Preferences_Linux_WG_USERSPACE
				case "gvisor":
					return cliconfigv1.Connection_Preferences_Linux_WG_NETSTACK
				default:
					return cliconfigv1.Connection_Preferences_Linux_WG_KERNEL
				}
			}(),
			EnforceImplementationMode: cmdArgs.ImplementationMode != "",
		}
	case "windows":
		connCfg.Preferences.WindowsPrefs = &cliconfigv1.Connection_Preferences_Windows{}
		connCfg.Preferences.DeviceName = "octelium"
	case "darwin":
		connCfg.Preferences.MacosPrefs = &cliconfigv1.Connection_Preferences_MacOS{}
		connCfg.Preferences.DeviceName = "utun"
	}

	if runtime.GOOS == "linux" && os.Getenv("OCTELIUM_CONTAINER_MODE") == "true" {
		connCfg.Preferences.RuntimeMode = cliconfigv1.Connection_Preferences_CONTAINER
	}

	if connCfg.Preferences.ESSH.IsEnabled && runtime.GOOS == "windows" {
		cliutils.LineWarn("eSSH is not current supported on Windows. Ignoring using eSSH\n")
		connCfg.Preferences.ESSH.IsEnabled = false
	}

	return connCfg, nil
}

func getPublishedServices(ctx context.Context, c userv1.MainServiceClient, domain string) ([]*cliconfigv1.Connection_Preferences_PublishedService, error) {
	var ret []*cliconfigv1.Connection_Preferences_PublishedService

	for _, svc := range cmdArgs.PublishServices {
		publishedService, err := doGetPublishedService(ctx, c, svc, domain)
		if err != nil {
			if grpcerr.IsUnimplemented(err) {
				return getPublishedServicesWithList(ctx, c, domain)
			}
			return nil, err
		}

		zap.L().Debug("Published Service added", zap.Any("svc", publishedService))
		ret = append(ret, publishedService)
	}

	return ret, nil
}

func doGetPublishedService(ctx context.Context,
	c userv1.MainServiceClient, arg, domain string) (*cliconfigv1.Connection_Preferences_PublishedService, error) {

	res, err := parsePublishedService(arg)
	if err != nil {
		return nil, err
	}

	svc, err := c.GetService(ctx, &metav1.GetOptions{
		Name: cliutils.GetServiceFullNameFromName(res.svc),
	})
	if err != nil {
		return nil, err
	}

	switch svc.Spec.Type {
	case userv1.Service_Spec_DNS, userv1.Service_Spec_UDP:
		return nil, errors.Errorf("UDP-based published Services are currently unsupported.")
	}

	return &cliconfigv1.Connection_Preferences_PublishedService{
		Fqdn:        fmt.Sprintf("%s.local.%s", svc.Metadata.Name, domain),
		Name:        svc.Metadata.Name,
		Namespace:   svc.Status.Namespace,
		Port:        int32(svc.Spec.Port),
		HostPort:    int32(res.port),
		HostAddress: res.addr,
		L4Type: func() cliconfigv1.Connection_Preferences_PublishedService_L4Type {
			switch svc.Spec.Type {
			case userv1.Service_Spec_UDP, userv1.Service_Spec_DNS:
				return cliconfigv1.Connection_Preferences_PublishedService_UDP
			default:
				return cliconfigv1.Connection_Preferences_PublishedService_TCP
			}
		}(),
	}, nil
}

type ctl struct {
	devCtl          *controller.Controller
	proxyCtl        *proxy.Controller
	stateController *stateController
	mu              sync.Mutex
	isClosed        bool
	cancelFn        context.CancelFunc
}

func newCtl(ctx context.Context, streamC userv1.MainService_ConnectClient, connCfg *cliconfigv1.Connection) (*ctl, error) {
	var err error
	ret := &ctl{}

	zap.L().Debug("Creating dev controller")
	ret.devCtl, err = controller.NewController(connCfg)
	if err != nil {
		return nil, err
	}

	if connCfg.Preferences != nil && connCfg.Preferences.ServeOpts != nil &&
		connCfg.Preferences.ServeOpts.IsEnabled {
		ret.proxyCtl, err = proxy.NewController(ctx, connCfg, ret.devCtl)
		if err != nil {
			return nil, err
		}
	}

	ret.stateController = newStateController(connCfg, ret.devCtl, ret.proxyCtl, streamC)

	return ret, nil
}

func (c *ctl) start(ctx context.Context) error {
	ctx, cancelFn := context.WithCancel(ctx)
	c.cancelFn = cancelFn

	zap.L().Debug("Starting dev controller...")
	if err := c.devCtl.Start(ctx); err != nil {
		zap.L().Warn("Could not start dev controller", zap.Error(err))
		if err := c.devCtl.Close(); err != nil {
			zap.L().Debug("Could not close dev controller after startup error", zap.Error(err))
		}
		return err
	}

	if c.proxyCtl != nil {
		zap.L().Debug("Starting proxy controller...")
		if err := c.proxyCtl.Start(ctx); err != nil {
			return err
		}
	}

	zap.L().Debug("Starting state controller...")
	if err := c.stateController.Start(ctx); err != nil {
		return err
	}

	return nil
}

func (c *ctl) close() error {
	zap.L().Debug("Closing controller...")
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return nil
	}
	c.isClosed = true
	c.cancelFn()

	if c.proxyCtl != nil {
		c.proxyCtl.Close()
	}

	c.devCtl.Close()

	return nil
}

func connect(ctx context.Context, domain string) error {
	if ldflags.IsDev() || os.Getenv("OCTELIUM_PPROF") == "true" {
		srv := pprofsrv.New()
		if err := srv.Run(ctx); err != nil {
			return err
		}

		defer srv.Close()
	}

	for {
		ret := make(chan tryConnectRet)
		doneCh := make(chan struct{})
		go func() {
			ret <- tryConnect(ctx, domain, doneCh)
		}()

		select {
		case <-ctx.Done():
			zap.L().Debug("Waiting for tryConnect to exit...")
			select {
			case <-time.After(2 * time.Second):
				zap.L().Debug("tryConnect timeout...")
			case <-doneCh:
				zap.L().Debug("tryConnect done...")
			}
			return nil
		case ret := <-ret:
			if !ret.needsReconnect {
				zap.L().Debug("No reconnection needed. Exiting...", zap.Error(ret.err))
				return ret.err
			}

			time.Sleep(2 * time.Second)
			if ret.err != nil {
				err := ret.err

				switch {
				case grpcerr.IsInvalidArg(err):
					return err
				}
				cliutils.LineWarn("Could not connect due to err: %s. Reconnecting...\n", err.Error())
			}
		}
	}
}

type tryConnectRet struct {
	err            error
	needsReconnect bool
}

func tryConnect(ctx context.Context, domain string, doneCh chan<- struct{}) tryConnectRet {

	doNeedReconnect := func(err error) bool {
		if grpcerr.IsInvalidArg(err) ||
			grpcerr.IsUnauthorized(err) ||
			grpcerr.IsNotFound(err) {
			return false
		}

		return true
	}
	conn, err := client.GetGRPCClientConn(ctx, domain)
	if err != nil {
		return tryConnectRet{
			err:            err,
			needsReconnect: doNeedReconnect(err),
		}
	}
	defer conn.Close()

	c := userv1.NewMainServiceClient(conn)

	var publishedServices []*cliconfigv1.Connection_Preferences_PublishedService

	if len(cmdArgs.PublishServices) > 0 {
		publishedServices, err = getPublishedServices(ctx, c, domain)
		if err != nil {
			return tryConnectRet{
				err:            err,
				needsReconnect: false,
			}
		}
	}

	zap.L().Debug("Connecting to API Server...")
	streamC, err := c.Connect(ctx)
	if err != nil {
		return tryConnectRet{
			err:            errors.Errorf("Could not connect to API Server: %s", err),
			needsReconnect: doNeedReconnect(err),
		}
	}

	if err := sendInitializeRequest(streamC, publishedServices); err != nil {
		return tryConnectRet{
			err:            errors.Errorf("Could not send init request to API Server: %s", err),
			needsReconnect: doNeedReconnect(err),
		}
	}

	connCfg, err := getConnectionConfig(ctx, c, streamC, publishedServices, domain)
	if err != nil {
		return tryConnectRet{
			err:            err,
			needsReconnect: doNeedReconnect(err),
		}
	}

	ctl, err := newCtl(ctx, streamC, connCfg)
	if err != nil {
		return tryConnectRet{
			err:            errors.Errorf("Could not initialize controller: %s", err.Error()),
			needsReconnect: false,
		}
	}

	if err := ctl.start(ctx); err != nil {
		zap.L().Warn("Could not start controller", zap.Error(err))
		return tryConnectRet{
			err:            errors.Errorf("Could not start controller: %s", err.Error()),
			needsReconnect: false,
		}
	}

	needsReconnect := false
	var retErr error
	cliutils.LineNotify("Connected successfully...\n")
	select {
	case <-ctx.Done():
		cliutils.LineInfo("Received shutdown signal\n")
	case err := <-ctl.stateController.getConnErrCh:
		needsReconnect = true
		retErr = errors.Errorf("Abruptly disconnected by API Server: %s", err)
	case <-ctl.stateController.apiserverDisconnectCh:
		cliutils.LineInfo("Disconnected by API Server\n")
	}

	ctl.close()
	close(doneCh)

	return tryConnectRet{
		err:            retErr,
		needsReconnect: needsReconnect,
	}
}

func getPublishedServicesWithList(ctx context.Context, c userv1.MainServiceClient, domain string) ([]*cliconfigv1.Connection_Preferences_PublishedService, error) {
	var ret []*cliconfigv1.Connection_Preferences_PublishedService

	zap.L().Debug("Listing available Services to publish ports")
	svcList, err := c.ListService(ctx, &userv1.ListServiceOptions{})
	if err != nil {
		return nil, err
	}

	for _, svc := range cmdArgs.PublishServices {
		publishedService, err := doGetPublishedServiceWithList(svcList, svc, domain)
		if err != nil {
			return nil, err
		}
		zap.L().Debug("Published Service added", zap.Any("publisheSerice", publishedService))
		ret = append(ret, publishedService)
	}

	return ret, nil
}

func doGetPublishedServiceWithList(svcList *userv1.ServiceList, arg, domain string) (*cliconfigv1.Connection_Preferences_PublishedService, error) {

	getService := func(svcList *userv1.ServiceList, name string) *userv1.Service {
		for _, itm := range svcList.Items {
			if cliutils.GetServiceFullNameFromName(itm.Metadata.Name) == cliutils.GetServiceFullNameFromName(name) {
				return itm
			}
		}
		return nil
	}

	res, err := parsePublishedService(arg)
	if err != nil {
		return nil, err
	}

	svc := getService(svcList, res.svc)
	if svc == nil {
		return nil, errors.Errorf("The Service %s does not exist", res.svc)
	}

	return &cliconfigv1.Connection_Preferences_PublishedService{
		Fqdn:        fmt.Sprintf("%s.local.%s", svc.Metadata.Name, domain),
		Name:        svc.Metadata.Name,
		Namespace:   svc.Status.Namespace,
		Port:        int32(svc.Spec.Port),
		HostPort:    int32(res.port),
		HostAddress: res.addr,
		L4Type: func() cliconfigv1.Connection_Preferences_PublishedService_L4Type {
			switch svc.Spec.Type {
			case userv1.Service_Spec_UDP:
				return cliconfigv1.Connection_Preferences_PublishedService_UDP
			default:
				return cliconfigv1.Connection_Preferences_PublishedService_TCP
			}
		}(),
	}, nil
}

type parsePublishedServiceResult struct {
	svc  string
	addr string
	port int
}

func parsePublishedService(arg string) (*parsePublishedServiceResult, error) {
	parts := strings.SplitN(arg, ":", 2)
	if len(parts) != 2 {
		return nil, errors.Errorf(
			"Invalid published Service %s. It must be: `service:hostPort`, `service.namespace:hostPort` or `service:hostAddress:hostPort`", arg)
	}

	ret := &parsePublishedServiceResult{
		svc: parts[0],
	}

	_, err := cliutils.ParseServiceNamespace(ret.svc)
	if err != nil {
		return nil, err
	}

	if strings.Contains(parts[1], ":") {
		addr, port, err := net.SplitHostPort(parts[1])
		if err != nil {
			return nil, err
		}

		switch addr {
		case "localhost":
		default:
			if !govalidator.IsIP(addr) {
				return nil, errors.Errorf("Invalid IP address: %s", addr)
			}
		}

		ret.addr = addr

		hostPort, err := strconv.ParseInt(port, 10, 32)
		if err != nil {
			return nil, err
		}

		if !govalidator.IsPort(fmt.Sprintf("%d", hostPort)) {
			return nil, errors.Errorf("Invalid port: %d", hostPort)
		}

		ret.port = int(hostPort)
	} else {
		ret.addr = "localhost"

		hostPort, err := strconv.ParseInt(parts[1], 10, 32)
		if err != nil {
			return nil, err
		}

		if !govalidator.IsPort(fmt.Sprintf("%d", hostPort)) {
			return nil, errors.Errorf("Invalid port: %d", hostPort)
		}

		ret.port = int(hostPort)
	}

	return ret, nil
}
