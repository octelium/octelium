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

package controller

import (
	"context"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/miekg/dns"
	bufferv2 "gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type netTun struct {
	stack          *stack.Stack
	dispatcher     stack.NetworkDispatcher
	events         chan tun.Event
	incomingPacket chan *bufferv2.View
	ctl            *Controller

	hasV4 bool
	hasV6 bool
}

type endpoint netTun
type Net netTun

func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *endpoint) MTU() uint32 {
	mtu, err := (*netTun)(e).MTU()
	if err != nil {
		panic(err)
	}
	return uint32(mtu)
}

func (*endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (*endpoint) MaxHeaderLength() uint16 {
	return 0
}

func (*endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (*endpoint) Wait() {}

func (e *endpoint) WritePacket(pkt *stack.PacketBuffer) tcpip.Error {
	e.incomingPacket <- pkt.ToView()
	return nil
}

func (e *endpoint) WriteRawPacket(*stack.PacketBuffer) tcpip.Error {
	panic("not implemented")
}

func (*endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

func (e *endpoint) WritePackets(pbs stack.PacketBufferList) (int, tcpip.Error) {
	lst := pbs.AsSlice()
	for _, pkt := range lst {
		e.WritePacket(pkt)
	}
	return len(lst), nil
}

func (*endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *endpoint) AddHeader(*stack.PacketBuffer) {
}

func (e *endpoint) Close() {

}

func (e *endpoint) SetLinkAddress(addr tcpip.LinkAddress) {

}

func (e *endpoint) SetMTU(mtu uint32) {

}

func (e *endpoint) SetOnCloseAction(func()) {

}

func (c *Controller) GetNetstackNet() *Net {
	if c.nsTun == nil {
		return nil
	}
	return (*Net)(c.nsTun)
}

func (c *Controller) GetGoNet() ccommon.GoNet {
	if c.nsTun == nil {
		return nil
	}
	return (*Net)(c.nsTun)
}

func (c *Controller) createNetstackTUN() error {
	switch runtime.GOARCH {
	case "amd64", "arm64":
	default:
		return errors.Errorf("gVisor netstack mode is not currently supported for the architecture: %s", runtime.GOARCH)
	}

	c.isNetstack = true

	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	}
	dev := &netTun{
		ctl:            c,
		stack:          stack.New(opts),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *bufferv2.View),
		hasV4:          c.ipv4Supported,
		hasV6:          c.ipv6Supported,
	}

	tcpipErr := dev.stack.CreateNIC(1, (*endpoint)(dev))
	if tcpipErr != nil {
		return errors.Errorf("CreateNIC: %v", tcpipErr)
	}

	for _, addr := range c.c.Connection.Addresses {

		if c.ipv4Supported && addr.V4 != "" {
			_, mip, _ := net.ParseCIDR(addr.V4)
			if err := dev.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{
				Protocol:          header.IPv4ProtocolNumber,
				AddressWithPrefix: tcpip.AddrFromSlice(mip.IP.To4()).WithPrefix(),
			}, stack.AddressProperties{}); err != nil {
				return errors.Errorf("Could not add addr v4: %+v", err)
			}

		}
		if c.ipv6Supported && addr.V6 != "" {
			_, mip, _ := net.ParseCIDR(addr.V6)
			if err := dev.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{
				Protocol:          header.IPv6ProtocolNumber,
				AddressWithPrefix: tcpip.AddrFromSlice(mip.IP).WithPrefix(),
			}, stack.AddressProperties{}); err != nil {
				return errors.Errorf("Could not add addr v6: %+v", err)
			}

		}

	}

	if c.ipv4Supported {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if c.ipv6Supported {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}

	dev.events <- tun.EventUp

	c.nsTun = dev
	zap.S().Debugf("Successfully created netstackTun")
	return nil
}

func (tun *netTun) Name() (string, error) {
	return tun.ctl.c.Preferences.DeviceName, nil
}

func (tun *netTun) File() *os.File {
	return nil
}

func (tun *netTun) Events() <-chan tun.Event {
	return tun.events
}

func (tun *netTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-tun.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (tun *netTun) Write(buffs [][]byte, offset int) (int, error) {

	for _, buf := range buffs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		// pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Data: buffer.NewVectorisedView(len(packet), []buffer.View{buffer.NewViewFromBytes(packet)})})
		// buffer := bufferv2.MakeWithView(bufferv2.NewViewWithData(packet))

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: bufferv2.MakeWithData(packet),
		})

		switch packet[0] >> 4 {
		case 4:
			tun.dispatcher.DeliverNetworkPacket(ipv4.ProtocolNumber, pkb)
		case 6:
			tun.dispatcher.DeliverNetworkPacket(ipv6.ProtocolNumber, pkb)
		}
	}

	return len(buffs), nil
}

func (tun *netTun) Flush() error {
	return nil
}

func (tun *netTun) BatchSize() int {
	return 1
}

func (tun *netTun) Close() error {
	tun.stack.RemoveNIC(1)

	if tun.events != nil {
		close(tun.events)
	}
	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}
	return nil
}

func (tun *netTun) MTU() (int, error) {
	return tun.ctl.getMTU(), nil
}

func convertToFullAddr(ip net.IP, port int) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	if ip4 := ip.To4(); ip4 != nil {
		return tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.AddrFromSlice(ip.To4()),
			Port: uint16(port),
		}, ipv4.ProtocolNumber
	} else {
		return tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.AddrFromSlice(ip),
			Port: uint16(port),
		}, ipv6.ProtocolNumber
	}
}

func (net *Net) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		panic("todo: deal with auto addr semantics for nil addr")
	}
	fa, pn := convertToFullAddr(addr.IP, addr.Port)
	return gonet.DialContextTCP(ctx, net.stack, fa, pn)
}

func (net *Net) DialTCP(addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		panic("todo: deal with auto addr semantics for nil addr")
	}
	fa, pn := convertToFullAddr(addr.IP, addr.Port)
	return gonet.DialTCP(net.stack, fa, pn)
}

func (net *Net) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	if addr == nil {
		panic("todo: deal with auto addr semantics for nil addr")
	}
	fa, pn := convertToFullAddr(addr.IP, addr.Port)
	return gonet.ListenTCP(net.stack, fa, pn)
}

func (net *Net) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var lfa, rfa *tcpip.FullAddress
	var pn tcpip.NetworkProtocolNumber
	if laddr != nil {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddr(laddr.IP, laddr.Port)
		lfa = &addr
	}
	if raddr != nil {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddr(raddr.IP, raddr.Port)
		rfa = &addr
	}
	return gonet.DialUDP(net.stack, lfa, rfa, pn)
}

var (
	errCanceled          = errors.New("operation was canceled")
	errTimeout           = errors.New("i/o timeout")
	errNumericPort       = errors.New("port must be numeric")
	errNoSuitableAddress = errors.New("no suitable address found")
	errMissingAddress    = errors.New("missing address")
)

func partialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, errTimeout
	}
	timeout := timeRemaining / time.Duration(addrsRemaining)
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		if timeRemaining < saneMinimum {
			timeout = timeRemaining
		} else {
			timeout = saneMinimum
		}
	}
	return now.Add(timeout), nil
}

func (tnet *Net) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		panic("nil context")
	}
	var acceptV4, acceptV6, useUDP bool
	if len(network) == 3 {
		acceptV4 = true
		acceptV6 = true
	} else if len(network) == 4 {
		acceptV4 = network[3] == '4'
		acceptV6 = network[3] == '6'
	}
	if !acceptV4 && !acceptV6 {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	}
	if network[:3] == "udp" {
		useUDP = true
	} else if network[:3] != "tcp" {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	}
	host, sport, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}
	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "dial", Err: errNumericPort}
	}
	allAddr, err := tnet.LookupContextHost(ctx, host)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}
	var addrs []net.IP
	for _, addr := range allAddr {
		if strings.IndexByte(addr, ':') != -1 && acceptV6 {
			addrs = append(addrs, net.ParseIP(addr))
		} else if strings.IndexByte(addr, '.') != -1 && acceptV4 {
			addrs = append(addrs, net.ParseIP(addr))
		}
	}
	if len(addrs) == 0 && len(allAddr) != 0 {
		return nil, &net.OpError{Op: "dial", Err: errNoSuitableAddress}
	}

	var firstErr error
	for i, addr := range addrs {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			if err == context.Canceled {
				err = errCanceled
			} else if err == context.DeadlineExceeded {
				err = errTimeout
			}
			return nil, &net.OpError{Op: "dial", Err: err}
		default:
		}

		dialCtx := ctx
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			partialDeadline, err := partialDeadline(time.Now(), deadline, len(addrs)-i)
			if err != nil {
				if firstErr == nil {
					firstErr = &net.OpError{Op: "dial", Err: err}
				}
				break
			}
			if partialDeadline.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
				cancel()
			}
		}

		var c net.Conn
		if useUDP {
			c, err = tnet.DialUDP(nil, &net.UDPAddr{IP: addr, Port: port})
		} else {
			c, err = tnet.DialContextTCP(dialCtx, &net.TCPAddr{IP: addr, Port: port})
		}
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = &net.OpError{Op: "dial", Err: errMissingAddress}
	}
	return nil, firstErr
}

func (tnet *Net) Dial(network, address string) (net.Conn, error) {
	return tnet.DialContext(context.Background(), network, address)
}

func (tnet *Net) LookupHost(host string) ([]string, error) {
	return tnet.LookupContextHost(context.Background(), host)
}

func (tnet *Net) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	if host == "" || (!tnet.hasV6 && !tnet.hasV4) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	zlen := len(host)
	if strings.IndexByte(host, ':') != -1 {
		if zidx := strings.LastIndexByte(host, '%'); zidx != -1 {
			zlen = zidx
		}
	}
	if ip := net.ParseIP(host[:zlen]); ip != nil {
		return []string{host[:zlen]}, nil
	}

	tnet.ctl.dnsServers.Lock()
	servers := append([]net.IP(nil), tnet.ctl.dnsServers.servers...)
	tnet.ctl.dnsServers.Unlock()

	type lookupResult struct {
		addrs []net.IP
		err   error
	}

	lookup := func(qtype uint16) lookupResult {
		fqdn := dns.Fqdn(host)
		var lastErr error

		for _, server := range servers {
			m := new(dns.Msg)
			m.SetQuestion(fqdn, qtype)
			m.RecursionDesired = true
			m.SetEdns0(4096, false)
			m.Id = dns.Id()

			serverAddr := net.JoinHostPort(server.String(), "53")

			in, err := tnet.exchangeDNS(ctx, "udp", m, serverAddr)
			if err != nil {
				lastErr = &net.DNSError{
					Err:    err.Error(),
					Name:   host,
					Server: server.String(),
				}
				continue
			}

			if in.Truncated {
				m.Id = dns.Id()
				in, err = tnet.exchangeDNS(ctx, "tcp", m, serverAddr)
				if err != nil {
					lastErr = &net.DNSError{
						Err:    err.Error(),
						Name:   host,
						Server: server.String(),
					}
					continue
				}
			}

			if in.Rcode != dns.RcodeSuccess {
				lastErr = &net.DNSError{
					Err:        dns.RcodeToString[in.Rcode],
					Name:       host,
					Server:     server.String(),
					IsNotFound: in.Rcode == dns.RcodeNameError,
				}
				continue
			}

			var addrs []net.IP
			for _, ans := range in.Answer {
				switch rr := ans.(type) {
				case *dns.A:
					addrs = append(addrs, rr.A)
				case *dns.AAAA:
					addrs = append(addrs, rr.AAAA)
				}
			}

			if len(addrs) > 0 {
				return lookupResult{addrs: addrs}
			}
		}

		return lookupResult{err: lastErr}
	}

	var (
		ch     = make(chan lookupResult, 2)
		queued int
	)

	if tnet.hasV4 {
		queued++
		go func() { ch <- lookup(dns.TypeA) }()
	}
	if tnet.hasV6 {
		queued++
		go func() { ch <- lookup(dns.TypeAAAA) }()
	}

	var addrsV4, addrsV6 []net.IP
	var lastErr error

	for range queued {
		r := <-ch
		if r.err != nil {
			lastErr = r.err
			continue
		}
		for _, ip := range r.addrs {
			if ip.To4() != nil {
				addrsV4 = append(addrsV4, ip)
			} else {
				addrsV6 = append(addrsV6, ip)
			}
		}
	}

	var addrs []net.IP
	if tnet.hasV6 {
		addrs = append(addrsV6, addrsV4...)
	} else {
		addrs = append(addrsV4, addrsV6...)
	}
	if len(addrs) == 0 && lastErr != nil {
		return nil, lastErr
	}

	out := make([]string, len(addrs))
	for i, ip := range addrs {
		out[i] = ip.String()
	}
	return out, nil
}

func (tnet *Net) exchangeDNS(ctx context.Context, netType string, m *dns.Msg, serverAddr string) (*dns.Msg, error) {
	host, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return nil, err
	}
	portN, _ := strconv.Atoi(port)
	serverIP := net.ParseIP(host)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var conn net.Conn
	if netType == "udp" {
		conn, err = tnet.DialUDP(nil, &net.UDPAddr{IP: serverIP, Port: portN})
	} else {
		conn, err = tnet.DialContextTCP(ctx, &net.TCPAddr{IP: serverIP, Port: portN})
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
	}

	dnsConn := &dns.Conn{Conn: conn}

	if err := dnsConn.WriteMsg(m); err != nil {
		return nil, err
	}

	in, err := dnsConn.ReadMsg()
	if err != nil {
		return nil, err
	}

	if in.Id != m.Id {
		return nil, errors.Errorf("dns message ID mismatch: got %d, expected %d", in.Id, m.Id)
	}
	if !in.Response {
		return nil, errors.Errorf("dns message is not a response")
	}

	return in, nil
}
