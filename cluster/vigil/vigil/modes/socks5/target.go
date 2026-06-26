/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package socks5

import (
	"net"
	"strconv"
	"strings"

	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/pkg/errors"
)

type addressType int

const (
	addressTypeUnspecified addressType = iota
	addressTypeIPv4
	addressTypeDomain
	addressTypeIPv6
)

type target struct {
	req *gosocks5.Request

	host string
	port int
	addr string

	addrType addressType
}

func newTarget(req *gosocks5.Request) (*target, error) {
	if req == nil || req.RawDestAddr == nil {
		return nil, errors.Errorf("nil SOCKS5 request destination")
	}

	if req.Command != statute.CommandConnect {
		return nil, errors.Errorf("unsupported SOCKS5 command: %d", req.Command)
	}

	raw := req.RawDestAddr

	if raw.Port <= 0 || raw.Port > 65535 {
		return nil, errors.Errorf("invalid SOCKS5 destination port: %d", raw.Port)
	}

	ret := &target{
		req:  req,
		port: raw.Port,
	}

	switch raw.AddrType {
	case statute.ATYPDomain:
		host, err := normalizeDomain(raw.FQDN)
		if err != nil {
			return nil, err
		}
		ret.host = host
		ret.addrType = addressTypeDomain

	case statute.ATYPIPv4:
		ip := raw.IP.To4()
		if ip == nil {
			return nil, errors.Errorf("invalid SOCKS5 IPv4 destination")
		}
		ret.host = ip.String()
		ret.addrType = addressTypeIPv4

	case statute.ATYPIPv6:
		ip := raw.IP.To16()
		if ip == nil || ip.To4() != nil {
			return nil, errors.Errorf("invalid SOCKS5 IPv6 destination")
		}
		ret.host = ip.String()
		ret.addrType = addressTypeIPv6

	default:
		return nil, errors.Errorf("unsupported SOCKS5 address type: %d", raw.AddrType)
	}

	ret.addr = net.JoinHostPort(ret.host, strconv.Itoa(ret.port))
	return ret, nil
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)

	if domain == "" {
		return "", errors.Errorf("empty SOCKS5 domain destination")
	}

	if len(domain) > 253 {
		return "", errors.Errorf("SOCKS5 domain destination is too long")
	}

	if strings.ContainsAny(domain, "\x00/\\") {
		return "", errors.Errorf("SOCKS5 domain destination contains invalid characters")
	}

	return domain, nil
}

func (t *target) toRequestAddressType() corev1.RequestContext_Request_SOCKS5_Connect_AddressType {
	switch t.addrType {
	case addressTypeIPv4:
		return corev1.RequestContext_Request_SOCKS5_Connect_IPV4
	case addressTypeDomain:
		return corev1.RequestContext_Request_SOCKS5_Connect_DOMAIN
	case addressTypeIPv6:
		return corev1.RequestContext_Request_SOCKS5_Connect_IPV6
	default:
		return corev1.RequestContext_Request_SOCKS5_Connect_ADDRESS_TYPE_UNSPECIFIED
	}
}

func (t *target) toLogAddressType() corev1.AccessLog_Entry_Info_SOCKS5_AddressType {
	switch t.addrType {
	case addressTypeIPv4:
		return corev1.AccessLog_Entry_Info_SOCKS5_IPV4
	case addressTypeDomain:
		return corev1.AccessLog_Entry_Info_SOCKS5_DOMAIN
	case addressTypeIPv6:
		return corev1.AccessLog_Entry_Info_SOCKS5_IPV6
	default:
		return corev1.AccessLog_Entry_Info_SOCKS5_ADDRESS_TYPE_UNSPECIFIED
	}
}
