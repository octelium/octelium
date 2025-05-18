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

//go:build serveenvoy

package envoy

/*
import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	"google.golang.org/protobuf/types/known/wrapperspb"
)

type L4Protocol int

const (
	ProtocolTCP = L4Protocol(iota)
	ProtocolUDP
)

func getAddress(host string, port uint32, protocol L4Protocol) *core.Address {

	proto := core.SocketAddress_TCP
	if protocol == ProtocolUDP {
		proto = core.SocketAddress_UDP
	}
	return &core.Address{Address: &core.Address_SocketAddress{
		SocketAddress: &core.SocketAddress{
			Address:  host,
			Protocol: proto,
			PortSpecifier: &core.SocketAddress_PortValue{
				PortValue: port,
			},
		},
	}}

}

func getGrpcService(clusterName string) *core.GrpcService {
	return &core.GrpcService{
		TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
			EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
				ClusterName: clusterName,
			},
		},
	}

}

func getCIDRRange(address string, prefix int) *core.CidrRange {

	return &core.CidrRange{
		AddressPrefix: address,
		PrefixLen: &wrapperspb.UInt32Value{
			Value: uint32(prefix),
		},
	}
}

func toBool(arg bool) *wrapperspb.BoolValue {
	return &wrapperspb.BoolValue{
		Value: arg,
	}
}
*/
