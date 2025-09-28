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

package umetav1

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"google.golang.org/protobuf/proto"
)

type ObjectI interface {
	GetKind() string
	GetApiVersion() string
	proto.Message
}

type ResourceObjectI interface {
	ObjectI
	GetMetadata() *metav1.Metadata
}

type LogResourceObjectI interface {
	ObjectI
	GetMetadata() *metav1.LogMetadata
}

type Duration struct {
	*metav1.Duration
}

type Metadata struct {
	*metav1.Metadata
}

func ToMetadata(d *metav1.Metadata) *Metadata {
	return &Metadata{
		Metadata: d,
	}
}

func ToDuration(d *metav1.Duration) *Duration {
	return &Duration{
		Duration: d,
	}
}

func (d *Duration) ToGo() time.Duration {
	if d == nil || d.Duration == nil || d.Type == nil {
		return time.Duration(0)
	}

	switch d.Type.(type) {
	case *metav1.Duration_Milliseconds:
		return time.Duration(int64(d.GetMilliseconds()) * int64(time.Millisecond))
	case *metav1.Duration_Seconds:
		return time.Duration(int64(d.GetSeconds()) * int64(time.Second))
	case *metav1.Duration_Minutes:
		return time.Duration(int64(d.GetMinutes()) * int64(time.Second) * 60)
	case *metav1.Duration_Hours:
		return time.Duration(int64(d.GetHours()) * int64(time.Second) * 60 * 60)
	case *metav1.Duration_Days:
		return time.Duration(int64(d.GetDays()) * int64(time.Second) * 60 * 60 * 24)
	case *metav1.Duration_Weeks:
		return time.Duration(int64(d.GetWeeks()) * int64(time.Second) * 60 * 60 * 24 * 7)
	case *metav1.Duration_Months:
		return time.Duration(int64(d.GetMonths()) * int64(time.Second) * 60 * 60 * 24 * 30)
	default:
		return time.Duration(0)
	}
}

func (d *Duration) ToSeconds() int64 {
	return int64(d.ToGo().Seconds())
}

/*
func (m *Metadata) GetCoreUserRef(name string) *metav1.ObjectReference {
	for _, v := range m.ObjectReferences {
		if v.Name == name && v.ApiVersion == "core/v1" && v.Kind == "User" {
			return v
		}
	}
	return nil
}
*/

/*
func (m *Metadata) GetCoreUserUID(name string) string {
	for k, v := range m.ObjectReferences {
		if v.Name == name && v.ApiVersion == "core/v1" && v.Kind == "User" {
			return k
		}
	}
	return ""
}
*/

func GetObjectReference(itm ResourceObjectI) *metav1.ObjectReference {
	if itm == nil || itm.GetMetadata() == nil {
		return nil
	}

	return &metav1.ObjectReference{
		ApiVersion:      itm.GetApiVersion(),
		Kind:            itm.GetKind(),
		Name:            itm.GetMetadata().Name,
		Uid:             itm.GetMetadata().Uid,
		ResourceVersion: itm.GetMetadata().ResourceVersion,
	}
}

type GoDualStackIP struct {
	IPv4 net.IP
	IPv6 net.IP
}

type GoDualStackNetwork struct {
	V4 *net.IPNet
	V6 *net.IPNet
}

type DualStackIP struct {
	*metav1.DualStackIP
}

func ToDualStackIP(a *metav1.DualStackIP) *DualStackIP {
	return &DualStackIP{
		DualStackIP: a,
	}
}

type DualStackNetwork struct {
	*metav1.DualStackNetwork
}

func ToDualStackNetwork(a *metav1.DualStackNetwork) *DualStackNetwork {
	return &DualStackNetwork{
		DualStackNetwork: a,
	}
}

func (arg *DualStackIP) ToGo() *GoDualStackIP {
	return &GoDualStackIP{
		IPv4: net.ParseIP(arg.Ipv4),
		IPv6: net.ParseIP(arg.Ipv6),
	}
}

func (arg *DualStackNetwork) ToGo() *GoDualStackNetwork {
	_, v4, _ := net.ParseCIDR(arg.V4)
	_, v6, _ := net.ParseCIDR(arg.V6)

	return &GoDualStackNetwork{
		V4: v4,
		V6: v6,
	}
}

func (n *DualStackNetwork) ToIP() *metav1.DualStackIP {

	ret := &metav1.DualStackIP{}

	if n.V4 != "" {
		ipv4, _, _ := net.ParseCIDR(n.V4)
		ret.Ipv4 = ipv4.String()
	}
	if n.V6 != "" {
		ipv6, _, _ := net.ParseCIDR(n.V6)
		ret.Ipv6 = ipv6.String()
	}

	return ret
}

func (i *DualStackIP) GetIndex() int {
	arg := make([]byte, 8)
	if i.Ipv4 != "" {
		ipv4 := i.ToGo().IPv4
		copy(arg[6:], ipv4[len(ipv4)-2:])
		return int(binary.BigEndian.Uint64(arg))
	}
	if i.Ipv6 != "" {
		ipv6 := i.ToGo().IPv6
		copy(arg[6:], ipv6[len(ipv6)-2:])
		return int(binary.BigEndian.Uint64(arg))
	}
	// We must not reach here anyway
	return 0
}
