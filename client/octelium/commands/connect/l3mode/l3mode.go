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

package l3mode

import (
	"net"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/userv1"
	"go.uber.org/zap"
)

func GetL3Mode(mode string) (userv1.ConnectRequest_Initialize_L3Mode, error) {

	if mode == "v6" {
		return userv1.ConnectRequest_Initialize_V6, nil
	}

	if mode == "v4" {
		return userv1.ConnectRequest_Initialize_V4, nil
	}

	if mode == "both" {
		return userv1.ConnectRequest_Initialize_BOTH, nil
	}

	isIPv6Supported, err := isSupported(true)
	if err != nil {
		return userv1.ConnectRequest_Initialize_BOTH, err
	}

	if isIPv6Supported {
		zap.S().Debugf("IPv6 is supported, going to request a IPv6-only mode from the Cluster")
		return userv1.ConnectRequest_Initialize_V6, nil
	}

	return userv1.ConnectRequest_Initialize_V4, nil
}

func isSupported(isV6 bool) (bool, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return false, err
		}
		for _, addr := range addrs {
			mip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				return false, err
			}

			if isV6 {
				if govalidator.IsIPv6(mip.String()) {
					return true, nil
				}
			} else {
				if govalidator.IsIPv4(mip.String()) {
					return true, nil
				}
			}

		}
	}
	return false, nil
}
