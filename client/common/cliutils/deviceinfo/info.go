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

package deviceinfo

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/denisbrodbeck/machineid"
)

type DeviceInfo struct {
	ID           string
	SerialNumber string
	Hostname     string
	MacAddresses []string
}

func getID() (string, error) {
	machineID, err := machineid.ID()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", sha256.Sum256([]byte(machineID))), nil
}

func GetDeviceInfo(ctx context.Context) (*DeviceInfo, error) {
	var err error
	ret := &DeviceInfo{}

	ret.ID, err = getID()
	if err != nil {
		return nil, err
	}
	ret.SerialNumber, err = getSerialNumber(ctx)
	if err != nil {
		return nil, err
	}

	ret.Hostname, err = os.Hostname()
	if err != nil {
		return nil, err
	}

	ret.MacAddresses, err = getMacAddresses()
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func getMacAddresses() ([]string, error) {

	isVirtual := func(name string) bool {

		virtuals := []string{
			"veth", "docker", "virbr",
			"vmnet", "vboxnet", "tun",
			"tap", "wg", "container", "octelium",
			"bridge", "lo", "awdl", "llw", "utun", "virtual",
		}

		for _, virtual := range virtuals {
			if strings.Contains(strings.ToLower(name), virtual) {
				return true
			}
		}

		return false
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var addrs []string

	for _, iface := range interfaces {

		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if len(iface.HardwareAddr) == 0 {
			continue
		}

		if isVirtual(iface.Name) {
			continue
		}

		addrs = append(addrs, iface.HardwareAddr.String())
	}

	return addrs, nil
}
