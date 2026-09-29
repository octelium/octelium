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
	ret.SerialNumber, err = GetSerialNumber(ctx)
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

func GetSerialNumber(ctx context.Context) (string, error) {
	ret, err := getSerialNumber(ctx)
	if err != nil {
		return "", err
	}

	ret = strings.TrimSpace(ret)
	if isInvalidSerialNumber(ret) {
		return "", nil
	}

	return ret, nil
}

func GetHardwareUUID(ctx context.Context) (string, error) {
	ret, err := getHardwareUUID(ctx)
	if err != nil {
		return "", err
	}

	return strings.ToLower(strings.TrimSpace(ret)), nil
}

func GetOSInstallationID() (string, error) {
	return machineid.ID()
}

func GetMacAddresses() ([]string, error) {
	return getMacAddresses()
}

const minSerialNumberLen = 6

func isInvalidSerialNumber(arg string) bool {
	arg = strings.ToLower(strings.TrimSpace(arg))

	if len(arg) < minSerialNumberLen {
		return true
	}

	switch arg {
	case "default string",
		"to be filled by o.e.m.",
		"system serial number",
		"chassis serial number",
		"not specified",
		"not applicable",
		"0123456789",
		"123456789",
		"null",
		"none",
		"invalid",
		"unknown":
		return true
	}

	return strings.Trim(arg, "0") == "" || strings.Trim(arg, "f") == ""
}

func isUsableMacAddress(hw net.HardwareAddr) bool {
	if len(hw) != 6 {
		return false
	}

	if hw[0]&0x01 != 0 || hw[0]&0x02 != 0 {
		return false
	}

	for _, b := range hw {
		if b != 0 {
			return true
		}
	}

	return false
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

		if !isUsableMacAddress(iface.HardwareAddr) {
			continue
		}

		addrs = append(addrs, iface.HardwareAddr.String())
	}

	return addrs, nil
}
