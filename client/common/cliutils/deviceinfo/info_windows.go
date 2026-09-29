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

	"github.com/pkg/errors"
	"github.com/yusufpapurcu/wmi"
)

type Win32_BIOS struct {
	SerialNumber string
}

type Win32_ComputerSystemProduct struct {
	UUID string
}

func getSerialNumber(ctx context.Context) (string, error) {
	var dst []Win32_BIOS
	query := wmi.CreateQuery(&dst, "")
	err := wmi.Query(query, &dst)
	if err != nil {
		return "", err
	}

	if len(dst) == 0 {
		return "", nil
	}

	return dst[0].SerialNumber, nil
}

func getHardwareUUID(ctx context.Context) (string, error) {
	var dst []Win32_ComputerSystemProduct
	query := wmi.CreateQuery(&dst, "")
	err := wmi.Query(query, &dst)
	if err != nil {
		return "", err
	}

	if len(dst) == 0 {
		return "", errors.Errorf("Could not find hardware UUID")
	}

	return dst[0].UUID, nil
}
