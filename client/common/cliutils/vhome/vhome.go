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

package vhome

import (
	"os"
	"os/user"
	"path"
	"runtime"
)

func GetOcteliumHome() (string, error) {
	if ret := os.Getenv("OCTELIUM_HOME"); ret != "" {
		return ret, nil
	}

	homeDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	suffix := func() string {
		if runtime.GOOS == "windows" {
			return "Octelium"
		} else {
			return "octelium"
		}
	}()

	return path.Join(homeDir, suffix), nil
}

func GetOcteliumUserHome() (string, error) {
	if ret := os.Getenv("OCTELIUM_USER_HOME"); ret != "" {
		return ret, nil
	}
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	return usr.HomeDir, nil
}
