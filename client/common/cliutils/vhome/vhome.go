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

	"github.com/pkg/errors"
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

	if os.Getuid() != 0 {
		return os.UserHomeDir()
	}

	if usr, err := func() (*user.User, error) {
		if uid := os.Getenv("SUDO_UID"); uid != "" {
			return user.LookupId(uid)
		}
		if u := os.Getenv("SUDO_USER"); u != "" {
			return user.Lookup(u)
		}
		if uid := os.Getenv("PKEXEC_UID"); uid != "" {
			return user.LookupId(uid)
		}
		return nil, errors.Errorf("Could not find initial user")
	}(); err == nil {
		return usr.HomeDir, nil
	}

	return os.UserHomeDir()
}
