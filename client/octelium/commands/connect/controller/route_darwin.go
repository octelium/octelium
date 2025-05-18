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
	"os/exec"

	"github.com/pkg/errors"
)

func (c *Controller) doSetRoutes() error {
	if c.isNetstack {
		return nil
	}
	cidr := c.c.Connection.Cidr
	if c.ipv4Supported && cidr.V4 != "" {
		if o, err := exec.Command("route", "-q", "-n", "add", "-inet", cidr.V4, "-iface", c.c.Preferences.DeviceName).CombinedOutput(); err != nil {
			return errors.Errorf("Could not set route %s: %s", cidr.V4, string(o))
		}
	}

	if c.ipv6Supported && cidr.V6 != "" {
		if o, err := exec.Command("route", "-q", "-n", "add", "-inet6", cidr.V6, "-iface", c.c.Preferences.DeviceName).CombinedOutput(); err != nil {
			return errors.Errorf("Could not set route %s: %s", cidr.V6, string(o))
		}
	}

	return nil
}

func (c *Controller) doUnsetRoutes() error {
	if c.isNetstack {
		return nil
	}

	cidr := c.c.Connection.Cidr
	if c.ipv4Supported && cidr.V4 != "" {
		if err := exec.Command("route", "-q", "-n", "delete", "-inet", cidr.V4, "-iface", c.c.Preferences.DeviceName).Run(); err != nil {
			return err
		}
	}

	if c.ipv6Supported && cidr.V6 != "" {
		if err := exec.Command("route", "-q", "-n", "delete", "-inet6", cidr.V6, "-iface", c.c.Preferences.DeviceName).Run(); err != nil {
			return err
		}
	}

	return nil
}
