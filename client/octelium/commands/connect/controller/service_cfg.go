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
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/cliutils/vhome"
	"go.uber.org/zap"
)

func (c *Controller) setServiceConfigs() error {
	for _, svcCfg := range c.c.Connection.ServiceConfigs {
		switch svcCfg.Type.(type) {
		case *userv1.ConnectionState_ServiceConfig_Ssh:
			if err := setServiceConfigSSH(svcCfg.GetSsh()); err != nil {
				return err
			}
		}
	}
	return nil
}

func setServiceConfigSSH(svcCfg *userv1.ConnectionState_ServiceConfig_SSH) error {
	homeDir, err := vhome.GetOcteliumUserHome()
	if err != nil {
		return err
	}

	zap.L().Debug("Setting SSH service configs", zap.String("userHome", homeDir))

	if _, err := os.Stat(path.Join(homeDir, ".ssh")); err != nil {
		if os.IsNotExist(err) {
			zap.L().Debug("No SSH dir. No config needs to be set...")
			return nil
		} else {
			zap.L().Debug("Could not check for SSH dir", zap.Error(err))
			return nil
		}
	}

	if err := setServiceConfigSSHKnownHosts(svcCfg, path.Join(homeDir, ".ssh", "known_hosts")); err != nil {
		zap.L().Warn("Could not set the Cluster CA in the known_hosts file",
			zap.String("filePath", path.Join(homeDir, ".ssh", "known_hosts")),
			zap.Error(err))
	}

	if err := setServiceConfigSSHAuthorizedKeys(svcCfg, path.Join(homeDir, ".ssh", "authorized_keys")); err != nil {
		zap.L().Warn("Could not set the Cluster CA in the authorized keys file",
			zap.String("filePath", path.Join(homeDir, ".ssh", "authorized_keys")),
			zap.Error(err))
	}

	return nil
}

func setServiceConfigSSHKnownHosts(svcCfg *userv1.ConnectionState_ServiceConfig_SSH, knownHostsPath string) error {

	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := os.ReadFile(knownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, knownHost := range svcCfg.KnownHosts {
		if strings.Contains(string(b), knownHost) {
			continue
		}

		zap.L().Debug("Setting SSH knownHost", zap.String("val", knownHost))

		if _, err = f.WriteString(fmt.Sprintf("\n%s\n", knownHost)); err != nil {
			return err
		}
	}

	return nil
}

func setServiceConfigSSHAuthorizedKeys(svcCfg *userv1.ConnectionState_ServiceConfig_SSH, authorizedKeysPath string) error {

	f, err := os.OpenFile(authorizedKeysPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, ak := range svcCfg.AuthorizedKeys {
		if strings.Contains(string(b), ak) {
			continue
		}

		zap.L().Debug("Setting SSH authorizedKey", zap.String("val", ak))

		if _, err = f.WriteString(fmt.Sprintf("\n%s\n", ak)); err != nil {
			return err
		}
	}

	return nil
}
