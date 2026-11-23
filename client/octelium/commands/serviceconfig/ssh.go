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

package serviceconfig

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/cliutils/vhome"
	"github.com/octelium/octelium/client/octelium/commands/connect/controller"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	sshFormatKnownHosts     = "known-hosts"
	sshFormatAuthorizedKeys = "authorized-keys"
	sshFormatCAPublicKey    = "ca-public-key"
)

type sshConfigFile struct {
	name  string
	lines []string
}

func getSSHConfigFiles(cfg *userv1.SetServiceConfigsResponse_Config_SSH) []sshConfigFile {
	return []sshConfigFile{
		{name: "known_hosts", lines: cfg.KnownHosts},
		{name: "authorized_keys", lines: cfg.AuthorizedKeys},
	}
}

func validateSSHFormat(format string) error {
	switch format {
	case sshFormatKnownHosts, sshFormatAuthorizedKeys, sshFormatCAPublicKey:
		return nil
	default:
		return errors.Errorf("Invalid SSH format: %s. It must be either `%s`, `%s` or `%s`",
			format, sshFormatKnownHosts, sshFormatAuthorizedKeys, sshFormatCAPublicKey)
	}
}

func getSSHConfigs(resp *userv1.SetServiceConfigsResponse) []*userv1.SetServiceConfigsResponse_Config_SSH {
	var ret []*userv1.SetServiceConfigsResponse_Config_SSH
	for _, cfg := range resp.Configs {
		if sshCfg := cfg.GetSsh(); sshCfg != nil {
			ret = append(ret, sshCfg)
		}
	}

	return ret
}

func getSSHCAPublicKeys(cfg *userv1.SetServiceConfigsResponse_Config_SSH) ([]ssh.PublicKey, error) {
	var ret []ssh.PublicKey

	add := func(key ssh.PublicKey) {
		if !slices.ContainsFunc(ret, func(k ssh.PublicKey) bool {
			return bytes.Equal(k.Marshal(), key.Marshal())
		}) {
			ret = append(ret, key)
		}
	}

	for _, line := range cfg.KnownHosts {
		marker, _, key, _, _, err := ssh.ParseKnownHosts([]byte(line))
		if err != nil {
			return nil, errors.Errorf("Could not parse the known_hosts entry %q: %+v", line, err)
		}
		if marker == "cert-authority" {
			add(key)
		}
	}

	for _, line := range cfg.AuthorizedKeys {
		key, _, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, errors.Errorf("Could not parse the authorized_keys entry %q: %+v", line, err)
		}
		if slices.ContainsFunc(options, func(option string) bool {
			return strings.EqualFold(option, "cert-authority")
		}) {
			add(key)
		}
	}

	return ret, nil
}

func getSSHConfigLines(cfg *userv1.SetServiceConfigsResponse_Config_SSH, format string) ([]string, error) {
	switch format {
	case sshFormatKnownHosts:
		return cfg.KnownHosts, nil
	case sshFormatAuthorizedKeys:
		return cfg.AuthorizedKeys, nil
	case sshFormatCAPublicKey:
		keys, err := getSSHCAPublicKeys(cfg)
		if err != nil {
			return nil, err
		}

		var ret []string
		for _, key := range keys {
			ret = append(ret, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
		}

		return ret, nil
	default:
		return nil, validateSSHFormat(format)
	}
}

func printSSHConfig(w io.Writer, cfg *userv1.SetServiceConfigsResponse_Config_SSH) error {
	for _, file := range getSSHConfigFiles(cfg) {
		if len(file.lines) == 0 {
			continue
		}

		if _, err := fmt.Fprintf(w, "# %s\n", file.name); err != nil {
			return err
		}

		for _, line := range file.lines {
			if _, err := fmt.Fprintf(w, "%s\n", line); err != nil {
				return err
			}
		}
	}

	return nil
}

func printSSHConfigs(w io.Writer, resp *userv1.SetServiceConfigsResponse, format string) error {
	sshCfgs := getSSHConfigs(resp)
	if len(sshCfgs) == 0 {
		return errors.Errorf("The --ssh-format flag can only be used with SSH Services")
	}

	var lines []string
	for _, cfg := range sshCfgs {
		cfgLines, err := getSSHConfigLines(cfg, format)
		if err != nil {
			return err
		}

		for _, line := range cfgLines {
			if !slices.Contains(lines, line) {
				lines = append(lines, line)
			}
		}
	}

	if len(lines) == 0 {
		return errors.Errorf("The SSH configuration of this Service has no entries in the %s format", format)
	}

	for _, line := range lines {
		if _, err := fmt.Fprintf(w, "%s\n", line); err != nil {
			return err
		}
	}

	return nil
}

func setConfigSSH(cfg *userv1.SetServiceConfigsResponse_Config_SSH, domain string) error {
	homeDir, err := vhome.GetOcteliumUserHome()
	if err != nil {
		return err
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	if _, err := os.Stat(sshDir); err != nil {
		return errors.Errorf("Could not use the SSH directory %s: %+v. You can use the --print flag to print the SSH configuration instead",
			sshDir, err)
	}

	var applied int
	for _, file := range getSSHConfigFiles(cfg) {
		if len(file.lines) == 0 {
			continue
		}

		filePath := filepath.Join(sshDir, file.name)
		if err := controller.SetManagedSSHConfig(domain, filePath, file.lines); err != nil {
			return errors.Errorf("Could not set the SSH configuration in %s: %+v", filePath, err)
		}

		cliutils.LineInfo("Set the SSH configuration of the Service in %s\n", filePath)
		applied++
	}

	if applied == 0 {
		return nil
	}

	keys, err := getSSHCAPublicKeys(cfg)
	if err != nil {
		zap.L().Debug("Could not get the Cluster SSH CA public keys", zap.Error(err))
	}

	for _, key := range keys {
		cliutils.LineInfo("The SHA256 fingerprint of the Cluster SSH CA: %s\n", ssh.FingerprintSHA256(key))
	}

	cliutils.LineInfo("These entries are removed once the octelium client disconnects from the Cluster\n")

	return nil
}
