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
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/cliutils/vhome"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const managedMarkerPrefix = "octelium-managed:"

const sshConfigLockName = "sshconfig.lock"

func (c *Controller) setServiceConfigs() error {
	for _, svcCfg := range c.c.Connection.ServiceConfigs {
		switch svcCfg.Type.(type) {
		case *userv1.ConnectionState_ServiceConfig_Ssh:
			if err := c.setServiceConfigSSH(svcCfg.GetSsh()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Controller) unsetServiceConfigs() error {
	return c.unsetServiceConfigSSH()
}

func (c *Controller) getManagedMarker() (string, error) {
	if c.c.Info == nil || c.c.Info.Cluster == nil {
		return "", errors.Errorf("The Connection does not have Cluster info")
	}

	domain := c.c.Info.Cluster.Domain
	if domain == "" || strings.ContainsAny(domain, " \t\r\n") {
		return "", errors.Errorf("Invalid Cluster domain: %q", domain)
	}

	return fmt.Sprintf("%s%s", managedMarkerPrefix, domain), nil
}

func (c *Controller) setServiceConfigSSH(svcCfg *userv1.ConnectionState_ServiceConfig_SSH) error {
	if svcCfg == nil {
		return nil
	}

	marker, err := c.getManagedMarker()
	if err != nil {
		zap.L().Warn("Could not set the SSH service configs", zap.Error(err))
		return nil
	}

	sshDir, err := getSSHDir()
	if err != nil {
		return err
	}
	if sshDir == "" {
		return nil
	}

	lock, err := acquireFileLock(sshConfigLockName)
	if err != nil {
		zap.L().Warn("Could not acquire the SSH config lock. Skipping the SSH service configs",
			zap.Error(err))
		return nil
	}
	defer releaseFileLock(lock)

	zap.L().Debug("Setting SSH service configs", zap.String("sshDir", sshDir))

	knownHostsPath := filepath.Join(sshDir, "known_hosts")
	if err := addManagedLines(knownHostsPath, sshDir, marker, svcCfg.KnownHosts); err != nil {
		zap.L().Warn("Could not set the Cluster CA in the known_hosts file",
			zap.String("filePath", knownHostsPath), zap.Error(err))
	}

	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	if err := addManagedLines(authorizedKeysPath, sshDir, marker, svcCfg.AuthorizedKeys); err != nil {
		zap.L().Warn("Could not set the Cluster CA in the authorized keys file",
			zap.String("filePath", authorizedKeysPath), zap.Error(err))
	}

	return nil
}

func (c *Controller) unsetServiceConfigSSH() error {
	marker, err := c.getManagedMarker()
	if err != nil {
		zap.L().Debug("Could not unset the SSH service configs", zap.Error(err))
		return nil
	}

	sshDir, err := getSSHDir()
	if err != nil {
		return err
	}
	if sshDir == "" {
		return nil
	}

	lock, err := acquireFileLock(sshConfigLockName)
	if err != nil {
		zap.L().Debug("Could not acquire the SSH config lock. Skipping the SSH config cleanup",
			zap.Error(err))
		return nil
	}
	defer releaseFileLock(lock)

	zap.L().Debug("Unsetting SSH service configs", zap.String("sshDir", sshDir))

	for _, filePath := range []string{
		filepath.Join(sshDir, "known_hosts"),
		filepath.Join(sshDir, "authorized_keys"),
	} {
		if err := removeManagedLines(filePath, marker); err != nil {
			zap.L().Debug("Could not remove the Cluster CA",
				zap.String("filePath", filePath), zap.Error(err))
		}
	}

	return nil
}

func getSSHDir() (string, error) {
	homeDir, err := vhome.GetOcteliumUserHome()
	if err != nil {
		return "", err
	}
	if homeDir == "" {
		return "", errors.Errorf("Could not determine the User home directory")
	}

	sshDir := filepath.Join(homeDir, ".ssh")

	if _, err := os.Stat(sshDir); err != nil {
		if os.IsNotExist(err) {
			zap.L().Debug("No SSH dir. No config needs to be set...",
				zap.String("path", sshDir))
		} else {
			zap.L().Debug("Could not check for SSH dir", zap.Error(err))
		}
		return "", nil
	}

	return sshDir, nil
}

func isManagedLine(line, marker string) bool {
	return strings.HasSuffix(strings.TrimRight(line, " \t\r"), fmt.Sprintf(" %s", marker))
}

func addManagedLines(filePath, sshDir, marker string, lines []string) error {
	var entries []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.ContainsAny(line, "\r\n") {
			return errors.Errorf("Refusing to write an SSH config entry spanning multiple lines")
		}

		entries = append(entries, line)
	}
	if len(entries) == 0 {
		return nil
	}

	content, err := os.ReadFile(filePath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	fileExisted := err == nil

	existing := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if idx := strings.LastIndex(line, " "+managedMarkerPrefix); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		existing[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	var pending []string
	for _, entry := range entries {
		if _, ok := existing[entry]; ok {
			continue
		}
		pending = append(pending, fmt.Sprintf("%s %s", entry, marker))
	}
	if len(pending) == 0 {
		return nil
	}

	var buf bytes.Buffer
	if len(content) > 0 && !bytes.HasSuffix(content, []byte("\n")) {
		buf.WriteString("\n")
	}
	for _, line := range pending {
		zap.L().Debug("Setting SSH config entry",
			zap.String("filePath", filePath), zap.String("val", line))
		buf.WriteString(line)
		buf.WriteString("\n")
	}

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	if !fileExisted {
		if fi, err := os.Stat(sshDir); err == nil {
			if err := setFileOwner(filePath, fi); err != nil {
				zap.L().Debug("Could not set the SSH config file owner",
					zap.String("filePath", filePath), zap.Error(err))
			}
		}
	}

	return nil
}

func removeManagedLines(filePath, marker string) error {
	fi, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	var removed int

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if isManagedLine(line, marker) {
			removed++
			continue
		}
		buf.WriteString(line)
		buf.WriteString("\n")
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if removed == 0 {
		return nil
	}

	zap.L().Debug("Removing SSH config entries",
		zap.String("filePath", filePath), zap.Int("entries", removed))

	return writeFileAtomic(filePath, buf.Bytes(), fi)
}

func writeFileAtomic(filePath string, content []byte, fi os.FileInfo) error {
	if resolved, err := filepath.EvalSymlinks(filePath); err == nil && resolved != filePath {
		zap.L().Debug("Following the symlink of the SSH config file",
			zap.String("filePath", filePath), zap.String("resolved", resolved))
		filePath = resolved
	}

	f, err := os.CreateTemp(filepath.Dir(filePath), fmt.Sprintf("%s.octelium-*", filepath.Base(filePath)))
	if err != nil {
		return err
	}
	tmpPath := f.Name()

	cleanup := func() {
		f.Close()
		os.Remove(tmpPath)
	}

	if _, err := f.Write(content); err != nil {
		cleanup()
		return err
	}

	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := os.Chmod(tmpPath, fi.Mode().Perm()); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := setFileOwner(tmpPath, fi); err != nil {
		zap.L().Debug("Could not set the SSH config file owner",
			zap.String("filePath", tmpPath), zap.Error(err))
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return nil
}
