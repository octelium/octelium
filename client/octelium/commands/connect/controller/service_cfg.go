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
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/cliutils/vhome"
	"github.com/octelium/octelium/client/octelium/internal/userexec"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const managedMarkerPrefix = "octelium-managed:"

const sshConfigLockName = "sshconfig.lock"

const sshConfigCmdName = "ssh-config"

const sshConfigCmdMaxInput = 1024 * 1024

const maxSSHTrustUsers = 32

var sshTrustUserRegex = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,255}$`)

func init() {
	userexec.Register(sshConfigCmdName, func(args []string) error {
		return runSSHConfigCmd(os.Stdin)
	})
}

type sshConfigOp struct {
	FilePath string   `json:"filePath"`
	Marker   string   `json:"marker"`
	Lines    []string `json:"lines,omitempty"`
	Remove   bool     `json:"remove,omitempty"`
}

func (o *sshConfigOp) run() error {
	if o.Remove {
		return removeManagedLines(o.FilePath, o.Marker)
	}

	return addManagedLines(o.FilePath, o.Marker, o.Lines)
}

func runSSHConfigCmd(r io.Reader) error {
	op := &sshConfigOp{}
	if err := json.NewDecoder(io.LimitReader(r, sshConfigCmdMaxInput)).Decode(op); err != nil {
		return err
	}

	if !isSSHCleanupPath(op.FilePath) {
		return errors.Errorf("Invalid SSH config file: %q", op.FilePath)
	}

	if !strings.HasPrefix(op.Marker, managedMarkerPrefix) || strings.ContainsAny(op.Marker, " \t\r\n") {
		return errors.Errorf("Invalid SSH config marker: %q", op.Marker)
	}

	return op.run()
}

func (c *Controller) setServiceConfigs() error {
	var hasSSH bool
	for _, svcCfg := range c.c.Connection.ServiceConfigs {
		switch svcCfg.Type.(type) {
		case *userv1.ConnectionState_ServiceConfig_Ssh:
			hasSSH = true
			if err := c.setServiceConfigSSH(svcCfg.GetSsh()); err != nil {
				return err
			}
		}
	}

	if !hasSSH && len(c.getSSHTrustUsers()) > 0 {
		cliutils.LineWarn("The Cluster did not provide its SSH CA. Could not trust it for the OS users: %s\n",
			strings.Join(c.getSSHTrustUsers(), ", "))
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

	return getManagedMarkerFromDomain(c.c.Info.Cluster.Domain)
}

func getManagedMarkerFromDomain(domain string) (string, error) {
	if domain == "" || strings.ContainsAny(domain, " \t\r\n") {
		return "", errors.Errorf("Invalid Cluster domain: %q", domain)
	}

	return fmt.Sprintf("%s%s", managedMarkerPrefix, domain), nil
}

func SetManagedSSHConfig(domain, filePath string, lines []string) error {
	marker, err := getManagedMarkerFromDomain(domain)
	if err != nil {
		return err
	}

	lock := waitFileLock(sshConfigLockName)
	defer releaseFileLock(lock)

	return doSSHConfigOp(&sshConfigOp{
		FilePath: filePath,
		Marker:   marker,
		Lines:    lines,
	})
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

	sshDir, err := c.getSSHDir()
	if err != nil {
		return err
	}

	var filePaths []string
	if sshDir != "" {
		filePaths = append(filePaths, filepath.Join(sshDir, "known_hosts"), filepath.Join(sshDir, "authorized_keys"))
	}

	var trustUserFiles []*sshTrustUserFile
	if len(svcCfg.AuthorizedKeys) > 0 {
		trustUserFiles = c.getSSHTrustUserFiles(filePaths)
	}

	c.sshTrustFilePaths = nil
	if len(filePaths) == 0 && len(trustUserFiles) == 0 {
		return nil
	}

	lock := waitFileLock(sshConfigLockName)
	defer releaseFileLock(lock)

	for _, itm := range trustUserFiles {
		c.sshTrustFilePaths = append(c.sshTrustFilePaths, itm.filePath)
	}
	c.setCleanupSSH(marker, slices.Concat(filePaths, c.sshTrustFilePaths))

	if sshDir != "" {
		zap.L().Debug("Setting SSH service configs", zap.String("sshDir", sshDir))

		knownHostsPath := filepath.Join(sshDir, "known_hosts")
		authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
		if err := doSSHConfigOp(&sshConfigOp{
			FilePath: knownHostsPath,
			Marker:   marker,
			Lines:    svcCfg.KnownHosts,
		}); err != nil {
			zap.L().Warn("Could not set the Cluster CA in the known_hosts file",
				zap.String("filePath", knownHostsPath), zap.Error(err))
		}

		if err := doSSHConfigOp(&sshConfigOp{
			FilePath: authorizedKeysPath,
			Marker:   marker,
			Lines:    svcCfg.AuthorizedKeys,
		}); err != nil {
			zap.L().Warn("Could not set the Cluster CA in the authorized keys file",
				zap.String("filePath", authorizedKeysPath), zap.Error(err))
		}
	}

	var failed bool
	for _, itm := range trustUserFiles {
		if err := doSSHConfigOp(&sshConfigOp{
			FilePath: itm.filePath,
			Marker:   marker,
			Lines:    svcCfg.AuthorizedKeys,
		}); err != nil {
			cliutils.LineWarn("Could not trust the Cluster SSH CA for the OS user %s in %s: %s\n",
				itm.user, itm.filePath, err)
			zap.L().Warn("Could not set the Cluster CA in the authorized keys file of an SSH trust user",
				zap.String("user", itm.user), zap.String("filePath", itm.filePath), zap.Error(err))
			c.sshTrustFilePaths = slices.DeleteFunc(c.sshTrustFilePaths, func(filePath string) bool {
				return filePath == itm.filePath
			})
			failed = true
			continue
		}

		cliutils.LineInfo("Trusted the Cluster SSH CA for the OS user %s in %s while connected\n",
			itm.user, itm.filePath)
	}

	if failed {
		c.setCleanupSSH(marker, slices.Concat(filePaths, c.sshTrustFilePaths))
	}

	return nil
}

type sshTrustUserFile struct {
	user     string
	filePath string
}

func (c *Controller) getSSHTrustUsers() []string {
	if !c.c.GetPreferences().GetServeOpts().GetIsEnabled() {
		return nil
	}

	return c.c.GetPreferences().GetServeOpts().GetSsh().GetTrustUsers()
}

func (c *Controller) getSSHTrustUserFiles(exclude []string) []*sshTrustUserFile {
	var ret []*sshTrustUserFile
	for _, name := range c.getSSHTrustUsers() {
		filePath, err := c.getSSHTrustUserFile(name)
		if err != nil {
			cliutils.LineWarn("Could not trust the Cluster SSH CA for the OS user %s: %s\n", name, err)
			zap.L().Warn("Could not find the authorized keys file of an SSH trust user",
				zap.String("user", name), zap.Error(err))
			continue
		}

		if slices.Contains(exclude, filePath) || slices.ContainsFunc(ret, func(itm *sshTrustUserFile) bool {
			return itm.filePath == filePath
		}) {
			zap.L().Debug("The authorized keys file of the SSH trust user is already managed",
				zap.String("user", name), zap.String("filePath", filePath))
			continue
		}

		ret = append(ret, &sshTrustUserFile{
			user:     name,
			filePath: filePath,
		})
	}

	return ret
}

func (c *Controller) getSSHTrustUserFile(name string) (string, error) {
	if !sshTrustUserRegex.MatchString(name) {
		return "", errors.Errorf("Invalid OS user name")
	}

	usr, err := c.lookupSSHTrustUser(name)
	if err != nil {
		if stderrors.As(err, new(user.UnknownUserError)) {
			return "", errors.Errorf("The OS user does not exist")
		}
		return "", errors.Errorf("Could not find the OS user: %+v", err)
	}

	if usr.HomeDir == "" || !filepath.IsAbs(usr.HomeDir) {
		return "", errors.Errorf("The OS user does not have a valid home directory: %q", usr.HomeDir)
	}

	sshDir := filepath.Join(usr.HomeDir, ".ssh")
	fi, err := os.Stat(sshDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", errors.Errorf("The SSH directory %s does not exist", sshDir)
		}
		return "", errors.Errorf("Could not access the SSH directory %s: %+v", sshDir, err)
	}
	if !fi.IsDir() {
		return "", errors.Errorf("The SSH directory %s is not a directory", sshDir)
	}

	return filepath.Join(sshDir, "authorized_keys"), nil
}

func (c *Controller) lookupSSHTrustUser(name string) (*user.User, error) {
	if c.lookupUser != nil {
		return c.lookupUser(name)
	}

	return user.Lookup(name)
}

func ValidateSSHTrustUsers(users []string) ([]string, error) {
	var ret []string
	for _, name := range users {
		name = strings.TrimSpace(name)
		if !sshTrustUserRegex.MatchString(name) {
			return nil, errors.Errorf("Invalid SSH trust user: %q", name)
		}
		if !slices.Contains(ret, name) {
			ret = append(ret, name)
		}
	}

	if len(ret) > maxSSHTrustUsers {
		return nil, errors.Errorf("Too many SSH trust users. The maximum is %d", maxSSHTrustUsers)
	}

	return ret, nil
}

func (c *Controller) unsetServiceConfigSSH() error {
	marker, err := c.getManagedMarker()
	if err != nil {
		zap.L().Debug("Could not unset the SSH service configs", zap.Error(err))
		return err
	}

	var retErr error
	var filePaths []string
	sshDir, err := c.getSSHDir()
	if err != nil {
		retErr = err
	} else if sshDir != "" {
		zap.L().Debug("Unsetting SSH service configs", zap.String("sshDir", sshDir))
		filePaths = append(filePaths, filepath.Join(sshDir, "known_hosts"), filepath.Join(sshDir, "authorized_keys"))
	}
	filePaths = append(filePaths, c.sshTrustFilePaths...)

	if len(filePaths) == 0 {
		return retErr
	}

	lock := waitFileLock(sshConfigLockName)
	defer releaseFileLock(lock)

	for _, filePath := range filePaths {
		if err := doSSHConfigOp(&sshConfigOp{
			FilePath: filePath,
			Marker:   marker,
			Remove:   true,
		}); err != nil {
			zap.L().Debug("Could not remove the Cluster CA",
				zap.String("filePath", filePath), zap.Error(err))
			retErr = stderrors.Join(retErr, err)
		}
	}

	return retErr
}

func (c *Controller) getSSHDir() (string, error) {
	homeDir, err := c.getUserHome()
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

func (c *Controller) getUserHome() (string, error) {
	if ret := c.c.GetPreferences().GetUserHome(); ret != "" {
		return ret, nil
	}

	return vhome.GetOcteliumUserHome()
}

func isManagedLine(line, marker string) bool {
	return strings.HasSuffix(strings.TrimRight(line, " \t\r"), fmt.Sprintf(" %s", marker))
}

func addManagedLines(filePath, marker string, lines []string) error {
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

	return f.Close()
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
