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
	"bytes"
	"crypto/sha256"
	stderrors "errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
)

func ReconcileConnectionCleanup(dbC *db.DB, domain string) {
	if dbC == nil || domain == "" {
		return
	}

	getCleanupStore(dbC).reconcile(domain)
}

func ListConnectionCleanupDomains(dbC *db.DB) []string {
	if dbC == nil {
		return nil
	}

	return getCleanupStore(dbC).listDomains()
}

func reconcileConnectionCleanup(dbC *db.DB, domain string, isPrivileged bool) {
	if dbC == nil || domain == "" {
		return
	}

	cleanup, err := dbC.GetConnectionCleanup(domain)
	if err != nil {
		if !dbC.ErrorIsNotFound(err) {
			zap.L().Warn("Could not read the previous connection cleanup state", zap.Error(err))
		}
		return
	}

	if pidStr := cleanup.GetMetadata()["pid"]; pidStr != "" {
		if pid, err := strconv.Atoi(pidStr); err == nil && pid != os.Getpid() && cleanupOwnerRunning(pid) {
			zap.L().Warn("The previous connection cleanup state belongs to a running process",
				zap.Int("pid", pid))
			return
		}
	}

	if isPrivileged {
		sanitizeConnectionCleanup(cleanup, domain)
	}

	cleanup.Phase = cliconfigv1.ConnectionCleanup_CLEANING
	if err := dbC.SetConnectionCleanup(domain, cleanup); err != nil {
		zap.L().Warn("Could not update the previous connection cleanup state", zap.Error(err))
	}

	var retErr error
	if err := reconcilePlatformCleanup(cleanup); err != nil {
		retErr = stderrors.Join(retErr, err)
	}
	if err := reconcileSSHCleanup(cleanup.GetSsh()); err != nil {
		retErr = stderrors.Join(retErr, err)
	}
	if retErr != nil {
		zap.L().Warn("Could not fully reconcile the previous connection cleanup state",
			zap.Error(retErr))
		return
	}

	if err := dbC.DeleteConnectionCleanup(domain); err != nil {
		zap.L().Warn("Could not delete the reconciled connection cleanup state", zap.Error(err))
	}
}

func (c *Controller) ReconcileCleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isClosed || c.closeErr == nil {
		return
	}

	zap.L().Debug("Reconciling the connection cleanup state after an incomplete close")
	if domain := c.cleanupDomain(); domain != "" {
		c.getCleanupStore().reconcile(domain)
	}
	c.releaseResolvConfLock()
}

func (c *Controller) getCleanupStore() *cleanupStore {
	if c.cleanupStore == nil {
		c.cleanupStore = getCleanupStore(c.dbC)
	}

	return c.cleanupStore
}

func (c *Controller) cleanupDomain() string {
	if c.c.GetInfo().GetCluster() == nil {
		return ""
	}
	return c.c.GetInfo().GetCluster().GetDomain()
}

func (c *Controller) prepareCleanup() {
	domain := c.cleanupDomain()
	if domain == "" {
		return
	}
	dbC := c.getCleanupStore().dbC
	if dbC == nil {
		return
	}
	if cleanup, err := dbC.GetConnectionCleanup(domain); err == nil && cleanup != nil {
		zap.L().Warn("A previous connection cleanup state is still pending")
		return
	} else if err != nil && !dbC.ErrorIsNotFound(err) {
		zap.L().Warn("Could not check the connection cleanup state", zap.Error(err))
		return
	}

	c.cleanup = &cliconfigv1.ConnectionCleanup{
		Id:        utilrand.GetRandomString(32),
		CreatedAt: pbutils.Now(),
		Phase:     cliconfigv1.ConnectionCleanup_PREPARED,
		Metadata: map[string]string{
			"pid": strconv.Itoa(os.Getpid()),
		},
	}
	if err := dbC.SetConnectionCleanup(domain, c.cleanup); err != nil {
		zap.L().Warn("Could not persist the connection cleanup state", zap.Error(err))
		c.cleanup = nil
	}
}

func (c *Controller) updateCleanup(fn func(*cliconfigv1.ConnectionCleanup)) {
	if c.cleanup == nil || c.getCleanupStore().dbC == nil {
		return
	}
	fn(c.cleanup)
	if err := c.cleanupStore.dbC.SetConnectionCleanup(c.cleanupDomain(), c.cleanup); err != nil {
		zap.L().Warn("Could not update the connection cleanup state", zap.Error(err))
	}
}

func (c *Controller) setCleanupPhase(phase cliconfigv1.ConnectionCleanup_Phase) {
	c.updateCleanup(func(cleanup *cliconfigv1.ConnectionCleanup) {
		cleanup.Phase = phase
	})
}

func (c *Controller) deleteCleanup() {
	if c.cleanup == nil || c.getCleanupStore().dbC == nil {
		return
	}
	if err := c.cleanupStore.dbC.DeleteConnectionCleanup(c.cleanupDomain()); err != nil {
		zap.L().Warn("Could not delete the connection cleanup state", zap.Error(err))
		return
	}
	c.cleanup = nil
}

func (c *Controller) setCleanupResolvConf(installed []byte) {
	c.updateCleanup(func(cleanup *cliconfigv1.ConnectionCleanup) {
		hash := sha256.Sum256(installed)
		cleanup.Dns = &cliconfigv1.ConnectionCleanup_DNS{
			Config: &cliconfigv1.ConnectionCleanup_DNS_ResolvConf_{
				ResolvConf: &cliconfigv1.ConnectionCleanup_DNS_ResolvConf{
					Path:          c.resolvConf.getPath(),
					Existed:       c.resolvConf.existed,
					IsSymlink:     c.resolvConf.isSymlink,
					LinkTarget:    c.resolvConf.linkTarget,
					Mode:          uint32(c.resolvConf.mode),
					Content:       c.resolvConf.content,
					InstalledHash: hash[:],
				},
			},
		}
	})
}

func restoreCleanupResolvConf(cfg *cliconfigv1.ConnectionCleanup_DNS_ResolvConf) error {
	if cfg == nil || cfg.Path == "" {
		return nil
	}

	content, err := os.ReadFile(cfg.Path)
	if err == nil {
		hash := sha256.Sum256(content)
		if len(cfg.InstalledHash) == 0 || !bytes.Equal(hash[:], cfg.InstalledHash) {
			zap.L().Warn("The current resolver configuration is not the version written by Octelium. Skipping its restoration",
				zap.String("path", cfg.Path))
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if !cfg.Existed {
		if err := os.Remove(cfg.Path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if cfg.IsSymlink {
		return replaceResolvConfSymlink(cfg.Path, cfg.LinkTarget)
	}
	return writeResolvConfInPlace(cfg.Path, cfg.Content, os.FileMode(cfg.Mode))
}

func (c *Controller) setCleanupSSH(marker string, paths []string) {
	c.updateCleanup(func(cleanup *cliconfigv1.ConnectionCleanup) {
		cleanup.Ssh = &cliconfigv1.ConnectionCleanup_SSH{
			Marker:    marker,
			FilePaths: paths,
		}
	})
}

func reconcileSSHCleanup(cfg *cliconfigv1.ConnectionCleanup_SSH) error {
	if cfg == nil || cfg.Marker == "" || len(cfg.FilePaths) == 0 {
		return nil
	}
	lock := waitFileLock(sshConfigLockName)
	defer releaseFileLock(lock)

	var retErr error
	for _, filePath := range cfg.FilePaths {
		if err := removeManagedLines(filePath, cfg.Marker); err != nil {
			retErr = stderrors.Join(retErr, err)
		}
	}
	return retErr
}

func sanitizeConnectionCleanup(cleanup *cliconfigv1.ConnectionCleanup, domain string) {
	if cfg := cleanup.GetDns().GetResolvConf(); cfg != nil {
		if cfg.Path != resolvConfPath || (cfg.IsSymlink && cfg.LinkTarget == "") {
			zap.L().Warn("Ignoring an invalid resolv.conf in the connection cleanup state",
				zap.String("path", cfg.Path))
			cleanup.Dns = nil
		} else {
			cfg.Mode = uint32(os.FileMode(cfg.Mode).Perm() &^ 0o022)
		}
	}

	if cfg := cleanup.GetDns().GetSystemdResolved(); cfg != nil && !isCleanupDeviceName(cfg.DeviceName) {
		zap.L().Warn("Ignoring an invalid systemd-resolved device in the connection cleanup state",
			zap.String("device", cfg.DeviceName))
		cleanup.Dns = nil
	}

	if cfg := cleanup.GetDns().GetMacos(); cfg != nil && cfg.ScutilKey != "" &&
		!scutilCleanupKeyRegex.MatchString(cfg.ScutilKey) {
		zap.L().Warn("Ignoring an invalid scutil key in the connection cleanup state",
			zap.String("key", cfg.ScutilKey))
		cfg.ScutilKey = ""
	}

	if cfg := cleanup.GetDns().GetWindows(); cfg != nil {
		if rulePath, err := getNRPTRuleLocalPath(domain); err != nil ||
			cfg.NrptRulePath != rulePath || cfg.NrptMarker != managedMarkerPrefix+domain {
			zap.L().Warn("Ignoring an invalid NRPT rule in the connection cleanup state",
				zap.String("path", cfg.NrptRulePath))
			cleanup.Dns = nil
		}
	}

	if cfg := cleanup.GetDevice(); cfg != nil && !isCleanupDeviceName(cfg.Name) {
		zap.L().Warn("Ignoring an invalid device in the connection cleanup state",
			zap.String("device", cfg.Name))
		cleanup.Device = nil
	}

	if cfg := cleanup.GetSsh(); cfg != nil {
		if cfg.Marker != managedMarkerPrefix+domain {
			zap.L().Warn("Ignoring an invalid SSH marker in the connection cleanup state",
				zap.String("marker", cfg.Marker))
			cleanup.Ssh = nil
		} else {
			cfg.FilePaths = slices.DeleteFunc(cfg.FilePaths, func(filePath string) bool {
				if isSSHCleanupPath(filePath) {
					return false
				}
				zap.L().Warn("Ignoring an invalid SSH file in the connection cleanup state",
					zap.String("filePath", filePath))
				return true
			})
		}
	}
}

var scutilCleanupKeyRegex = regexp.MustCompile(`^State:/Network/Service/octelium-[A-Za-z0-9-]+/DNS$`)

func isCleanupDeviceName(name string) bool {
	return strings.HasPrefix(name, "octelium")
}

func isSSHCleanupPath(filePath string) bool {
	switch filepath.Base(filePath) {
	case "known_hosts", "authorized_keys":
		return filepath.IsAbs(filePath) && filepath.Base(filepath.Dir(filePath)) == ".ssh"
	default:
		return false
	}
}
