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
	"strconv"

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

func (c *Controller) cleanupDomain() string {
	if c.c.GetInfo().GetCluster() == nil {
		return ""
	}
	return c.c.GetInfo().GetCluster().GetDomain()
}

func (c *Controller) prepareCleanup() {
	if c.dbC == nil {
		return
	}
	domain := c.cleanupDomain()
	if domain == "" {
		return
	}
	if cleanup, err := c.dbC.GetConnectionCleanup(domain); err == nil && cleanup != nil {
		zap.L().Warn("A previous connection cleanup state is still pending")
		return
	} else if err != nil && !c.dbC.ErrorIsNotFound(err) {
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
	if err := c.dbC.SetConnectionCleanup(domain, c.cleanup); err != nil {
		zap.L().Warn("Could not persist the connection cleanup state", zap.Error(err))
		c.cleanup = nil
	}
}

func (c *Controller) updateCleanup(fn func(*cliconfigv1.ConnectionCleanup)) {
	if c.cleanup == nil || c.dbC == nil {
		return
	}
	fn(c.cleanup)
	if err := c.dbC.SetConnectionCleanup(c.cleanupDomain(), c.cleanup); err != nil {
		zap.L().Warn("Could not update the connection cleanup state", zap.Error(err))
	}
}

func (c *Controller) setCleanupPhase(phase cliconfigv1.ConnectionCleanup_Phase) {
	c.updateCleanup(func(cleanup *cliconfigv1.ConnectionCleanup) {
		cleanup.Phase = phase
	})
}

func (c *Controller) deleteCleanup() {
	if c.cleanup == nil || c.dbC == nil {
		return
	}
	if err := c.dbC.DeleteConnectionCleanup(c.cleanupDomain()); err != nil {
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
	lock, err := acquireFileLock(sshConfigLockName)
	if err != nil {
		return err
	}
	defer releaseFileLock(lock)

	var retErr error
	for _, filePath := range cfg.FilePaths {
		if err := removeManagedLines(filePath, cfg.Marker); err != nil {
			retErr = stderrors.Join(retErr, err)
		}
	}
	return retErr
}
