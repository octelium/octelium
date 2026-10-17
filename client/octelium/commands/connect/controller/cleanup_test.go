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
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestRestoreCleanupResolvConf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	original := []byte("nameserver 1.1.1.1\n")
	installed := []byte("nameserver 100.64.0.53\n")
	assert.Nil(t, os.WriteFile(path, installed, 0644))
	hash := sha256.Sum256(installed)

	assert.Nil(t, restoreCleanupResolvConf(&cliconfigv1.ConnectionCleanup_DNS_ResolvConf{
		Path:          path,
		Existed:       true,
		Mode:          0644,
		Content:       original,
		InstalledHash: hash[:],
	}))
	b, err := os.ReadFile(path)
	assert.Nil(t, err)
	assert.Equal(t, original, b)
}

func TestRestoreCleanupResolvConfDoesNotOverwriteChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	installed := []byte("nameserver 100.64.0.53\n")
	current := []byte("nameserver 9.9.9.9\n")
	assert.Nil(t, os.WriteFile(path, current, 0644))
	hash := sha256.Sum256(installed)

	assert.Nil(t, restoreCleanupResolvConf(&cliconfigv1.ConnectionCleanup_DNS_ResolvConf{
		Path:          path,
		Existed:       true,
		Mode:          0644,
		Content:       []byte("nameserver 1.1.1.1\n"),
		InstalledHash: hash[:],
	}))
	b, err := os.ReadFile(path)
	assert.Nil(t, err)
	assert.Equal(t, current, b)
}

func TestReconcileConnectionCleanupDeletesCompletedState(t *testing.T) {
	dbC, err := db.Open("memory")
	assert.Nil(t, err)
	domain := "example.com"
	assert.Nil(t, dbC.SetConnectionCleanup(domain, &cliconfigv1.ConnectionCleanup{
		Id: "cleanup-id",
	}))

	ReconcileConnectionCleanup(dbC, domain)
	_, err = dbC.GetConnectionCleanup(domain)
	assert.True(t, dbC.ErrorIsNotFound(err))
}

func TestRestoreCleanupResolvConfMissingFiles(t *testing.T) {
	for _, originalExisted := range []bool{false, true} {
		for _, installedExists := range []bool{false, true} {
			t.Run(fmt.Sprintf("original-%t-installed-%t", originalExisted, installedExists), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "resolv.conf")
				original := []byte("nameserver 192.0.2.53\n")
				installed := []byte("nameserver fd00::53\n")
				hash := sha256.Sum256(installed)
				if installedExists {
					assert.Nil(t, os.WriteFile(path, installed, 0600))
				}
				assert.Nil(t, restoreCleanupResolvConf(&cliconfigv1.ConnectionCleanup_DNS_ResolvConf{
					Path: path, Existed: originalExisted, Content: original, Mode: 0600, InstalledHash: hash[:],
				}))
				content, err := os.ReadFile(path)
				if originalExisted {
					assert.Nil(t, err)
					assert.Equal(t, original, content)
				} else {
					assert.True(t, os.IsNotExist(err))
				}
			})
		}
	}
}

func TestRestoreCleanupResolvConfWithoutOwnershipHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	current := []byte("nameserver 192.0.2.53\n")
	assert.Nil(t, os.WriteFile(path, current, 0600))
	assert.Nil(t, restoreCleanupResolvConf(&cliconfigv1.ConnectionCleanup_DNS_ResolvConf{
		Path: path, Existed: true, Content: []byte("nameserver fd00::53\n"),
	}))
	content, err := os.ReadFile(path)
	assert.Nil(t, err)
	assert.Equal(t, current, content)
	assert.Nil(t, restoreCleanupResolvConf(nil))
	assert.Nil(t, restoreCleanupResolvConf(&cliconfigv1.ConnectionCleanup_DNS_ResolvConf{}))
	assert.NotNil(t, restoreCleanupResolvConf(&cliconfigv1.ConnectionCleanup_DNS_ResolvConf{Path: t.TempDir()}))
}

func TestControllerPrepareCleanupPreservesPendingJournal(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	dbC, err := db.Open("memory")
	if !assert.Nil(t, err) {
		return
	}
	t.Cleanup(func() { assert.Nil(t, dbC.Close()) })
	c.dbC = dbC
	pending := &cliconfigv1.ConnectionCleanup{
		Id: "pending-cleanup", Phase: cliconfigv1.ConnectionCleanup_CLEANING,
		Metadata: map[string]string{"pid": "123"},
	}
	assert.Nil(t, dbC.SetConnectionCleanup("example.com", pending))
	c.prepareCleanup()
	assert.Nil(t, c.cleanup)
	saved, err := dbC.GetConnectionCleanup("example.com")
	assert.Nil(t, err)
	assert.True(t, proto.Equal(pending, saved))
}

func TestControllerResolvConfCleanupJournalTracksUpdates(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	dbC, err := db.Open("memory")
	if !assert.Nil(t, err) {
		return
	}
	t.Cleanup(func() { assert.Nil(t, dbC.Close()) })
	c.dbC = dbC
	original := []byte("nameserver 192.0.2.53\n")
	assert.Nil(t, os.WriteFile(c.resolvConf.path, original, 0600))
	c.prepareCleanup()
	for _, servers := range [][]string{{"100.64.0.53"}, {"fd00::53"}} {
		c.c.Connection.Dns.Servers = servers
		assert.Nil(t, c.setResolvConf())
		installed, err := os.ReadFile(c.resolvConf.path)
		assert.Nil(t, err)
		hash := sha256.Sum256(installed)
		cleanup, err := dbC.GetConnectionCleanup("example.com")
		if !assert.Nil(t, err) {
			return
		}
		cfg := cleanup.GetDns().GetResolvConf()
		if assert.NotNil(t, cfg) {
			assert.Equal(t, c.resolvConf.path, cfg.Path)
			assert.True(t, cfg.Existed)
			assert.False(t, cfg.IsSymlink)
			assert.Equal(t, original, cfg.Content)
			assert.Equal(t, hash[:], cfg.InstalledHash)
		}
	}
	assert.Nil(t, c.unsetResolvConf())
}
