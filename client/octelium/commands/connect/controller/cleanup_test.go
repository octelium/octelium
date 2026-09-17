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
	"os"
	"path/filepath"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/client/common/db"
	"github.com/stretchr/testify/assert"
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
