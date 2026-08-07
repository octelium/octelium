//go:build !windows
// +build !windows

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
	"os"
	"path"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func getFileOwner(t *testing.T, filePath string) (uint32, uint32) {
	fi, err := os.Stat(filePath)
	assert.Nil(t, err)

	st, ok := fi.Sys().(*syscall.Stat_t)
	assert.True(t, ok)

	return st.Uid, st.Gid
}

func TestServiceConfigSSHFileOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to change file ownership")
	}

	const usrUID, usrGID = 1000, 1000

	homeDir := t.TempDir()
	t.Setenv("OCTELIUM_USER_HOME", homeDir)

	sshDir := path.Join(homeDir, ".ssh")
	assert.Nil(t, os.MkdirAll(sshDir, 0700))
	assert.Nil(t, os.Chown(sshDir, usrUID, usrGID))

	c := newTestSSHCtlForDomain("example.com")

	assert.Nil(t, c.setServiceConfigs())

	for _, name := range []string{"authorized_keys", "known_hosts"} {
		uid, gid := getFileOwner(t, path.Join(sshDir, name))
		assert.Equal(t, uint32(usrUID), uid)
		assert.Equal(t, uint32(usrGID), gid)
	}

	assert.Nil(t, c.unsetServiceConfigs())

	for _, name := range []string{"authorized_keys", "known_hosts"} {
		uid, gid := getFileOwner(t, path.Join(sshDir, name))
		assert.Equal(t, uint32(usrUID), uid)
		assert.Equal(t, uint32(usrGID), gid)
	}
}
