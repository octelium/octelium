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
	"path/filepath"

	"github.com/gofrs/flock"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var errLockBusy = errors.Errorf("The lock is held by another process")

func getLockDirs() []string {
	var ret []string
	if !cliutils.IsWindows() {
		ret = append(ret, filepath.Join("/run", "octelium"))
	}

	return append(ret, filepath.Join(os.TempDir(), "octelium"))
}

func acquireFileLock(name string) (*flock.Flock, error) {
	for _, dir := range getLockDirs() {
		if err := os.MkdirAll(dir, 0755); err != nil {
			continue
		}

		lock := flock.New(filepath.Join(dir, name), flock.SetPermissions(0644))

		locked, err := lock.TryLock()
		if err != nil {
			zap.L().Debug("Could not try to acquire the lock file",
				zap.String("path", lock.Path()), zap.Error(err))
			continue
		}

		if !locked {
			return nil, errLockBusy
		}

		return lock, nil
	}

	zap.L().Debug("Could not create a lock file. Proceeding without a lock",
		zap.String("name", name))

	return nil, nil
}

func releaseFileLock(lock *flock.Flock) {
	if lock == nil {
		return
	}

	if err := lock.Close(); err != nil {
		zap.L().Debug("Could not release the lock file",
			zap.String("path", lock.Path()), zap.Error(err))
	}
}
