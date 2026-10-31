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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func holdTestFileLock(t *testing.T, dirs []string) func() {
	t.Helper()
	lock, err := doAcquireFileLock(dirs, "test.lock", 0)
	require.NoError(t, err)
	require.NotNil(t, lock)
	var once sync.Once
	release := func() {
		once.Do(func() { releaseFileLock(lock) })
	}
	t.Cleanup(release)
	return release
}

func TestFileLockWithoutTimeoutFailsFast(t *testing.T) {
	dirs := []string{t.TempDir()}
	holdTestFileLock(t, dirs)
	started := time.Now()
	lock, err := doAcquireFileLock(dirs, "test.lock", 0)
	assert.ErrorIs(t, err, errLockBusy)
	assert.Nil(t, lock)
	assert.Less(t, time.Since(started), time.Second)
}

func TestFileLockWaitsForBriefHolder(t *testing.T) {
	dirs := []string{t.TempDir()}
	release := holdTestFileLock(t, dirs)
	time.AfterFunc(200*time.Millisecond, release)
	started := time.Now()
	lock, err := doAcquireFileLock(dirs, "test.lock", 5*time.Second)
	require.NoError(t, err)
	require.NotNil(t, lock)
	assert.GreaterOrEqual(t, time.Since(started), 150*time.Millisecond)
	other, err := doAcquireFileLock(dirs, "test.lock", 0)
	assert.ErrorIs(t, err, errLockBusy, "the waiter must hold the lock exclusively")
	assert.Nil(t, other)
	releaseFileLock(lock)
	other, err = doAcquireFileLock(dirs, "test.lock", 0)
	require.NoError(t, err)
	assert.NotNil(t, other)
	releaseFileLock(other)
}

func TestFileLockWaitGivesUpOnStuckHolder(t *testing.T) {
	dirs := []string{t.TempDir()}
	holdTestFileLock(t, dirs)
	started := time.Now()
	lock, err := doAcquireFileLock(dirs, "test.lock", 300*time.Millisecond)
	assert.ErrorIs(t, err, errLockBusy)
	assert.Nil(t, lock)
	elapsed := time.Since(started)
	assert.GreaterOrEqual(t, elapsed, 300*time.Millisecond)
	assert.Less(t, elapsed, 3*time.Second)
}

func TestFileLockBusyDoesNotFallBackToAnotherDir(t *testing.T) {
	shared, private := t.TempDir(), t.TempDir()
	holdTestFileLock(t, []string{shared})
	lock, err := doAcquireFileLock([]string{shared, private}, "test.lock", 200*time.Millisecond)
	assert.ErrorIs(t, err, errLockBusy)
	assert.Nil(t, lock)
	_, err = os.Stat(filepath.Join(private, "test.lock"))
	assert.True(t, os.IsNotExist(err), "a busy lock must never be replaced by a lock that nobody else uses")
}

func TestFileLockFallsBackWhenDirIsUnusable(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocked, nil, 0600))
	private := t.TempDir()
	lock, err := doAcquireFileLock([]string{blocked, private}, "test.lock", time.Second)
	require.NoError(t, err)
	require.NotNil(t, lock)
	assert.Equal(t, filepath.Join(private, "test.lock"), lock.Path())
	releaseFileLock(lock)
	lock, err = doAcquireFileLock([]string{blocked}, "test.lock", time.Second)
	assert.NoError(t, err)
	assert.Nil(t, lock, "without a usable lock directory the caller proceeds without a lock")
}

func TestFileLockConcurrentWaitersAreMutuallyExclusive(t *testing.T) {
	dirs := []string{t.TempDir()}
	var inside, overlaps, acquired atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				lock, err := doAcquireFileLock(dirs, "test.lock", 10*time.Second)
				if !assert.NoError(t, err) || !assert.NotNil(t, lock) {
					return
				}
				if inside.Add(1) > 1 {
					overlaps.Add(1)
				}
				time.Sleep(time.Millisecond)
				inside.Add(-1)
				acquired.Add(1)
				releaseFileLock(lock)
			}
		}()
	}
	wg.Wait()
	assert.Zero(t, overlaps.Load(), "two holders of the same lock in one process must exclude each other")
	assert.Equal(t, int32(40), acquired.Load())
}
