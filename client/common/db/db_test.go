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

package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLockRefresh(t *testing.T) {
	for _, dbPath := range []string{"mem", t.TempDir()} {
		dbC, err := Open(dbPath)
		assert.Nil(t, err)

		unlock, err := dbC.LockRefresh(context.Background())
		assert.Nil(t, err)

		{
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_, err := dbC.LockRefresh(ctx)
			cancel()
			assert.ErrorIs(t, err, context.DeadlineExceeded)
		}

		lockedCh := make(chan func())
		go func() {
			unlock, err := dbC.LockRefresh(context.Background())
			assert.Nil(t, err)
			lockedCh <- unlock
		}()

		select {
		case <-lockedCh:
			t.Fatal("The refresh lock was acquired while it was held")
		case <-time.After(100 * time.Millisecond):
		}

		unlock()

		select {
		case unlock := <-lockedCh:
			unlock()
		case <-time.After(5 * time.Second):
			t.Fatal("The refresh lock was not acquired after it was released")
		}

		unlock, err = dbC.LockRefresh(context.Background())
		assert.Nil(t, err)
		unlock()

		assert.Nil(t, dbC.Close())
	}
}
