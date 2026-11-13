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

package ipc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasLoginSession(t *testing.T) {
	ctx := context.Background()

	{
		info, err := os.Stat(consolePath)
		require.NoError(t, err)
		owner := fmt.Sprintf("%d", info.Sys().(*syscall.Stat_t).Uid)

		ret, err := HasLoginSession(ctx, &Principal{
			ID: owner,
		})
		assert.Nil(t, err)
		assert.True(t, ret)
	}

	prev := consolePath
	t.Cleanup(func() {
		consolePath = prev
	})

	consolePath = filepath.Join(t.TempDir(), "console")
	require.NoError(t, os.WriteFile(consolePath, nil, 0600))

	{
		ret, err := HasLoginSession(ctx, &Principal{
			ID: fmt.Sprintf("%d", os.Getuid()),
		})
		assert.Nil(t, err)
		assert.True(t, ret)
	}

	{
		ret, err := HasLoginSession(ctx, &Principal{
			ID: fmt.Sprintf("%d", os.Getuid()+1),
		})
		assert.Nil(t, err)
		assert.False(t, ret)
	}

	{
		ret, err := HasLoginSession(ctx, &Principal{
			ID: "",
		})
		assert.Nil(t, err)
		assert.False(t, ret)
	}

	consolePath = filepath.Join(t.TempDir(), "missing")

	{
		_, err := HasLoginSession(ctx, &Principal{
			ID: fmt.Sprintf("%d", os.Getuid()),
		})
		assert.NotNil(t, err)
	}
}
