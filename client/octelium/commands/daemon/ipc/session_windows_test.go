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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func isCurrentProcessInteractive(t *testing.T) bool {
	var token windows.Token
	require.NoError(t, windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &token))
	defer token.Close()

	var impersonationToken windows.Token
	require.NoError(t, windows.DuplicateTokenEx(token, windows.TOKEN_QUERY, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &impersonationToken))
	defer impersonationToken.Close()

	sid, err := windows.CreateWellKnownSid(windows.WinInteractiveSid)
	require.NoError(t, err)

	ret, err := impersonationToken.IsMember(sid)
	require.NoError(t, err)

	return ret
}

func TestIsInteractiveToken(t *testing.T) {
	var token windows.Token
	require.NoError(t, windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token))
	defer token.Close()

	ret, err := isInteractiveToken(token)
	assert.Nil(t, err)
	assert.Equal(t, isCurrentProcessInteractive(t), ret)

	_, err = isInteractiveToken(windows.Token(0))
	assert.NotNil(t, err)
}

func TestHasLoginSession(t *testing.T) {
	ctx := context.Background()

	{
		ret, err := HasLoginSession(ctx, &Principal{
			ID:            "S-1-5-21-1-2-3-1001",
			isInteractive: true,
		})
		assert.Nil(t, err)
		assert.True(t, ret)
	}

	{
		ret, err := HasLoginSession(ctx, &Principal{
			ID: "S-1-5-21-1-2-3-1001",
		})
		assert.Nil(t, err)
		assert.False(t, ret)
	}

	{
		_, err := HasLoginSession(ctx, &Principal{
			ID:               "S-1-5-21-1-2-3-1001",
			isInteractiveErr: errors.New("token"),
		})
		assert.NotNil(t, err)
	}
}
