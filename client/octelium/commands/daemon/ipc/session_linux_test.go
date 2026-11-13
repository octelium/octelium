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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeLoginctl = `#!/bin/sh
echo "$@" >> "$0.log"
if [ "$1" != "--no-pager" ]; then
	exit 2
fi
case "$2 $3 $4" in
"--property=Sessions show-user 1000")
	printf 'Sessions=c1 4 -p bad;id 5\n'
	;;
"--property=Sessions show-user 1001")
	printf 'Sessions=c2 c3\n'
	;;
"--property=Sessions show-user 1002")
	printf 'Sessions=\n'
	;;
"--property=Sessions show-user 1003")
	printf 'Sessions=c6\n'
	;;
"--property=Sessions show-user 1004")
	printf 'Sessions=c7 c8\n'
	;;
"--property=Sessions show-user 1005")
	printf 'Sessions=c9\n'
	;;
"--property=Class show-session c1")
	printf 'Class=manager\n'
	;;
"--property=Class show-session 4")
	exit 1
	;;
"--property=Class show-session 5")
	printf 'Class=user\n'
	;;
"--property=Class show-session c2")
	printf 'Class=greeter\n'
	;;
"--property=Class show-session c3")
	printf 'Class=background\n'
	;;
"--property=Class show-session c6")
	printf 'Class=user-early\n'
	;;
"--property=Class show-session c7")
	printf 'Class=lock-screen\n'
	;;
"--property=Class show-session c8")
	printf 'Class=userx\n'
	;;
"--property=Class show-session c9")
	printf 'Class=user-incomplete\n'
	;;
"--no-legend list-sessions ")
	if [ -e "$0.nologind" ]; then
		echo "Failed to connect to bus" >&2
		exit 1
	fi
	;;
*)
	exit 1
	;;
esac
`

func setFakeLoginctl(t *testing.T) string {
	dir := t.TempDir()
	ret := filepath.Join(dir, "loginctl")
	require.NoError(t, os.WriteFile(ret, []byte(fakeLoginctl), 0755))

	prev := loginctlPath
	loginctlPath = ret
	t.Cleanup(func() {
		loginctlPath = prev
	})

	return ret
}

func TestHasLoginSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fake := setFakeLoginctl(t)

	for _, tc := range []struct {
		id       string
		expected bool
	}{
		{id: "1000", expected: true},
		{id: "1001", expected: false},
		{id: "1002", expected: false},
		{id: "1003", expected: true},
		{id: "1004", expected: false},
		{id: "1005", expected: true},
		{id: "1006", expected: false},
	} {
		ret, err := HasLoginSession(ctx, &Principal{
			ID: tc.id,
		})
		assert.Nil(t, err, "id=%s", tc.id)
		assert.Equal(t, tc.expected, ret, "id=%s", tc.id)
	}

	logs, err := os.ReadFile(fake + ".log")
	require.NoError(t, err)
	assert.NotContains(t, string(logs), "show-session -p")
	assert.NotContains(t, string(logs), "bad;id")
	assert.Contains(t, string(logs), "--no-pager --no-legend list-sessions")

	require.NoError(t, os.WriteFile(fake+".nologind", nil, 0600))

	{
		_, err := HasLoginSession(ctx, &Principal{
			ID: "1006",
		})
		assert.NotNil(t, err)
	}

	{
		ret, err := HasLoginSession(ctx, &Principal{
			ID: "1000",
		})
		assert.Nil(t, err)
		assert.True(t, ret)
	}
}

func TestHasLoginSessionNoLoginctl(t *testing.T) {
	prev := loginctlPath
	loginctlPath = filepath.Join(t.TempDir(), "loginctl")
	t.Cleanup(func() {
		loginctlPath = prev
	})

	_, err := HasLoginSession(context.Background(), &Principal{
		ID: "1000",
	})
	assert.NotNil(t, err)
}

func TestHasLoginSessionCanceled(t *testing.T) {
	setFakeLoginctl(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := HasLoginSession(ctx, &Principal{
		ID: "1000",
	})
	assert.NotNil(t, err)
}

func TestGetLoginctlProperty(t *testing.T) {
	out := []byte("Class=user\n  Sessions=c1 2 \nName=usr1\r\nEmpty=\n")

	assert.Equal(t, "user", getLoginctlProperty(out, "Class"))
	assert.Equal(t, "c1 2", getLoginctlProperty(out, "Sessions"))
	assert.Equal(t, "usr1", getLoginctlProperty(out, "Name"))
	assert.Equal(t, "", getLoginctlProperty(out, "Empty"))
	assert.Equal(t, "", getLoginctlProperty(out, "Missing"))
	assert.Equal(t, "", getLoginctlProperty(nil, "Class"))
}

func TestIsValidSessionID(t *testing.T) {
	for _, arg := range []string{"1", "c1", "C12", "abc123", strings.Repeat("a", maxSessionIDLen)} {
		assert.True(t, isValidSessionID(arg), "arg=%s", arg)
	}

	for _, arg := range []string{"", "-p", "--all", "c 1", "c1;", "../1", "c-1", "é1",
		strings.Repeat("a", maxSessionIDLen+1)} {
		assert.False(t, isValidSessionID(arg), "arg=%s", arg)
	}
}

func TestIsUserSessionClass(t *testing.T) {
	for _, arg := range []string{"user", "user-early", "user-incomplete", "user-light", "user-early-light"} {
		assert.True(t, isUserSessionClass(arg), "class=%s", arg)
	}

	for _, arg := range []string{"", "greeter", "lock-screen", "background", "background-light",
		"manager", "manager-early", "none", "userx", "User", " user"} {
		assert.False(t, isUserSessionClass(arg), "class=%s", arg)
	}
}
