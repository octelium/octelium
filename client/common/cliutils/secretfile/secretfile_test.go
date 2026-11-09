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

package secretfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRead(t *testing.T) {
	dir := t.TempDir()

	for _, itm := range []struct {
		name    string
		content string
		want    string
	}{
		{"plain", "token", "token"},
		{"newline", "token\n", "token"},
		{"crlf", "token\r\n", "token"},
		{"spaces", "  \ttoken \n\n", "token"},
		{"max", strings.Repeat("a", maxSize), strings.Repeat("a", maxSize)},
	} {
		t.Run(itm.name, func(t *testing.T) {
			filePath := filepath.Join(dir, itm.name)
			require.NoError(t, os.WriteFile(filePath, []byte(itm.content), 0600))
			ret, err := Read(filePath)
			require.NoError(t, err)
			assert.Equal(t, itm.want, ret)
		})
	}

	for _, itm := range []struct {
		name    string
		content string
		err     string
	}{
		{"empty", "", "is empty"},
		{"whitespace", " \n\t\r\n", "is empty"},
		{"large", strings.Repeat("a", maxSize+1), "is too large"},
	} {
		t.Run(itm.name, func(t *testing.T) {
			filePath := filepath.Join(dir, itm.name)
			require.NoError(t, os.WriteFile(filePath, []byte(itm.content), 0600))
			_, err := Read(filePath)
			assert.ErrorContains(t, err, itm.err)
		})
	}

	_, err := Read("")
	assert.ErrorContains(t, err, "path is not set")

	_, err = Read(filepath.Join(dir, "missing"))
	assert.ErrorContains(t, err, "Could not open")

	_, err = Read(dir)
	assert.Error(t, err)
}

func TestReadRotated(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(filePath, []byte("first\n"), 0600))
	ret, err := Read(filePath)
	require.NoError(t, err)
	assert.Equal(t, "first", ret)

	tmpPath := filePath + ".tmp"
	require.NoError(t, os.WriteFile(tmpPath, []byte("second\n"), 0600))
	require.NoError(t, os.Rename(tmpPath, filePath))
	ret, err = Read(filePath)
	require.NoError(t, err)
	assert.Equal(t, "second", ret)
}
