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

package cliutils

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/printer"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateOutFormat(t *testing.T) {
	for _, itm := range []string{"", "json", "yaml", "yml"} {
		assert.Nil(t, ValidateOutFormat(itm), "out: %s", itm)
	}

	for _, itm := range []string{"xml", "JSON", "table", "wide"} {
		assert.NotNil(t, ValidateOutFormat(itm), "out: %s", itm)
	}
}

func TestOutFormatPrint(t *testing.T) {
	for _, format := range []string{"json", "yaml", "yml", ""} {
		t.Run(format, func(t *testing.T) {
			arg := &authv1.SessionToken{AccessToken: "token", RefreshToken: "refresh", ExpiresIn: 3600}
			out, err := OutFormatPrint(format, arg)
			require.NoError(t, err)
			ret := &authv1.SessionToken{}
			if format == "json" {
				require.NoError(t, pbutils.UnmarshalJSON(out, ret))
			} else {
				require.NoError(t, pbutils.UnmarshalYAML(out, ret))
			}
			assert.True(t, pbutils.IsEqual(arg, ret))
		})
	}
	out, err := OutFormatPrint("xml", &authv1.SessionToken{})
	assert.Nil(t, out)
	assert.ErrorContains(t, err, "Invalid output format: xml")
}

func TestGetDataValueSources(t *testing.T) {
	for _, opts := range []*GetDataValueOpts{
		{Value: "value", FromFile: "file"},
		{FromFile: "file", FromEnv: "ENV"},
		{Value: "value", FromFile: "file", FromEnv: "ENV"},
	} {
		_, err := GetDataValue(opts)
		assert.ErrorContains(t, err, "Only one of")
	}
	t.Setenv("OCTELIUM_TEST_EMPTY_VALUE", "")
	ret, err := GetDataValue(&GetDataValueOpts{FromEnv: "OCTELIUM_TEST_EMPTY_VALUE"})
	require.NoError(t, err)
	assert.Empty(t, ret)
	_, err = GetDataValue(&GetDataValueOpts{FromFile: filepath.Join(t.TempDir(), "missing")})
	assert.ErrorIs(t, err, os.ErrNotExist)
	t.Setenv("DEBIAN_FRONTEND", "noninteractive")
	_, err = GetDataValue(&GetDataValueOpts{})
	assert.ErrorContains(t, err, "--value, --file or --from-env")
	path := filepath.Join(t.TempDir(), "stdin")
	require.NoError(t, os.WriteFile(path, []byte("line1\nline2\x00\n"), 0600))
	f, err := os.Open(path)
	require.NoError(t, err)
	prev := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = prev
		f.Close()
	})
	ret, err = GetDataValue(&GetDataValueOpts{FromFile: "-"})
	require.NoError(t, err)
	assert.Equal(t, "line1\nline2\x00\n", string(ret))
}

func TestPrinterIncrementalOutput(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	require.NoError(t, err)
	previous := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = previous; f.Close() }()
	p := printer.NewPrinter("Name", "State")
	p.AppendAndRenderRow("resource-one", "Ready")
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	out, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Contains(t, string(out), "resource-one")
	assert.Contains(t, string(out), "Ready")
	assert.Contains(t, string(out), "NAME")
}

func TestGetDataValue(t *testing.T) {

	{
		val, err := GetDataValue(&GetDataValueOpts{
			Value: "v1",
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "v1", string(val))
	}

	{
		path := filepath.Join(t.TempDir(), "value")
		assert.Nil(t, os.WriteFile(path, []byte("v2"), 0644))

		val, err := GetDataValue(&GetDataValueOpts{
			FromFile: path,
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "v2", string(val))
	}

	{
		t.Setenv("OCTELIUM_TEST_VALUE", "v3")

		val, err := GetDataValue(&GetDataValueOpts{
			FromEnv: "OCTELIUM_TEST_VALUE",
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "v3", string(val))
	}

	{
		_, err := GetDataValue(&GetDataValueOpts{
			FromEnv: "OCTELIUM_TEST_VALUE_NOT_SET",
		})
		assert.NotNil(t, err)
	}

	{
		_, err := GetDataValue(&GetDataValueOpts{
			Value:   "v1",
			FromEnv: "OCTELIUM_TEST_VALUE",
		})
		assert.NotNil(t, err)
	}

	{
		_, err := GetDataValue(&GetDataValueOpts{})
		assert.NotNil(t, err)
	}
}
