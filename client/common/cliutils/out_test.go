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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateOutFormat(t *testing.T) {
	for _, itm := range []string{"", "json", "yaml", "yml"} {
		assert.Nil(t, ValidateOutFormat(itm), "out: %s", itm)
	}

	for _, itm := range []string{"xml", "JSON", "table", "wide"} {
		assert.NotNil(t, ValidateOutFormat(itm), "out: %s", itm)
	}
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
