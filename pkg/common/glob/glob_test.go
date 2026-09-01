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

package glob

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		arg     string
		want    bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"read_file", "read_file", true},
		{"read_file", "read_files", false},
		{"read_*", "read_file", true},
		{"read_*", "read_", true},
		{"read_*", "write_file", false},
		{"*_file", "read_file", true},
		{"*_file", "read_file_x", false},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxcyyb", false},
		{"*search*", "web_search_preview", true},
		{"srv/*", "srv/tool", true},
	} {
		assert.Equal(t, tc.want, Match(tc.pattern, tc.arg),
			"pattern %q against %q", tc.pattern, tc.arg)
	}
}

func TestValidate(t *testing.T) {
	assert.Nil(t, Validate("read_*"))
	assert.NotNil(t, Validate(""))
	assert.NotNil(t, Validate(strings.Repeat("a", MaxPatternLen+1)))
	assert.NotNil(t, Validate(strings.Repeat("*", maxStars+1)))
	assert.NotNil(t, Validate("read\x00"))
}
