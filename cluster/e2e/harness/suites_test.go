/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package harness

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSuites(t *testing.T) {
	for in, want := range map[string][]string{
		"":             {SuiteBase},
		"base":         {SuiteBase},
		"chaos":        {SuiteChaos},
		"all":          {SuiteBase, SuiteChaos},
		"chaos, base":  {SuiteChaos, SuiteBase},
		"base,base":    {SuiteBase},
		"chaos,all":    {SuiteBase, SuiteChaos},
		" chaos ,base": {SuiteChaos, SuiteBase},
	} {
		got, err := ParseSuites(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	_, err := ParseSuites("base,soak")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "soak")
}

func TestSuiteSelected(t *testing.T) {
	t.Setenv(SuiteEnv, "")
	assert.True(t, SuiteSelected(SuiteBase), "the base suite runs by default")
	assert.False(t, SuiteSelected(SuiteChaos), "the chaos suite never runs by default")

	t.Setenv(SuiteEnv, "chaos")
	assert.False(t, SuiteSelected(SuiteBase))
	assert.True(t, SuiteSelected(SuiteChaos))

	t.Setenv(SuiteEnv, "all")
	assert.True(t, SuiteSelected(SuiteBase))
	assert.True(t, SuiteSelected(SuiteChaos))

	t.Setenv(SuiteEnv, "unknown")
	assert.False(t, SuiteSelected(SuiteBase), "an invalid selection runs nothing")
}

func TestChaosScaleSelection(t *testing.T) {
	for _, s := range append([]string{""}, ChaosScales...) {
		assert.NoError(t, ValidateChaosScale(s), s)
	}
	assert.Error(t, ValidateChaosScale("huge"))

	t.Setenv(ChaosScaleEnv, "")
	assert.Equal(t, ChaosScaleDefault, ChaosScale())

	t.Setenv(ChaosScaleEnv, "xlarge")
	assert.Equal(t, "xlarge", ChaosScale())
}
