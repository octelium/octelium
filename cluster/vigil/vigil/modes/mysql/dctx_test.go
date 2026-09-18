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

package mysql

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/stretchr/testify/assert"
)

func newTestDctx(cfg *corev1.Service_Spec_Config_MySQL) *dctx {
	return &dctx{
		svcConfig: &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Mysql{
				Mysql: cfg,
			},
		},
	}
}

func TestGetLoggedQuery(t *testing.T) {
	{
		c := newTestDctx(&corev1.Service_Spec_Config_MySQL{})

		query, isTruncated := c.getLoggedQuery("SELECT 1")
		assert.Equal(t, "SELECT 1", query)
		assert.False(t, isTruncated)
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_MySQL{
			Visibility: &corev1.Service_Spec_Config_MySQL_Visibility{
				DisableQuery: true,
			},
		})

		query, isTruncated := c.getLoggedQuery("SELECT 1")
		assert.Equal(t, "", query)
		assert.False(t, isTruncated)
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_MySQL{})

		query, isTruncated := c.getLoggedQuery(strings.Repeat("a", maxLoggedQueryLen+100))
		assert.Len(t, query, maxLoggedQueryLen)
		assert.True(t, isTruncated)
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_MySQL{
			Visibility: &corev1.Service_Spec_Config_MySQL_Visibility{
				DisableQuery: true,
			},
		})

		query, isTruncated := c.getLoggedQuery(strings.Repeat("a", maxLoggedQueryLen+100))
		assert.Equal(t, "", query)
		assert.False(t, isTruncated)
	}
}

func TestTruncateQuery(t *testing.T) {
	for _, arg := range []struct {
		query string
		out   string
	}{
		{"", ""},
		{"SELECT 1", "SELECT 1"},
		{strings.Repeat("a", maxLoggedQueryLen), strings.Repeat("a", maxLoggedQueryLen)},
		{strings.Repeat("a", maxLoggedQueryLen+1), strings.Repeat("a", maxLoggedQueryLen)},
	} {
		assert.Equal(t, arg.out, truncateQuery(arg.query))
	}

	{
		query := strings.Repeat("a", maxLoggedQueryLen-1) + "€"
		out := truncateQuery(query)
		assert.True(t, utf8.ValidString(out))
		assert.Equal(t, strings.Repeat("a", maxLoggedQueryLen-1), out)
	}
}
