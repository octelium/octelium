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

package octeliumc

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultAddr(t *testing.T) {

	addr := DefaultAddr()

	assert.True(t, strings.HasSuffix(addr, ".octelium.svc:8080"), addr)
	assert.True(t, strings.Contains(addr, "octelium"), addr)
	assert.Equal(t, addr, DefaultAddr())
}

func TestDefaultDialOpts(t *testing.T) {

	ctx := context.Background()

	opts, err := DefaultDialOpts(ctx)
	if err != nil {
		assert.Nil(t, opts)
		return
	}

	assert.True(t, len(opts) >= 3)
	for _, opt := range opts {
		assert.NotNil(t, opt)
	}
}
