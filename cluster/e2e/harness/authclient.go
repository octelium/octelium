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

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/authc"
)

func (h *H) AuthC(t *testing.T) authv1.MainServiceClient {
	t.Helper()

	c, err := authc.NewClient(t.Context(), h.Domain, nil)
	if err != nil {
		t.Fatalf("Could not build an authentication client for %s: %+v", h.Domain, err)
	}

	t.Cleanup(func() { c.Close() })

	return c.C()
}
