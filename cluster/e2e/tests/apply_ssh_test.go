//go:build e2e

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

package tests

import (
	"fmt"
	"testing"
)

func applyESSH(t *testing.T, a *applyCtx) {
	a.h.MustWaitService(t, "essh")

	a.h.MustRun(t, fmt.Sprintf(`ssh -p %d %s@localhost 'echo hello world'`,
		a.port("essh"), sshUser(t, a.h)))
}
