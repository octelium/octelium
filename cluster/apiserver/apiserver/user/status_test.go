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

package user

import (
	"testing"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/stretchr/testify/assert"
)

func TestGetStatus(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usr, err := tstuser.NewUser(usrSrv.octeliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	resp, err := usrSrv.GetStatus(usr.Ctx(), &userv1.GetStatusRequest{})
	assert.Nil(t, err)
	assert.Equal(t, usr.Usr.Metadata.Name, resp.User.Metadata.Name)
}
