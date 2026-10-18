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

package suite

import (
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/cluster/e2e/scenario"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRejectsValidSession(t *testing.T) {
	for _, code := range []codes.Code{
		codes.NotFound, codes.PermissionDenied, codes.InvalidArgument, codes.Unauthenticated,
	} {
		assert.True(t, rejectsValidSession(status.Error(code, "rejected")), code.String())
		assert.True(t, rejectsValidSession(errors.Wrap(status.Error(code, "rejected"), "wrapped")), code.String())
	}

	for _, code := range []codes.Code{
		codes.Unavailable, codes.Internal, codes.DeadlineExceeded, codes.Unknown,
		codes.Canceled, codes.ResourceExhausted, codes.Unimplemented, codes.Aborted,
	} {
		assert.False(t, rejectsValidSession(status.Error(code, "transient")), code.String())
	}

	assert.False(t, rejectsValidSession(errors.New("connection reset by peer")))
}

func TestErrorLogRejectedSince(t *testing.T) {
	l := &errorLog{}

	l.add(status.Error(codes.NotFound, "Session UID not Found"))
	time.Sleep(time.Millisecond)
	since := time.Now()

	l.add(status.Error(codes.Unavailable, "no healthy upstream"))
	l.add(status.Error(codes.PermissionDenied, "Octelium: Unauthorized"))
	l.add(status.Error(codes.Unauthenticated, "Octelium: Unauthenticated"))

	got := l.rejectedSince(since)
	assert.Equal(t, 2, got.Total())
	assert.Equal(t, 1, got.Count("grpc-PermissionDenied"))
	assert.Equal(t, 1, got.Count("grpc-Unauthenticated"))

	assert.Equal(t, 3, l.rejectedSince(time.Time{}).Total())
	assert.Zero(t, l.rejectedSince(time.Now().Add(time.Second)).Total())
}

func TestUpgradeClientOpts(t *testing.T) {
	type combo struct {
		tunnel userv1.ConnectRequest_Initialize_ConnectionType
		mode   userv1.ConnectRequest_Initialize_L3Mode
	}

	h := &harness.H{Scenario: &scenario.Scenario{Caps: scenario.Capabilities{capQUICv0, capIPv6}}}

	seen := map[combo]bool{}
	for i := range upgradeClients {
		o := upgradeClientOpts(h, i)
		seen[combo{o.Tunnel, o.L3Mode}] = true
	}
	assert.Len(t, seen, 6, "the virtual clients must cover every tunnel and IP mode")

	single := &harness.H{Scenario: &scenario.Scenario{}}
	for i := range upgradeClients {
		o := upgradeClientOpts(single, i)
		assert.Equal(t, userv1.ConnectRequest_Initialize_WIREGUARD, o.Tunnel)
		assert.Equal(t, userv1.ConnectRequest_Initialize_V4, o.L3Mode)
	}
}

func TestUpgradeDisruptions(t *testing.T) {
	assert.LessOrEqual(t, upgradeClients+upgradeChurnClients, upgradeFleetSessions)

	seen := map[string]bool{}
	for _, d := range upgradeDisruptions() {
		assert.NotEmpty(t, d.name)
		assert.False(t, seen[d.name], "the disruption %s is declared more than once", d.name)
		seen[d.name] = true

		assert.NotNil(t, d.run, d.name)
		assert.Equal(t, d.name != "OctovigilRollout", d.drops,
			"%s replaces the API Server so the client streams must drop", d.name)
	}

	assert.True(t, seen["GenesisUpgrade"])
}
