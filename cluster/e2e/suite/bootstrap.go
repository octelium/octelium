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
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/e2e/harness"
	"go.uber.org/zap"
)

var (
	h       *harness.H
	initErr error
)

func H() *harness.H { return h }

func Bootstrap(m *testing.M) int {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	zap.ReplaceGlobals(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h, initErr = harness.New(ctx, nil)

	code := m.Run()

	if h != nil {
		h.Close()
	}

	return code
}

func Run(t *testing.T, phases []Phase) {
	if initErr != nil {
		t.Fatalf("Could not initialize the e2e harness: %+v", initErr)
	}

	if err := Validate(phases); err != nil {
		t.Fatalf("Invalid phase list: %+v", err)
	}

	started := time.Now()

	for _, p := range phases {
		t.Run(p.Name, func(t *testing.T) {
			h.Setup(t)
			p.Run(t, h)
		})
	}

	zap.L().Debug("Test done", zap.Duration("duration", time.Since(started)))
}
