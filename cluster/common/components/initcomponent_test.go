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

package components

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetShutdownSignals(t *testing.T) {
	assert.Equal(t, []os.Signal{os.Interrupt}, getShutdownSignals(nil))
	assert.Equal(t, []os.Signal{os.Interrupt}, getShutdownSignals(&RunComponentOpts{}))
	assert.Equal(t, []os.Signal{os.Interrupt, syscall.SIGTERM}, getShutdownSignals(&RunComponentOpts{
		CancelOnSIGTERM: true,
	}))
}

func TestRunComponentCancelOnSIGTERM(t *testing.T) {
	var isCanceled bool

	RunComponent(func(ctx context.Context) error {
		proc, err := os.FindProcess(os.Getpid())
		if err != nil {
			return err
		}

		if err := proc.Signal(syscall.SIGTERM); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			isCanceled = true
		case <-time.After(10 * time.Second):
		}

		return nil
	}, &RunComponentOpts{
		CancelOnSIGTERM: true,
	})

	assert.True(t, isCanceled)
}
