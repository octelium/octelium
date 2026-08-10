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

package scenario

import (
	"context"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	second = time.Second
	minute = time.Minute
)

func pollUntil(ctx context.Context, what string,
	budget, interval time.Duration, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	started := time.Now()
	attempts := 0

	var lastErr error
	for {
		attempts++
		lastErr = fn(ctx)
		if lastErr == nil {
			zap.L().Debug("Condition met",
				zap.String("what", what),
				zap.Int("attempts", attempts),
				zap.Duration("elapsed", time.Since(started)))
			return nil
		}

		select {
		case <-ctx.Done():
			return errors.Errorf(
				"Timed out after %s waiting for %s (%d attempts). Last error: %+v",
				time.Since(started).Truncate(time.Millisecond), what, attempts, lastErr)
		case <-time.After(interval):
		}
	}
}
