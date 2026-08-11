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

const pollReportEvery = 15 * time.Second

type fatalError struct {
	err error
}

func (f *fatalError) Error() string { return f.err.Error() }

func fatal(err error) error { return &fatalError{err: err} }

func pollUntil(ctx context.Context, what string,
	budget, interval time.Duration, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	started := time.Now()
	attempts := 0
	reported := time.Now()

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

		var f *fatalError
		if errors.As(lastErr, &f) {
			return errors.Errorf("Gave up waiting for %s after %s: %+v",
				what, time.Since(started).Truncate(time.Millisecond), f.err)
		}

		if time.Since(reported) >= pollReportEvery {
			reported = time.Now()
			zap.L().Info("Still waiting",
				zap.String("what", what),
				zap.Int("attempts", attempts),
				zap.Duration("elapsed", time.Since(started).Truncate(time.Second)),
				zap.Duration("budget", budget),
				zap.NamedError("lastError", lastErr))
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
