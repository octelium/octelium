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
	"context"
	"testing"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const DefaultPollInterval = 250 * time.Millisecond

func (h *H) Within(t *testing.T, what string,
	budget time.Duration, fn func(ctx context.Context) error) time.Duration {
	t.Helper()
	return h.WithinEvery(t, what, budget, DefaultPollInterval, fn)
}

func (h *H) WithinEvery(t *testing.T, what string,
	budget, interval time.Duration, fn func(ctx context.Context) error) time.Duration {
	t.Helper()

	elapsed, err := h.poll(t.Context(), what, budget, interval, fn)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	zap.L().Debug("Condition met",
		zap.String("what", what), zap.Duration("elapsed", elapsed))

	return elapsed
}

func (h *H) Eventually(t *testing.T, what string,
	budget time.Duration, fn func(ctx context.Context) error) {
	t.Helper()
	h.Within(t, what, budget, fn)
}

func (h *H) EventuallyEvery(t *testing.T, what string,
	budget, interval time.Duration, fn func(ctx context.Context) error) {
	t.Helper()
	h.WithinEvery(t, what, budget, interval, fn)
}

func (h *H) EventuallyErr(ctx context.Context, what string,
	budget time.Duration, fn func(ctx context.Context) error) error {
	_, err := h.poll(ctx, what, budget, DefaultPollInterval, fn)
	return err
}

func (h *H) Consistently(t *testing.T, what string,
	window time.Duration, fn func(ctx context.Context) error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), window)
	defer cancel()

	started := time.Now()
	for {
		if err := fn(ctx); err != nil {
			t.Fatalf("%s did not hold: after %s: %+v",
				what, time.Since(started).Truncate(time.Millisecond), err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(DefaultPollInterval):
		}
	}
}

func (h *H) poll(parent context.Context, what string,
	budget, interval time.Duration, fn func(ctx context.Context) error) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()

	started := time.Now()
	attempts := 0

	for {
		attempts++
		err := fn(ctx)
		if err == nil {
			return time.Since(started), nil
		}

		select {
		case <-ctx.Done():
			return time.Since(started), errors.Errorf(
				"Timed out after %s waiting for %s (%d attempts). Last error: %+v",
				time.Since(started).Truncate(time.Millisecond), what, attempts, err)
		case <-time.After(interval):
		}
	}
}
