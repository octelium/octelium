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
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLatencySummary(t *testing.T) {
	l := &Latencies{}
	assert.Equal(t, "n=0", l.Summary().String())

	for i := 100; i >= 1; i-- {
		l.Add(time.Duration(i) * time.Millisecond)
	}

	s := l.Summary()
	assert.Equal(t, 100, s.Count)
	assert.Equal(t, time.Millisecond, s.Min)
	assert.Equal(t, 100*time.Millisecond, s.Max)
	assert.Equal(t, 50*time.Millisecond, s.P50)
	assert.Equal(t, 95*time.Millisecond, s.P95)
	assert.Equal(t, 99*time.Millisecond, s.P99)
	assert.Equal(t, 50500*time.Microsecond, s.Mean)
	assert.Contains(t, s.String(), "p99=99ms")

	other := &Latencies{}
	other.Add(time.Second)
	l.Merge(other)
	assert.Equal(t, 101, l.Count())
	assert.Equal(t, time.Second, l.Summary().Max)
}

func TestPercentileOfOne(t *testing.T) {
	assert.Equal(t, time.Second, percentile([]time.Duration{time.Second}, 99))
	assert.Equal(t, time.Second, percentile([]time.Duration{time.Second}, 1))
	assert.Zero(t, percentile(nil, 50))
}

func TestClassifyError(t *testing.T) {
	for want, err := range map[string]error{
		ErrClassEnvoyOverflow: status.Error(codes.Unavailable,
			"upstream connect error or disconnect/reset before headers. reset reason: overflow"),
		ErrClassEnvoyNoUpstream: status.Error(codes.Unavailable, "no healthy upstream"),
		ErrClassEnvoyReset: status.Error(codes.Unavailable,
			"upstream connect error or disconnect/reset before headers. reset reason: connection termination"),
		ErrClassTooManyFiles:     &net.OpError{Op: "dial", Err: os.NewSyscallError("socket", syscall.EMFILE)},
		ErrClassAddrNotAvail:     &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EADDRNOTAVAIL)},
		ErrClassConnRefused:      &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
		ErrClassConnReset:        errors.New("read tcp 1.2.3.4:5->6.7.8.9:443: read: connection reset by peer"),
		"grpc-Unauthenticated":   status.Error(codes.Unauthenticated, "no session"),
		"grpc-ResourceExhausted": status.Error(codes.ResourceExhausted, "too many"),
		ErrClassDeadline:         errors.Wrap(context.DeadlineExceeded, "waiting"),
		ErrClassCanceled:         context.Canceled,
		ErrClassEOF:              errors.New("unexpected EOF"),
		"short":                  errors.New("short"),
		"the first part":         errors.New("the first part: the rest of it"),
	} {
		assert.Equal(t, want, ClassifyError(err), "%v", err)
	}

	assert.Empty(t, ClassifyError(nil))
}

func TestErrorCounter(t *testing.T) {
	c := NewErrorCounter()
	assert.Equal(t, "no errors", c.String())

	c.Add(nil)
	for range 3 {
		c.Add(status.Error(codes.Unauthenticated, "no session"))
	}
	c.Add(context.Canceled)

	assert.Equal(t, 4, c.Total())
	assert.Equal(t, 3, c.Count("grpc-Unauthenticated"))
	assert.Equal(t, map[string]int{"grpc-Unauthenticated": 3, ErrClassCanceled: 1}, c.Classes())

	out := c.String()
	assert.Contains(t, out, "4 errors")
	assert.Less(t, indexOf(out, "grpc-Unauthenticated"), indexOf(out, ErrClassCanceled),
		"the most frequent class is listed first")
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestForEach(t *testing.T) {
	var inFlight, peak atomic.Int64

	r := ForEach(t.Context(), 50, 5, func(ctx context.Context, i int) error {
		cur := inFlight.Add(1)
		defer inFlight.Add(-1)

		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}

		time.Sleep(2 * time.Millisecond)
		if i%10 == 0 {
			return fmt.Errorf("failed %d", i)
		}
		return nil
	})

	assert.Equal(t, 50, r.Total)
	assert.Equal(t, 45, r.Succeeded)
	assert.Equal(t, 5, r.Failed())
	assert.Equal(t, 5, r.Errors.Total())
	assert.Equal(t, 45, r.Latency.Count())
	assert.LessOrEqual(t, peak.Load(), int64(5), "the concurrency must be bounded")
	assert.Greater(t, r.Rate(), 0.0)
	assert.Contains(t, r.String(), "45/50 succeeded")

	empty := ForEach(t.Context(), 0, 5, func(ctx context.Context, i int) error { return nil })
	assert.Zero(t, empty.Total)
}

func TestForEachHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	var calls atomic.Int64
	r := ForEach(ctx, 100, 1, func(ctx context.Context, i int) error {
		if calls.Add(1) == 10 {
			cancel()
		}
		return nil
	})

	assert.Equal(t, int64(10), calls.Load())
	assert.Equal(t, 10, r.Succeeded)
	assert.Equal(t, 90, r.Errors.Count(ErrClassCanceled))
}

func TestRunFor(t *testing.T) {
	var calls atomic.Int64

	started := time.Now()
	r := RunFor(t.Context(), 200*time.Millisecond, 4, func(ctx context.Context, worker, iteration int) error {
		calls.Add(1)
		if err := Sleep(ctx, 10*time.Millisecond); err != nil {
			return err
		}
		if iteration == 0 && worker == 0 {
			return errors.New("first")
		}
		return nil
	})

	assert.Less(t, time.Since(started), 2*time.Second)
	assert.Greater(t, r.Total, 20)
	assert.Equal(t, r.Total-1, r.Succeeded)
	assert.Equal(t, 1, r.Errors.Total(), "an operation interrupted by the end of the run is not an error")
}

func TestReconnectBackoff(t *testing.T) {
	for attempt := 1; attempt < 20; attempt++ {
		got := ReconnectBackoff(attempt, 0, 0)
		assert.GreaterOrEqual(t, got, reconnectBackoffMin, "attempt %d", attempt)
		assert.LessOrEqual(t, got, reconnectBackoffMax+time.Nanosecond, "attempt %d", attempt)
	}

	for attempt := 1; attempt < 10; attempt++ {
		got := ReconnectBackoff(attempt, 10*time.Millisecond, 40*time.Millisecond)
		assert.GreaterOrEqual(t, got, 10*time.Millisecond)
		assert.LessOrEqual(t, got, 41*time.Millisecond)
	}
}

func TestSleep(t *testing.T) {
	require.NoError(t, Sleep(t.Context(), time.Millisecond))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	assert.ErrorIs(t, Sleep(ctx, time.Hour), context.Canceled)
	assert.ErrorIs(t, Sleep(ctx, 0), context.Canceled)
}
