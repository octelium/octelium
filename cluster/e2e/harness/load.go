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
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Latencies struct {
	mu   sync.Mutex
	vals []time.Duration
}

func (l *Latencies) Add(d time.Duration) {
	l.mu.Lock()
	l.vals = append(l.vals, d)
	l.mu.Unlock()
}

func (l *Latencies) Merge(other *Latencies) {
	other.mu.Lock()
	vals := slices.Clone(other.vals)
	other.mu.Unlock()

	l.mu.Lock()
	l.vals = append(l.vals, vals...)
	l.mu.Unlock()
}

func (l *Latencies) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.vals)
}

func (l *Latencies) Summary() LatencySummary {
	l.mu.Lock()
	vals := slices.Clone(l.vals)
	l.mu.Unlock()

	return summarize(vals)
}

type LatencySummary struct {
	Count int           `json:"count"`
	Min   time.Duration `json:"min"`
	P50   time.Duration `json:"p50"`
	P90   time.Duration `json:"p90"`
	P95   time.Duration `json:"p95"`
	P99   time.Duration `json:"p99"`
	Max   time.Duration `json:"max"`
	Mean  time.Duration `json:"mean"`
}

func summarize(vals []time.Duration) LatencySummary {
	ret := LatencySummary{Count: len(vals)}
	if len(vals) == 0 {
		return ret
	}

	slices.Sort(vals)

	var total time.Duration
	for _, v := range vals {
		total += v
	}

	ret.Min = vals[0]
	ret.Max = vals[len(vals)-1]
	ret.Mean = total / time.Duration(len(vals))
	ret.P50 = percentile(vals, 50)
	ret.P90 = percentile(vals, 90)
	ret.P95 = percentile(vals, 95)
	ret.P99 = percentile(vals, 99)

	return ret
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}

	idx := int(float64(len(sorted))*p/100+0.5) - 1
	idx = max(0, min(idx, len(sorted)-1))

	return sorted[idx]
}

func (s LatencySummary) String() string {
	if s.Count == 0 {
		return "n=0"
	}

	r := func(d time.Duration) time.Duration {
		switch {
		case d >= time.Second:
			return d.Truncate(10 * time.Millisecond)
		case d >= time.Millisecond:
			return d.Truncate(10 * time.Microsecond)
		default:
			return d
		}
	}

	return fmt.Sprintf("n=%d min=%s p50=%s p90=%s p95=%s p99=%s max=%s",
		s.Count, r(s.Min), r(s.P50), r(s.P90), r(s.P95), r(s.P99), r(s.Max))
}

type ErrorCounter struct {
	mu      sync.Mutex
	total   int
	byClass map[string]int
	samples map[string]string
}

func NewErrorCounter() *ErrorCounter {
	return &ErrorCounter{
		byClass: map[string]int{},
		samples: map[string]string{},
	}
}

func (e *ErrorCounter) Add(err error) {
	if err == nil {
		return
	}

	class := ClassifyError(err)

	e.mu.Lock()
	defer e.mu.Unlock()

	e.total++
	e.byClass[class]++
	if _, ok := e.samples[class]; !ok {
		msg := err.Error()
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		e.samples[class] = msg
	}
}

func (e *ErrorCounter) Total() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.total
}

func (e *ErrorCounter) Count(class string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.byClass[class]
}

func (e *ErrorCounter) Classes() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()

	ret := make(map[string]int, len(e.byClass))
	for k, v := range e.byClass {
		ret[k] = v
	}
	return ret
}

func (e *ErrorCounter) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.total == 0 {
		return "no errors"
	}

	classes := make([]string, 0, len(e.byClass))
	for k := range e.byClass {
		classes = append(classes, k)
	}
	sort.Slice(classes, func(i, j int) bool {
		if e.byClass[classes[i]] != e.byClass[classes[j]] {
			return e.byClass[classes[i]] > e.byClass[classes[j]]
		}
		return classes[i] < classes[j]
	})

	var b strings.Builder
	fmt.Fprintf(&b, "%d errors:", e.total)
	for _, class := range classes {
		fmt.Fprintf(&b, "\n  %6d x %s (e.g. %s)", e.byClass[class], class, e.samples[class])
	}

	return b.String()
}

const (
	ErrClassEnvoyOverflow   = "envoy-circuit-breaker-overflow"
	ErrClassEnvoyNoUpstream = "envoy-no-healthy-upstream"
	ErrClassEnvoyReset      = "envoy-upstream-reset"
	ErrClassDeadline        = "deadline-exceeded"
	ErrClassCanceled        = "canceled"
	ErrClassConnRefused     = "connection-refused"
	ErrClassConnReset       = "connection-reset"
	ErrClassTooManyFiles    = "too-many-open-files"
	ErrClassAddrNotAvail    = "ephemeral-ports-exhausted"
	ErrClassEOF             = "eof"
	ErrClassTimeout         = "timeout"
)

func ClassifyError(err error) string {
	if err == nil {
		return ""
	}

	msg := err.Error()
	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "reset reason: overflow") ||
		strings.Contains(lower, "x-envoy-overloaded"):
		return ErrClassEnvoyOverflow
	case strings.Contains(lower, "no healthy upstream"):
		return ErrClassEnvoyNoUpstream
	case strings.Contains(lower, "upstream connect error") ||
		strings.Contains(lower, "disconnect/reset before headers"):
		return ErrClassEnvoyReset
	case errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		strings.Contains(lower, "too many open files"):
		return ErrClassTooManyFiles
	case errors.Is(err, syscall.EADDRNOTAVAIL) ||
		strings.Contains(lower, "cannot assign requested address"):
		return ErrClassAddrNotAvail
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(lower, "connection refused"):
		return ErrClassConnRefused
	case errors.Is(err, syscall.ECONNRESET) || strings.Contains(lower, "connection reset"):
		return ErrClassConnReset
	}

	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return fmt.Sprintf("grpc-%s", st.Code())
	}

	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded):
		return ErrClassDeadline
	case errors.Is(err, context.Canceled):
		return ErrClassCanceled
	case errors.As(err, &netErr) && netErr.Timeout():
		return ErrClassTimeout
	case strings.Contains(lower, "eof"):
		return ErrClassEOF
	}

	if idx := strings.IndexAny(msg, ":\n"); idx > 0 && idx < 60 {
		return strings.TrimSpace(msg[:idx])
	}
	if len(msg) > 60 {
		return msg[:60]
	}
	return msg
}

type PoolResult struct {
	Total     int
	Succeeded int
	Elapsed   time.Duration
	Latency   *Latencies
	Errors    *ErrorCounter
}

func (r *PoolResult) Failed() int {
	return r.Total - r.Succeeded
}

func (r *PoolResult) Rate() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	return float64(r.Succeeded) / r.Elapsed.Seconds()
}

func (r *PoolResult) String() string {
	return fmt.Sprintf("%d/%d succeeded in %s (%.1f/s). Latency %s. %s",
		r.Succeeded, r.Total, r.Elapsed.Truncate(time.Millisecond), r.Rate(),
		r.Latency.Summary(), r.Errors)
}

func ForEach(ctx context.Context, n, concurrency int,
	fn func(ctx context.Context, i int) error) *PoolResult {
	ret := &PoolResult{
		Total:   n,
		Latency: &Latencies{},
		Errors:  NewErrorCounter(),
	}

	if n <= 0 {
		return ret
	}

	concurrency = max(1, min(concurrency, n))

	var next atomic.Int64
	var succeeded atomic.Int64
	var wg sync.WaitGroup

	started := time.Now()

	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= n {
					return
				}

				if err := ctx.Err(); err != nil {
					ret.Errors.Add(err)
					continue
				}

				opStarted := time.Now()
				if err := fn(ctx, i); err != nil {
					ret.Errors.Add(err)
					continue
				}

				ret.Latency.Add(time.Since(opStarted))
				succeeded.Add(1)
			}
		}()
	}

	wg.Wait()

	ret.Elapsed = time.Since(started)
	ret.Succeeded = int(succeeded.Load())

	return ret
}

func RunFor(ctx context.Context, duration time.Duration, workers int,
	fn func(ctx context.Context, worker, iteration int) error) *PoolResult {
	ret := &PoolResult{
		Latency: &Latencies{},
		Errors:  NewErrorCounter(),
	}

	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	var total atomic.Int64
	var succeeded atomic.Int64
	var wg sync.WaitGroup

	started := time.Now()

	for worker := range max(1, workers) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iteration := 0; ctx.Err() == nil; iteration++ {
				opStarted := time.Now()
				err := fn(ctx, worker, iteration)
				if ctx.Err() != nil && err != nil {
					return
				}

				total.Add(1)
				if err != nil {
					ret.Errors.Add(err)
					continue
				}

				ret.Latency.Add(time.Since(opStarted))
				succeeded.Add(1)
			}
		}()
	}

	wg.Wait()

	ret.Elapsed = time.Since(started)
	ret.Total = int(total.Load())
	ret.Succeeded = int(succeeded.Load())

	return ret
}

func Jitter(base, spread time.Duration) time.Duration {
	if spread <= 0 {
		return base
	}
	return base + time.Duration(rand.Int64N(int64(spread)))
}

func Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func LogPool(what string, r *PoolResult) {
	zap.L().Info(what,
		zap.Int("total", r.Total),
		zap.Int("succeeded", r.Succeeded),
		zap.Duration("elapsed", r.Elapsed),
		zap.Float64("ratePerSecond", r.Rate()),
		zap.String("latency", r.Latency.Summary().String()),
		zap.Any("errors", r.Errors.Classes()))
}
