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

package k8sretry

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/wait"
)

func IsTransient(err error) bool {
	var networkError *net.OpError
	var dnsError *net.DNSError
	var timeoutError net.Error
	return k8serr.IsTimeout(err) || k8serr.IsServerTimeout(err) || k8serr.IsTooManyRequests(err) ||
		k8serr.IsServiceUnavailable(err) || k8serr.IsInternalError(err) || k8serr.IsUnexpectedServerError(err) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		utilnet.IsConnectionReset(err) || utilnet.IsConnectionRefused(err) || utilnet.IsHTTP2ConnectionLost(err) ||
		errors.As(err, &networkError) || errors.As(err, &dnsError) ||
		(errors.As(err, &timeoutError) && (timeoutError.Timeout() || timeoutError.Temporary()))
}

func Do(ctx context.Context, fn func(context.Context) error) error {
	return Retry(ctx, wait.Backoff{Steps: 15, Duration: 400 * time.Millisecond, Factor: 1.4, Jitter: 0.2}, fn)
}

func Read[T any](ctx context.Context, fn func(context.Context) (T, error)) (T, error) {
	var result T
	err := Do(ctx, func(ctx context.Context) error {
		var err error
		result, err = fn(ctx)
		return err
	})
	return result, err
}

func Create[T metav1.Object](ctx context.Context, object T, create, get func(context.Context) (T, error)) (T, error) {
	var result T
	name, namespace := object.GetName(), object.GetNamespace()
	if name == "" {
		return result, errors.New("A stable resource name is required for retryable creation")
	}
	var createErr error
	readback := false
	err := Do(ctx, func(ctx context.Context) error {
		if !readback {
			result, createErr = create(ctx)
			if createErr == nil {
				if result.GetName() != name || (namespace != "" && result.GetNamespace() != namespace) {
					return errors.New("The created resource identity differs from the requested identity")
				}
				return nil
			}
			if !k8serr.IsAlreadyExists(createErr) && !IsTransient(createErr) {
				return createErr
			}
			readback = true
		}
		var err error
		result, err = get(ctx)
		if err == nil && (result.GetName() != name || (namespace != "" && result.GetNamespace() != namespace)) {
			return errors.New("The resource readback identity differs from the requested identity")
		}
		if k8serr.IsNotFound(err) {
			readback = false
			if k8serr.IsAlreadyExists(createErr) {
				return k8serr.NewConflict(schema.GroupResource{}, "", err)
			}
			return createErr
		}
		return err
	})
	if err != nil && createErr != nil && !errors.Is(err, createErr) {
		return result, errors.Join(err, createErr)
	}
	return result, err
}

func Delete[T metav1.Object](ctx context.Context, object T, get func(context.Context) (T, error), remove func(context.Context, metav1.DeleteOptions) error) error {
	uid, version := object.GetUID(), object.GetResourceVersion()
	readback := false
	var deleteErr error
	return Do(ctx, func(ctx context.Context) error {
		if !readback {
			deleteErr = remove(ctx, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &version}})
			if deleteErr == nil || k8serr.IsNotFound(deleteErr) {
				return nil
			}
			if !IsTransient(deleteErr) && !k8serr.IsConflict(deleteErr) {
				return deleteErr
			}
			readback = true
		}
		current, err := get(ctx)
		if k8serr.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.GetUID() != uid {
			return errors.New("The resource was replaced. Refusing to delete the replacement")
		}
		if current.GetDeletionTimestamp() != nil {
			return nil
		}
		if current.GetResourceVersion() != version {
			return errors.New("The resource changed. Refusing to delete it")
		}
		readback = false
		return deleteErr
	})
}

func Retry(ctx context.Context, backoff wait.Backoff, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	steps := backoff.Steps
	if steps < 1 {
		steps = 1
	}
	var lastErr error
	for attempt := 0; attempt < steps; attempt++ {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, lastErr)
		}
		requestCtx, requestCancel := context.WithTimeout(ctx, 10*time.Second)
		lastErr = fn(requestCtx)
		requestCancel()
		if err := ctx.Err(); err != nil {
			return errors.Join(err, lastErr)
		}
		if lastErr == nil || (!IsTransient(lastErr) && !k8serr.IsConflict(lastErr)) || attempt == steps-1 {
			return lastErr
		}
		delay := backoff.Step()
		if seconds, ok := k8serr.SuggestsClientDelay(lastErr); ok && time.Duration(seconds)*time.Second > delay {
			delay = time.Duration(seconds) * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
	return lastErr
}

func Wait(ctx context.Context, interval, timeout time.Duration, check func(context.Context) (bool, error)) error {
	if interval <= 0 || timeout <= 0 {
		return errors.New("The polling interval and timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, lastErr)
		}
		requestCtx, requestCancel := context.WithTimeout(ctx, 10*time.Second)
		ready, err := check(requestCtx)
		requestCancel()
		lastErr = err
		if err := ctx.Err(); err != nil {
			return errors.Join(err, lastErr)
		}
		if err == nil && ready {
			return nil
		}
		if err != nil && !IsTransient(err) && !k8serr.IsConflict(err) {
			return err
		}
		delay := wait.Jitter(interval, 0.2)
		if seconds, ok := k8serr.SuggestsClientDelay(err); ok && time.Duration(seconds)*time.Second > delay {
			delay = time.Duration(seconds) * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}
