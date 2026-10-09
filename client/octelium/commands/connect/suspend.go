// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connect

import (
	"context"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	suspendCheckInterval = 5 * time.Second
	suspendMinDuration   = 10 * time.Second
	resumeProbeTimeout   = 5 * time.Second
)

func getSuspendDuration(prev, cur time.Time) time.Duration {
	ret := max(cur.Sub(prev), cur.Round(0).Sub(prev.Round(0))) - suspendCheckInterval
	if ret < suspendMinDuration {
		return 0
	}

	return ret
}

func watchSuspend(ctx context.Context,
	tickCh <-chan time.Time, nowFn func() time.Time, resumeCh chan<- time.Duration) {
	prev := nowFn()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickCh:
			cur := nowFn()
			suspended := getSuspendDuration(prev, cur)
			prev = cur

			if suspended == 0 {
				continue
			}

			zap.L().Debug("The host has resumed", zap.Duration("suspended", suspended))

			select {
			case resumeCh <- suspended:
			default:
			}
		}
	}
}

func probeConnection(ctx context.Context, cl userv1.MainServiceClient) error {
	ctx, cancel := context.WithTimeout(ctx, resumeProbeTimeout)
	defer cancel()

	_, err := cl.GetStatus(ctx, &userv1.GetStatusRequest{}, grpc_retry.Disable())
	switch {
	case err == nil:
		return nil
	case ctx.Err() != nil, grpcerr.IsUnavailable(err), grpcerr.IsDeadlineExceeded(err):
		return errors.Wrap(err, "The Cluster did not respond")
	default:
		zap.L().Debug("The Cluster responded to the probe with an error", zap.Error(err))
		return nil
	}
}
