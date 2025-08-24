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

//go:build !windows
// +build !windows

package connect

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
)

func doConnect(ctx context.Context, domain string) error {

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	ctx, cancelFn := context.WithCancel(ctx)
	go func() {
		<-signalCh
		zap.L().Debug("Received shutdown signal")
		cancelFn()
	}()

	return connect(ctx, domain)
}
