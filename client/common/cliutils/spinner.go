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

package cliutils

import (
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"

	"github.com/fatih/color"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
)

// The credit of the spinner code goes to the authors of https://github.com/kubernetes-sigs/kind

var spinnerFrames = []string{
	`⠋`,
	`⠙`,
	`⠹`,
	`⠸`,
	`⠼`,
	`⠴`,
	`⠦`,
	`⠧`,
	`⠇`,
	`⠏`,
}

type Spinner struct {
	stop    chan struct{}
	stopped chan struct{}
	mu      *sync.Mutex
	running bool
	writer  io.Writer
	ticker  *time.Ticker
	prefix  string
	suffix  string

	frameFormat string
}

func NewSpinner(w io.Writer) *Spinner {
	frameFormat := "\x1b[?7l\r%s %s %s (%s)\x1b[?7h"

	if runtime.GOOS == "windows" {
		frameFormat = "\r%s %s %s (%s)"
	}
	return &Spinner{
		stop:        make(chan struct{}, 1),
		stopped:     make(chan struct{}),
		mu:          &sync.Mutex{},
		writer:      w,
		frameFormat: frameFormat,
	}
}

func (s *Spinner) SetPrefix(prefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prefix = prefix
}

func (s *Spinner) SetSuffix(suffix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.suffix = suffix
}

func (s *Spinner) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.running = true
	s.ticker = time.NewTicker(time.Millisecond * 100)
	go func() {
		t := time.Now()
		for {
			for _, frame := range spinnerFrames {
				select {
				case <-s.stop:
					func() {
						s.mu.Lock()
						defer s.mu.Unlock()
						color.New(color.Bold).Fprintf(s.writer, s.frameFormat, s.prefix, "✓", s.suffix, utils_types.HumanDuration(time.Since(t)))
						fmt.Fprintf(s.writer, "\n")
						s.ticker.Stop()
						s.running = false
						s.stopped <- struct{}{}
					}()
					return

				case <-s.ticker.C:
					func() {
						s.mu.Lock()
						defer s.mu.Unlock()
						color.New(color.FgCyan, color.Bold).Fprintf(s.writer, s.frameFormat, s.prefix, frame, s.suffix, utils_types.HumanDuration(time.Since(t)))
					}()
				}
			}
		}
	}()
}

func (s *Spinner) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.stop <- struct{}{}
	s.mu.Unlock()
	<-s.stopped
}
