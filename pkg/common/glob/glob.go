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

package glob

import (
	"strings"

	"github.com/pkg/errors"
)

const (
	MaxPatternLen = 256
	maxStars      = 16
)

func Validate(pattern string) error {
	if pattern == "" {
		return errors.Errorf("The pattern is empty")
	}
	if len(pattern) > MaxPatternLen {
		return errors.Errorf("The pattern is too long: %d", len(pattern))
	}
	if strings.Count(pattern, "*") > maxStars {
		return errors.Errorf("The pattern has too many wildcards: %s", pattern)
	}
	for i := 0; i < len(pattern); i++ {
		if pattern[i] < 0x20 || pattern[i] == 0x7f {
			return errors.Errorf("The pattern contains a control character")
		}
	}

	return nil
}

func Match(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}

	parts := strings.Split(pattern, "*")

	if head := parts[0]; head != "" {
		if !strings.HasPrefix(s, head) {
			return false
		}
		s = s[len(head):]
	}

	if tail := parts[len(parts)-1]; tail != "" {
		if len(s) < len(tail) || !strings.HasSuffix(s, tail) {
			return false
		}
		s = s[:len(s)-len(tail)]
	}

	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		idx := strings.Index(s, part)
		if idx < 0 {
			return false
		}
		s = s[idx+len(part):]
	}

	return true
}

func MatchAny(patterns []string, s string) bool {
	for _, pattern := range patterns {
		if Match(pattern, s) {
			return true
		}
	}
	return false
}
