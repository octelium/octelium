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

package httputils

import (
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/pkg/errors"
)

const (
	defaultMaxRequestBodySize = 32 * 1024 * 1024
	maxRequestBodySize        = 64 * 1024 * 1024
)

func GetMaxRequestBodySize(svcCfg *corev1.Service_Spec_Config) int64 {
	cfg := svcCfg.GetHttp().GetBody()
	if cfg == nil || cfg.MaxRequestSize == 0 {
		return defaultMaxRequestBodySize
	}

	if int64(cfg.MaxRequestSize) > maxRequestBodySize {
		return maxRequestBodySize
	}

	return int64(cfg.MaxRequestSize)
}

func CheckPathChars(path string) error {
	for i := range len(path) {
		c := path[i]
		if c < 0x20 || c == 0x7f {
			return errors.Errorf("The request path contains an invalid control character")
		}
	}

	return nil
}

func HasDotSegmentCandidate(path string) bool {
	return strings.Contains(path, "/.") || strings.Contains(path, "\\.")
}

func HasBackslashDotSegment(path string) bool {
	start := 0

	for i := 0; i <= len(path); i++ {
		if i != len(path) && path[i] != '/' && path[i] != '\\' {
			continue
		}

		segment := path[start:i]
		if segment == "." || segment == ".." {
			leftBackslash := start > 0 && path[start-1] == '\\'
			rightBackslash := i < len(path) && path[i] == '\\'

			if leftBackslash || rightBackslash {
				return true
			}
		}

		start = i + 1
	}

	return false
}

func RemoveDotSegments(path string) (string, bool) {
	segments := strings.Split(path, "/")
	out := make([]string, 1, len(segments))
	changed := false

	for i, segment := range segments[1:] {
		isLast := i == len(segments)-2

		switch segment {
		case ".":
			changed = true
			if isLast {
				out = append(out, "")
			}
		case "..":
			changed = true
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
			if isLast {
				out = append(out, "")
			}
		default:
			out = append(out, segment)
		}
	}

	if !changed {
		return path, false
	}

	return strings.Join(out, "/"), true
}

func CleanPath(path string) (string, error) {
	if path == "" {
		return "", errors.Errorf("Empty request path")
	}

	if !strings.HasPrefix(path, "/") {
		return "", errors.Errorf("The request path is not absolute")
	}

	if err := CheckPathChars(path); err != nil {
		return "", err
	}

	if !HasDotSegmentCandidate(path) {
		return path, nil
	}

	if HasBackslashDotSegment(path) {
		return "", errors.Errorf("The request path contains an ambiguous backslash dot-segment")
	}

	cleanedPath, _ := RemoveDotSegments(path)

	return cleanedPath, nil
}
