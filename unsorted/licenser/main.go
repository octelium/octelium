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

package main

import (
	"bytes"
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func main() {
	if err := doMain(context.Background()); err != nil {
		panic(err)
	}
}

func doMain(ctx context.Context) error {
	clusterComponents := []string{
		"apiserver",
		"authserver",
		"common",
		"dnsserver",
		"genesis",
		"gwagent",
		"ingress",
		"nocturne",
		"nodeinit",
		"octovigil",
		"portal",
		"rscserver",
		"vigil",
		"wrdpgw",
	}

	clientComponents := []string{
		"octelium",
		"octeliumctl",
		"octops",
	}

	additionalApacheModules := []string{
		"apis",
		"octelium-go",
		"pkg",
	}

	agplv3, err := os.ReadFile("./unsorted/licenser/agplv3.txt")
	if err != nil {
		return err
	}

	apachev2, err := os.ReadFile("./unsorted/licenser/apachev2.txt")
	if err != nil {
		return err
	}

	if err := os.WriteFile("LICENSE-APACHE", apachev2, 0666); err != nil {
		return err
	}

	if err := os.WriteFile("LICENSE-AGPL-3.0", agplv3, 0666); err != nil {
		return err
	}

	for _, comp := range clusterComponents {
		if err := os.WriteFile(path.Join("cluster", comp, "LICENSE"), agplv3, 0666); err != nil {
			return err
		}
	}

	for _, comp := range clientComponents {
		if err := os.WriteFile(path.Join("client", comp, "LICENSE"), apachev2, 0666); err != nil {
			return err
		}
	}

	for _, mod := range additionalApacheModules {
		if err := os.WriteFile(path.Join(mod, "LICENSE"), apachev2, 0666); err != nil {
			return err
		}
	}

	if err := setHeader(ctx, "./apis", apacheHeader); err != nil {
		return err
	}

	if err := setHeader(ctx, "./octelium-go", apacheHeader); err != nil {
		return err
	}

	if err := setHeader(ctx, "./pkg", apacheHeader); err != nil {
		return err
	}

	if err := setHeader(ctx, "./client", apacheHeader); err != nil {
		return err
	}

	if err := setHeader(ctx, "./cluster", agplHeader); err != nil {
		return err
	}

	return nil
}

func setClusterHeader(ctx context.Context) error {
	return setHeader(ctx, "./cluster", agplHeader)
}

func setClientHeader(ctx context.Context) error {
	return setHeader(ctx, "./client/octeliumctl", apacheHeader)
}

func setHeader(ctx context.Context, rootPath string, header string) error {
	_ = ctx

	return filepath.Walk(rootPath, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if shouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		if !strings.HasSuffix(filePath, ".go") {
			return nil
		}

		cn, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}

		newFile, ok := applyHeader(string(cn), header)
		if !ok {
			return nil
		}

		if newFile == string(cn) {
			return nil
		}

		return os.WriteFile(filePath, []byte(newFile), info.Mode().Perm())
	})
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", ".idea", ".vscode", "node_modules", "vendor", "dist", "build", "target", ".libs":
		return true
	default:
		return false
	}
}

func applyHeader(src string, header string) (string, bool) {
	src = strings.ReplaceAll(src, "\r\n", "\n")

	pkgIdx := packageIdx(src)
	if pkgIdx < 0 {
		return "", false
	}

	prefix := src[:pkgIdx]
	body := src[pkgIdx:]

	buildLines, remainingPrefix := extractBuildConstraints(prefix)
	remainingPrefix = stripKnownLicenseHeaders(remainingPrefix)
	remainingPrefix = strings.TrimLeft(remainingPrefix, "\n")

	var b strings.Builder

	if len(buildLines) > 0 {
		b.WriteString(strings.Join(buildLines, "\n"))
		b.WriteString("\n\n")
	}

	b.WriteString(strings.TrimRight(header, "\n"))
	b.WriteString("\n\n")

	if remainingPrefix != "" {
		b.WriteString(remainingPrefix)
		if !strings.HasSuffix(remainingPrefix, "\n") {
			b.WriteString("\n")
		}
	}

	b.WriteString(body)

	return b.String(), true
}

func packageIdx(src string) int {
	offset := 0

	for _, line := range splitLinesKeepingEnd(src) {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "package ") {
			return offset + len(line) - len(trimmed)
		}
		offset += len(line)
	}

	return -1
}

func extractBuildConstraints(prefix string) ([]string, string) {
	var goBuildLines []string
	var plusBuildLines []string
	var remaining []string

	for _, line := range splitLinesKeepingEnd(prefix) {
		lineNoEnd := strings.TrimRight(line, "\n")
		trimmed := strings.TrimSpace(lineNoEnd)

		switch {
		case strings.HasPrefix(trimmed, "//go:build"):
			goBuildLines = append(goBuildLines, lineNoEnd)
		case strings.HasPrefix(trimmed, "// +build"):
			plusBuildLines = append(plusBuildLines, lineNoEnd)
		default:
			remaining = append(remaining, line)
		}
	}

	buildLines := make([]string, 0, len(goBuildLines)+len(plusBuildLines))
	buildLines = append(buildLines, goBuildLines...)
	buildLines = append(buildLines, plusBuildLines...)

	return buildLines, strings.Join(remaining, "")
}

func stripKnownLicenseHeaders(s string) string {
	headers := []string{
		apacheHeader,
		agplHeader,
	}

	for {
		before := s
		s = strings.TrimLeft(s, " \t\n")

		matched := false
		for _, hdr := range headers {
			h := strings.TrimRight(strings.ReplaceAll(hdr, "\r\n", "\n"), "\n")
			if strings.HasPrefix(s, h) {
				s = s[len(h):]
				matched = true
				break
			}
		}

		if !matched || s == before {
			break
		}
	}

	return strings.TrimLeft(s, " \t\n")
}

func splitLinesKeepingEnd(s string) []string {
	if s == "" {
		return nil
	}

	var ret []string
	for len(s) > 0 {
		idx := strings.IndexByte(s, '\n')
		if idx < 0 {
			ret = append(ret, s)
			break
		}

		ret = append(ret, s[:idx+1])
		s = s[idx+1:]
	}

	return ret
}

func getIdx(src []byte) int {
	ret := bytes.Index(src, []byte("package "))
	if idx := bytes.Index(src, []byte("//go:build")); idx >= 0 && idx < ret {
		ret = idx
	}

	if idx := bytes.Index(src, []byte("// +build")); idx >= 0 && idx < ret {
		ret = idx
	}

	if idx := bytes.Index(src, []byte("// Code generated")); idx >= 0 && idx < ret {
		ret = idx
	}

	return ret
}

const apacheHeader = `// Copyright Octelium Labs, LLC. All rights reserved.
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
`

const agplHeader = `/*
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
`
