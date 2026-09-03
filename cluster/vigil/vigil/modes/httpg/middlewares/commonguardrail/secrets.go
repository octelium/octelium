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

package commonguardrail

import (
	"strings"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/pkg/errors"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"go.uber.org/zap"
)

const (
	secretMatchTimeout           = 500 * time.Millisecond
	maxSecretOccurrenceScanBytes = 256 * 1024 * 1024
)

type secretScanner struct {
	mu      sync.Mutex
	matcher matcher.Matcher
}

var (
	secretScannerOnce sync.Once
	secretScannerRef  *secretScanner
	secretScannerErr  error
)

func getSecretScanner() (*secretScanner, error) {
	secretScannerOnce.Do(func() {
		startedAt := time.Now()

		rules, err := rule.NewLoader().LoadBuiltinRules()
		if err != nil {
			secretScannerErr = err
			return
		}
		rules = rule.FilterNoisy(rules, false)

		m, err := matcher.New(matcher.Config{
			Rules:        rules,
			MatchTimeout: secretMatchTimeout,
		})
		if err != nil {
			secretScannerErr = err
			return
		}

		secretScannerRef = &secretScanner{matcher: m}

		zap.L().Debug("Loaded the Guardrail secret detector",
			zap.Int("rules", len(rules)),
			zap.Duration("duration", time.Since(startedAt)))
	})

	if secretScannerErr != nil {
		return nil, secretScannerErr
	}

	return secretScannerRef, nil
}

func WarmSecretScanner() {
	go func() {
		if _, err := getSecretScanner(); err != nil {
			zap.L().Warn("Could not load the Guardrail secret detector",
				zap.Error(err))
		}
	}()
}

func HasSecretsPattern(svc *corev1.Service) bool {
	cfgs := append([]*corev1.Service_Spec_Config{svc.GetSpec().GetConfig()},
		svc.GetSpec().GetDynamicConfig().GetConfigs()...)

	hasSecrets := func(
		patterns []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern) bool {
		for _, pattern := range patterns {
			if pattern.GetSecrets() != nil {
				return true
			}
		}
		return false
	}

	for _, cfg := range cfgs {
		for _, plugin := range cfg.GetLlm().GetPlugins() {
			if hasSecrets(plugin.GetGuardrail().GetPatterns()) {
				return true
			}
		}
		for _, plugin := range cfg.GetMcp().GetPlugins() {
			if hasSecrets(plugin.GetGuardrail().GetPatterns()) {
				return true
			}
		}
	}

	return false
}

type secretMatch struct {
	rule  string
	start int
	end   int
}

func (s *secretScanner) scan(text string, maxFindings int) ([]*secretMatch, error) {
	s.mu.Lock()
	matches, err := s.matcher.Match([]byte(text))
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	var ret []*secretMatch
	seen := make(map[[2]int]struct{})
	budget := maxSecretOccurrenceScanBytes

	for _, m := range matches {
		start := int(m.Location.Offset.Start)
		end := int(m.Location.Offset.End)
		if start < 0 || end > len(text) || start >= end {
			continue
		}
		if _, ok := seen[[2]int{start, end}]; ok {
			continue
		}

		budget = budget - (len(text) - start)
		if budget < 0 {
			return nil, errors.Errorf("The secret detector matched too many times")
		}

		for _, span := range findAllOccurrences(
			text[start:], text[start:end], maxFindings+1) {

			cur := [2]int{start + span[0], start + span[1]}
			if _, ok := seen[cur]; ok {
				continue
			}
			seen[cur] = struct{}{}
			ret = append(ret, &secretMatch{rule: m.RuleID, start: cur[0], end: cur[1]})
		}

		if len(ret) > maxFindings {
			return nil, errors.Errorf("The secret detector matched too many times")
		}
	}

	return ret, nil
}

func findAllOccurrences(text, arg string, maxOccurrences int) [][2]int {
	var ret [][2]int

	for i := 0; i < len(text) && len(ret) < maxOccurrences; {
		idx := strings.Index(text[i:], arg)
		if idx < 0 {
			break
		}
		ret = append(ret, [2]int{i + idx, i + idx + len(arg)})
		i = i + idx + len(arg)
	}

	return ret
}
