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
	"bytes"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/pkg/errors"
)

const (
	MaxResponseBytes    = 8 * 1024 * 1024
	MaxPatternFindings  = 4096
	MaxReplacementBytes = 8 * 1024
	MaxMutatedBytes     = 32 * 1024 * 1024

	maxRegexCacheEntries = 1024
)

var rgxCache sync.Map
var rgxCacheLen atomic.Int64

func compileRegex(arg string) (*regexp.Regexp, error) {
	if val, ok := rgxCache.Load(arg); ok {
		return val.(*regexp.Regexp), nil
	}

	ret, err := regexp.Compile(arg)
	if err != nil {
		return nil, err
	}

	if rgxCacheLen.Load() >= maxRegexCacheEntries {
		rgxCache.Range(func(k, _ any) bool {
			rgxCache.Delete(k)
			return false
		})
		rgxCacheLen.Add(-1)
	}

	if _, isLoaded := rgxCache.LoadOrStore(arg, ret); !isLoaded {
		rgxCacheLen.Add(1)
	}

	return ret, nil
}

type Rule struct {
	Cfg *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern
	Idx int

	name      string
	rgx       *regexp.Regexp
	typ       corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Type
	isSecrets bool
	excludes  map[string]struct{}
}

func (r *Rule) isExcluded(arg string) bool {
	_, ok := r.excludes[strings.ToLower(arg)]
	return ok
}

func (r *Rule) Action() corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Action {
	if ret := r.Cfg.GetAction(); ret !=
		corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_ACTION_UNSET {
		return ret
	}
	return corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_DENY
}

func (r *Rule) IsRewrite() bool {
	return rewriteRank(r.Action()) > 0
}

func rewriteRank(
	action corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Action) int {
	switch action {
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_STRIP:
		return 3
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REPLACE:
		return 2
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REDACT:
		return 1
	default:
		return 0
	}
}

type PatternSet struct {
	rules []*Rule
}

func NewPatternSet(
	patterns []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern) (*PatternSet, error) {
	ret := &PatternSet{}

	for i, conf := range patterns {
		rule := &Rule{
			Cfg: conf,
			Idx: i,
		}

		switch conf.Match.(type) {
		case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Regex:
			rgx, err := compileRegex(conf.GetRegex())
			if err != nil {
				return nil, errors.Errorf("Could not compile the Guardrail Pattern %d", i)
			}
			rule.rgx = rgx
		case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Type_:
			rule.typ = conf.GetType()
			rule.name = detectorName(conf.GetType())
		case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Secrets_:
			rule.isSecrets = true
			rule.excludes = make(map[string]struct{})
			for _, exclude := range conf.GetSecrets().GetExcludeRules() {
				rule.excludes[strings.ToLower(exclude)] = struct{}{}
			}
		default:
			return nil, errors.Errorf("The Guardrail Pattern match is not set")
		}

		ret.rules = append(ret.rules, rule)
	}

	if len(ret.rules) == 0 {
		return nil, errors.Errorf("The Guardrail carries no Pattern")
	}

	return ret, nil
}

type Finding struct {
	Rule  *Rule
	Name  string
	Start int
	End   int
}

func (p *PatternSet) Inspect(text string) ([]*Finding, error) {
	var ret []*Finding
	var secrets []*secretMatch
	var isScanned bool

	for _, rule := range p.rules {
		var count int

		switch {
		case rule.rgx != nil:
			for _, loc := range rule.rgx.FindAllStringIndex(text, MaxPatternFindings+1) {
				ret = append(ret, &Finding{Rule: rule, Start: loc[0], End: loc[1]})
				count++
			}
		case rule.isSecrets:
			if !isScanned {
				scanner, err := getSecretScanner()
				if err != nil {
					return nil, err
				}
				matches, err := scanner.scan(text, MaxPatternFindings)
				if err != nil {
					return nil, err
				}
				secrets = matches
				isScanned = true
			}
			for _, m := range secrets {
				if rule.isExcluded(m.rule) {
					continue
				}
				ret = append(ret, &Finding{
					Rule: rule, Name: m.rule, Start: m.start, End: m.end})
				count++
			}
		default:
			matches, isExhausted := runDetector(rule.typ, text, MaxPatternFindings)
			if isExhausted {
				return nil, errors.Errorf(
					"The Guardrail Pattern %d matched too many times", rule.Idx)
			}
			for _, m := range matches {
				ret = append(ret, &Finding{Rule: rule, Start: m.start, End: m.end})
				count++
			}
		}

		if count > MaxPatternFindings {
			return nil, errors.Errorf(
				"The Guardrail Pattern %d matched too many times", rule.Idx)
		}
	}

	return ret, nil
}

func DeniedFinding(findings []*Finding) *Finding {
	for _, f := range findings {
		if f.Rule.Action() ==
			corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_DENY {
			return f
		}
	}
	return nil
}

func Rewrite(text string, findings []*Finding,
	replacements map[int]string) (string, uint32, error) {

	sorted := make([]*Finding, 0, len(findings))
	for _, f := range findings {
		if !f.Rule.IsRewrite() {
			continue
		}
		if f.Start < 0 || f.End > len(text) || f.Start >= f.End {
			continue
		}
		sorted = append(sorted, f)
	}

	if len(sorted) == 0 {
		return text, 0, nil
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		if sorted[i].End != sorted[j].End {
			return sorted[i].End > sorted[j].End
		}
		return sorted[i].Rule.Idx < sorted[j].Rule.Idx
	})

	var merged []*Finding
	for _, f := range sorted {
		if len(merged) == 0 {
			merged = append(merged, &Finding{
				Rule: f.Rule, Name: f.Name, Start: f.Start, End: f.End})
			continue
		}

		cur := merged[len(merged)-1]
		if f.Start >= cur.End {
			merged = append(merged, &Finding{
				Rule: f.Rule, Name: f.Name, Start: f.Start, End: f.End})
			continue
		}

		if f.End > cur.End {
			cur.End = f.End
		}
		if isRuleMoreDestructive(f.Rule, cur.Rule) {
			cur.Rule = f.Rule
			cur.Name = f.Name
		}
	}

	projected := len(text)
	for _, f := range merged {
		projected = projected - (f.End - f.Start) +
			len(findingReplacement(f, replacements))
	}
	if projected > MaxMutatedBytes {
		return "", 0, errors.Errorf("The rewritten content is too large")
	}

	var out bytes.Buffer
	var count uint32
	last := 0
	for _, f := range merged {
		out.WriteString(text[last:f.Start])
		out.WriteString(findingReplacement(f, replacements))
		last = f.End
		count++
	}
	out.WriteString(text[last:])

	return out.String(), count, nil
}

func isRuleMoreDestructive(arg, cur *Rule) bool {
	argRank := rewriteRank(arg.Action())
	curRank := rewriteRank(cur.Action())
	if argRank != curRank {
		return argRank > curRank
	}
	return arg.Idx < cur.Idx
}

func findingReplacement(f *Finding, replacements map[int]string) string {
	switch f.Rule.Action() {
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_STRIP:
		return ""
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REPLACE:
		return replacements[f.Rule.Idx]
	default:
		if f.Name != "" {
			return redactPlaceholder(f.Name)
		}
		return redactPlaceholder(f.Rule.name)
	}
}

func redactPlaceholder(name string) string {
	if name == "" {
		return "[REDACTED]"
	}
	return "[REDACTED:" + strings.ToUpper(name) + "]"
}
