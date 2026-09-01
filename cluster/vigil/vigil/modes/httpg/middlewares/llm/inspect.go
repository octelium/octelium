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

package llm

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
	maxGuardrailResponseBytes = 8 * 1024 * 1024
	maxPatternFindings        = 4096
	maxReplacementBytes       = 8 * 1024
	maxMutatedRequestBytes    = 32 * 1024 * 1024
	maxRegexCacheEntries      = 1024
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

type patternRule struct {
	cfg  *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern
	idx  int
	name string
	rgx  *regexp.Regexp
	typ  corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Type
}

func (r *patternRule) action() corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Action {
	if ret := r.cfg.GetAction(); ret !=
		corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_ACTION_UNSET {
		return ret
	}
	return corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_DENY
}

func (r *patternRule) isRewrite() bool {
	return rewriteRank(r.action()) > 0
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

type patternSet struct {
	rules []*patternRule
}

func newPatternSet(
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Guardrail) (*patternSet, error) {
	ret := &patternSet{}

	for i, conf := range cfg.GetPatterns() {
		rule := &patternRule{
			cfg:  conf,
			idx:  i,
			name: conf.GetName(),
		}

		switch conf.Match.(type) {
		case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Regex:
			rgx, err := compileRegex(conf.GetRegex())
			if err != nil {
				return nil, errors.Errorf("Could not compile the Guardrail Pattern %q",
					conf.GetName())
			}
			rule.rgx = rgx
		case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Type_:
			rule.typ = conf.GetType()
			if rule.name == "" {
				rule.name = detectorName(conf.GetType())
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

type finding struct {
	rule  *patternRule
	start int
	end   int
}

func (p *patternSet) inspect(text string) ([]*finding, error) {
	var ret []*finding

	for _, rule := range p.rules {
		var count int

		if rule.rgx != nil {
			for _, loc := range rule.rgx.FindAllStringIndex(text, maxPatternFindings+1) {
				ret = append(ret, &finding{rule: rule, start: loc[0], end: loc[1]})
				count++
			}
		} else {
			for _, m := range runDetector(rule.typ, text,
				rule.cfg.GetMinEntropyLength(), maxPatternFindings+1) {
				ret = append(ret, &finding{rule: rule, start: m.start, end: m.end})
				count++
			}
		}

		if count > maxPatternFindings {
			return nil, errors.Errorf(
				"The Guardrail Pattern %q matched too many times", rule.name)
		}
	}

	return ret, nil
}

func deniedFinding(findings []*finding) *finding {
	for _, f := range findings {
		if f.rule.action() ==
			corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_DENY {
			return f
		}
	}
	return nil
}

func rewrite(text string, findings []*finding,
	replacements map[int]string) (string, uint32, error) {

	sorted := make([]*finding, 0, len(findings))
	for _, f := range findings {
		if !f.rule.isRewrite() {
			continue
		}
		if f.start < 0 || f.end > len(text) || f.start >= f.end {
			continue
		}
		sorted = append(sorted, f)
	}

	if len(sorted) == 0 {
		return text, 0, nil
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].start != sorted[j].start {
			return sorted[i].start < sorted[j].start
		}
		if sorted[i].end != sorted[j].end {
			return sorted[i].end > sorted[j].end
		}
		return sorted[i].rule.idx < sorted[j].rule.idx
	})

	var merged []*finding
	for _, f := range sorted {
		if len(merged) == 0 {
			merged = append(merged, &finding{rule: f.rule, start: f.start, end: f.end})
			continue
		}

		cur := merged[len(merged)-1]
		if f.start > cur.end {
			merged = append(merged, &finding{rule: f.rule, start: f.start, end: f.end})
			continue
		}

		if f.end > cur.end {
			cur.end = f.end
		}
		if isRuleMoreDestructive(f.rule, cur.rule) {
			cur.rule = f.rule
		}
	}

	var projected int
	for _, f := range merged {
		projected = projected + len(findingReplacement(f, replacements))
	}
	if len(text)+projected > maxMutatedRequestBytes {
		return "", 0, errors.Errorf("The rewritten content is too large")
	}

	var out bytes.Buffer
	var count uint32
	last := 0
	for _, f := range merged {
		out.WriteString(text[last:f.start])
		out.WriteString(findingReplacement(f, replacements))
		last = f.end
		count++
	}
	out.WriteString(text[last:])

	return out.String(), count, nil
}

func isRuleMoreDestructive(arg, cur *patternRule) bool {
	argRank := rewriteRank(arg.action())
	curRank := rewriteRank(cur.action())
	if argRank != curRank {
		return argRank > curRank
	}
	return arg.idx < cur.idx
}

func findingReplacement(f *finding, replacements map[int]string) string {
	switch f.rule.action() {
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_STRIP:
		return ""
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REPLACE:
		return replacements[f.rule.idx]
	default:
		return redactPlaceholder(f.rule.name)
	}
}

func redactPlaceholder(name string) string {
	if name == "" {
		return "[REDACTED]"
	}
	return "[REDACTED:" + strings.ToUpper(name) + "]"
}

func guardrailDenyMessage(cfg *corev1.Service_Spec_Config_LLM_Plugin_Guardrail) string {
	if msg := cfg.GetDenyMessage(); msg != "" {
		return msg
	}
	return "Octelium: this content is not allowed by this Service"
}
