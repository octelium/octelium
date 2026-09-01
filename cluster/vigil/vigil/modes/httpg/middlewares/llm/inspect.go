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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/pkg/errors"
)

const (
	defaultGuardrailMaxBytes = 1024 * 1024
	maxGuardrailMaxBytes     = 8 * 1024 * 1024
)

type patternRule struct {
	cfg  *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern
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
	switch r.action() {
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REDACT,
		corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_STRIP,
		corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REPLACE:
		return true
	default:
		return false
	}
}

type patternSet struct {
	rules []*patternRule
}

func newPatternSet(
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Guardrail) (*patternSet, error) {
	ret := &patternSet{}

	for _, conf := range cfg.GetPatterns() {
		rule := &patternRule{
			cfg:  conf,
			name: conf.GetName(),
		}

		switch conf.Match.(type) {
		case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Regex:
			rgx, err := regexp.Compile(conf.GetRegex())
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

func (p *patternSet) inspect(text string) []*finding {
	var ret []*finding

	for _, rule := range p.rules {
		if rule.rgx != nil {
			for _, loc := range rule.rgx.FindAllStringIndex(text, -1) {
				ret = append(ret, &finding{rule: rule, start: loc[0], end: loc[1]})
			}
			continue
		}

		for _, m := range runDetector(rule.typ, text, rule.cfg.GetMinEntropyLength()) {
			ret = append(ret, &finding{rule: rule, start: m.start, end: m.end})
		}
	}

	return ret
}

func findingRuleNames(findings []*finding) []string {
	seen := make(map[string]struct{}, len(findings))
	var ret []string
	for _, f := range findings {
		if _, ok := seen[f.rule.name]; ok {
			continue
		}
		seen[f.rule.name] = struct{}{}
		ret = append(ret, f.rule.name)
	}
	return ret
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
	replacements map[string]string) (string, uint32) {

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
		return text, 0
	}

	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].start != sorted[j].start {
			return sorted[i].start < sorted[j].start
		}
		return sorted[i].end > sorted[j].end
	})

	var merged []*finding
	for _, f := range sorted {
		if len(merged) == 0 {
			merged = append(merged, &finding{rule: f.rule, start: f.start, end: f.end})
			continue
		}
		cur := merged[len(merged)-1]
		if f.start <= cur.end {
			if f.end > cur.end {
				cur.end = f.end
			}
			continue
		}
		merged = append(merged, &finding{rule: f.rule, start: f.start, end: f.end})
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

	return out.String(), count
}

func findingReplacement(f *finding, replacements map[string]string) string {
	switch f.rule.action() {
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_STRIP:
		return ""
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REPLACE:
		return replacements[f.rule.name]
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

func guardrailMaxBytes(arg uint32) int {
	if arg == 0 {
		return defaultGuardrailMaxBytes
	}
	return min(int(arg), maxGuardrailMaxBytes)
}

func guardrailDenyMessage(cfg *corev1.Service_Spec_Config_LLM_Plugin_Guardrail) string {
	if msg := cfg.GetDenyMessage(); msg != "" {
		return msg
	}
	return "Octelium: this content is not allowed by this Service"
}
