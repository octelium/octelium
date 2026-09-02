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
	"regexp"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
)

var (
	rgxEmail      = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	rgxCreditCard = regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)
	rgxIBAN       = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)
)

var rgxUSSSNPlain = regexp.MustCompile(`\b(\d{3})[ \-]?(\d{2})[ \-]?(\d{4})\b`)

type detectorMatch struct {
	name  string
	start int
	end   int
}

func runDetector(typ corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Type,
	text string, maxFindings int) ([]detectorMatch, bool) {

	name := detectorName(typ)

	find := func(rgx *regexp.Regexp) ([][]int, bool) {
		locs := rgx.FindAllStringIndex(text, maxFindings+1)
		return locs, len(locs) > maxFindings
	}

	findSubmatch := func(rgx *regexp.Regexp) ([][]int, bool) {
		locs := rgx.FindAllStringSubmatchIndex(text, maxFindings+1)
		return locs, len(locs) > maxFindings
	}

	simple := func(rgx *regexp.Regexp) ([]detectorMatch, bool) {
		locs, isExhausted := find(rgx)
		var ret []detectorMatch
		for _, loc := range locs {
			ret = append(ret, detectorMatch{name: name, start: loc[0], end: loc[1]})
		}
		return ret, isExhausted
	}

	switch typ {
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_EMAIL:
		return simple(rgxEmail)
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_CREDIT_CARD:
		locs, isExhausted := find(rgxCreditCard)
		var ret []detectorMatch
		for _, loc := range locs {
			if !isLuhnValid(text[loc[0]:loc[1]]) {
				continue
			}
			ret = append(ret, detectorMatch{name: name, start: loc[0], end: loc[1]})
		}
		return ret, isExhausted
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_IBAN:
		locs, isExhausted := find(rgxIBAN)
		var ret []detectorMatch
		for _, loc := range locs {
			if !isIBANValid(text[loc[0]:loc[1]]) {
				continue
			}
			ret = append(ret, detectorMatch{name: name, start: loc[0], end: loc[1]})
		}
		return ret, isExhausted
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_US_SSN:
		locs, isExhausted := findSubmatch(rgxUSSSNPlain)
		var ret []detectorMatch
		for _, loc := range locs {
			area := text[loc[2]:loc[3]]
			group := text[loc[4]:loc[5]]
			serial := text[loc[6]:loc[7]]
			if area == "000" || area == "666" || area[0] == '9' ||
				group == "00" || serial == "0000" {
				continue
			}
			ret = append(ret, detectorMatch{name: name, start: loc[0], end: loc[1]})
		}
		return ret, isExhausted
	default:
		return nil, false
	}
}

func detectorName(typ corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Type) string {
	return strings.ToLower(typ.String())
}

func isLuhnValid(arg string) bool {
	var digits []int
	for i := 0; i < len(arg); i++ {
		switch {
		case arg[i] >= '0' && arg[i] <= '9':
			digits = append(digits, int(arg[i]-'0'))
		case arg[i] == ' ' || arg[i] == '-':
		default:
			return false
		}
	}

	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	var sum int
	isDouble := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if isDouble {
			d = d * 2
			if d > 9 {
				d = d - 9
			}
		}
		sum = sum + d
		isDouble = !isDouble
	}

	return sum%10 == 0
}

func isIBANValid(arg string) bool {
	arg = strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(arg))
	if len(arg) < 15 || len(arg) > 34 {
		return false
	}

	rearranged := arg[4:] + arg[:4]

	var remainder int
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			remainder = (remainder*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			val := int(c-'A') + 10
			remainder = (remainder*100 + val) % 97
		default:
			return false
		}
	}

	return remainder == 1
}
