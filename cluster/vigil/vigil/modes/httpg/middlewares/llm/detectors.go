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
	"math"
	"regexp"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
)

const defaultMinEntropyLength = 24

var (
	rgxEmail      = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	rgxCreditCard = regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)
	rgxIBAN       = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)
	rgxAWSKey     = regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`)
	rgxGCPKey     = regexp.MustCompile(`"type"\s*:\s*"service_account"`)
	rgxPrivateKey = regexp.MustCompile(`-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`)
	rgxJWT        = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`)
	rgxEntropy    = regexp.MustCompile(`[A-Za-z0-9+/_\-]{16,}={0,2}`)
)

var rgxUSSSNPlain = regexp.MustCompile(`\b(\d{3})[ \-]?(\d{2})[ \-]?(\d{4})\b`)

type detectorMatch struct {
	name  string
	start int
	end   int
}

func runDetector(typ corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Type,
	text string, minEntropyLength uint32) []detectorMatch {

	name := detectorName(typ)

	simple := func(rgx *regexp.Regexp) []detectorMatch {
		var ret []detectorMatch
		for _, loc := range rgx.FindAllStringIndex(text, -1) {
			ret = append(ret, detectorMatch{name: name, start: loc[0], end: loc[1]})
		}
		return ret
	}

	switch typ {
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_EMAIL:
		return simple(rgxEmail)
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_CREDIT_CARD:
		var ret []detectorMatch
		for _, loc := range rgxCreditCard.FindAllStringIndex(text, -1) {
			if !isLuhnValid(text[loc[0]:loc[1]]) {
				continue
			}
			ret = append(ret, detectorMatch{name: name, start: loc[0], end: loc[1]})
		}
		return ret
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_IBAN:
		var ret []detectorMatch
		for _, loc := range rgxIBAN.FindAllStringIndex(text, -1) {
			if !isIBANValid(text[loc[0]:loc[1]]) {
				continue
			}
			ret = append(ret, detectorMatch{name: name, start: loc[0], end: loc[1]})
		}
		return ret
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_US_SSN:
		var ret []detectorMatch
		for _, loc := range rgxUSSSNPlain.FindAllStringSubmatchIndex(text, -1) {
			area := text[loc[2]:loc[3]]
			group := text[loc[4]:loc[5]]
			serial := text[loc[6]:loc[7]]
			if area == "000" || area == "666" || area[0] == '9' ||
				group == "00" || serial == "0000" {
				continue
			}
			ret = append(ret, detectorMatch{name: name, start: loc[0], end: loc[1]})
		}
		return ret
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_AWS_ACCESS_KEY:
		return simple(rgxAWSKey)
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_GCP_SERVICE_ACCOUNT_KEY:
		return simple(rgxGCPKey)
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_PRIVATE_KEY:
		return simple(rgxPrivateKey)
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_JWT:
		return simple(rgxJWT)
	case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_HIGH_ENTROPY:
		minLen := int(minEntropyLength)
		if minLen == 0 {
			minLen = defaultMinEntropyLength
		}
		var ret []detectorMatch
		for _, loc := range rgxEntropy.FindAllStringIndex(text, -1) {
			candidate := text[loc[0]:loc[1]]
			if len(candidate) < minLen {
				continue
			}
			if shannonEntropy(candidate) < 3.5 {
				continue
			}
			ret = append(ret, detectorMatch{name: name, start: loc[0], end: loc[1]})
		}
		return ret
	default:
		return nil
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

func shannonEntropy(arg string) float64 {
	if arg == "" {
		return 0
	}

	var counts [256]int
	for i := 0; i < len(arg); i++ {
		counts[arg[i]]++
	}

	var ret float64
	length := float64(len(arg))
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		ret = ret - p*math.Log2(p)
	}

	return ret
}
