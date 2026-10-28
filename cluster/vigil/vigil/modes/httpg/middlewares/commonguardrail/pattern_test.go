package commonguardrail

import (
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPatternSetConfiguration(t *testing.T) {
	for _, cfg := range [][]*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
		nil,
		{{}},
		{{Match: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Regex{Regex: "["}}},
	} {
		got, err := NewPatternSet(cfg)
		assert.NotNil(t, err)
		assert.Nil(t, got)
	}
	p, err := NewPatternSet([]*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
		{Match: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Regex{Regex: "secret"}},
	})
	require.Nil(t, err)
	findings, err := p.Inspect("a secret value")
	require.Nil(t, err)
	require.Len(t, findings, 1)
	assert.Same(t, findings[0], DeniedFinding(findings))
	assert.Equal(t, "secret", "a secret value"[findings[0].Start:findings[0].End])
	assert.Nil(t, DeniedFinding(nil))
}

func TestPatternDetectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Type
		text string
		want string
	}{
		{"Email", corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_EMAIL, "Contact me@example.com today", "me@example.com"},
		{"CreditCard", corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_CREDIT_CARD, "card 4111-1111-1111-1111.", "4111-1111-1111-1111"},
		{"IBAN", corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_IBAN, "account GB82WEST12345698765432.", "GB82WEST12345698765432"},
		{"SSN", corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_US_SSN, "ssn 123-45-6789.", "123-45-6789"},
		{"InvalidCard", corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_CREDIT_CARD, "4111-1111-1111-1112", ""},
		{"InvalidIBAN", corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_IBAN, "GB83WEST12345698765432", ""},
		{"InvalidSSNArea", corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_US_SSN, "000-45-6789 666-45-6789 999-45-6789", ""},
		{"InvalidSSNGroup", corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_US_SSN, "123-00-6789 123-45-0000", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matches, exhausted := runDetector(tc.typ, tc.text, 10)
			assert.False(t, exhausted)
			if tc.want == "" {
				assert.Empty(t, matches)
				return
			}
			require.Len(t, matches, 1)
			assert.Equal(t, tc.want, tc.text[matches[0].start:matches[0].end])
		})
	}
	assert.True(t, isLuhnValid("4111 1111 1111 1111"))
	assert.False(t, isLuhnValid("4111x111111111111"))
	assert.False(t, isLuhnValid("1"))
	assert.True(t, isIBANValid("gb82 west 1234 5698 7654 32"))
	assert.False(t, isIBANValid("GB82WEST1234569876543!"))
	assert.False(t, isIBANValid("GB82"))
}

func TestPatternFindingBudget(t *testing.T) {
	p, err := NewPatternSet([]*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
		{Match: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Regex{Regex: "x"}},
	})
	require.Nil(t, err)
	findings, err := p.Inspect(strings.Repeat("x", MaxPatternFindings))
	require.Nil(t, err)
	assert.Len(t, findings, MaxPatternFindings)
	_, err = p.Inspect(strings.Repeat("x", MaxPatternFindings+1))
	assert.NotNil(t, err)
	_, exhausted := runDetector(corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_EMAIL, "a@example.com b@example.com", 1)
	assert.True(t, exhausted)
}

func TestPatternRewriteOverlapPrecedence(t *testing.T) {
	redact := &Rule{Idx: 0, Cfg: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{Action: corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REDACT}}
	replace := &Rule{Idx: 1, Cfg: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{Action: corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REPLACE}}
	strip := &Rule{Idx: 2, Cfg: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{Action: corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_STRIP}}
	for _, tc := range []struct {
		name     string
		findings []*Finding
		want     string
		count    uint32
	}{
		{"Redact", []*Finding{{Rule: redact, Name: "email", Start: 1, End: 3}}, "a[REDACTED:EMAIL]def", 1},
		{"Replace", []*Finding{{Rule: replace, Start: 1, End: 3}}, "aVALUEdef", 1},
		{"Strip", []*Finding{{Rule: strip, Start: 1, End: 3}}, "adef", 1},
		{"Overlap", []*Finding{{Rule: redact, Start: 1, End: 4}, {Rule: strip, Start: 3, End: 5}}, "af", 1},
		{"Adjacent", []*Finding{{Rule: strip, Start: 1, End: 3}, {Rule: replace, Start: 3, End: 5}}, "aVALUEf", 2},
		{"InvalidOffsets", []*Finding{{Rule: strip, Start: -1, End: 3}, {Rule: redact, Start: 1, End: 20}, {Rule: redact, Start: 2, End: 2}}, "abcdef", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, count, err := Rewrite("abcdef", tc.findings, map[int]string{1: "VALUE"})
			require.Nil(t, err)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.count, count)
		})
	}
}

func TestPatternRewritePreservesUnicode(t *testing.T) {
	p, err := NewPatternSet([]*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
		{Match: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Regex{Regex: "秘密"}, Action: corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REDACT},
	})
	require.Nil(t, err)
	text := "🔒 秘密 café"
	findings, err := p.Inspect(text)
	require.Nil(t, err)
	got, count, err := Rewrite(text, findings, nil)
	require.Nil(t, err)
	assert.Equal(t, "🔒 [REDACTED] café", got)
	assert.Equal(t, uint32(1), count)
	assert.Nil(t, DeniedFinding(findings))
}
