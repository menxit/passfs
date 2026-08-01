package main

import (
	"bytes"
	"strings"
	"testing"
)

const (
	sampleLowerAlnum = "abcdefghijklmnopqrstuvwxyz0123456789"
	sampleUpperAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	sampleHex        = "0123456789abcdef"
)

// One realistic sample per rule keeps every pattern honest: a rule without a
// matching sample fails TestSecretTokenRulesMatchSamples.
var secretTokenRuleSamples = map[string]string{
	"age-secret-key": "AGE-SECRET-KEY-1" +
		"QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" +
		"QPZRY9X8GF2TVDW0S3JN54KHCE",
	"anthropic-api-key": "sk-ant-api03-" +
		sampleLowerAlnum + sampleLowerAlnum + sampleUpperAlpha[:21] + "AA",
	"aws-access-token":       "AKIA" + "Q7ZP3M5X2JW4KBT6",
	"azure-ad-client-secret": "abc8Q~" + sampleLowerAlnum[:32],
	"databricks-api-token":   "dapi" + sampleHex + sampleHex,
	"digitalocean-token": "dop_v1_" +
		sampleHex + sampleHex + sampleHex + sampleHex,
	"doppler-api-token": "dp.pt." + sampleLowerAlnum + sampleLowerAlnum[:7],
	"gcp-api-key":       "AIza" + sampleLowerAlnum[:35],
	"github-token":      "ghp_" + sampleLowerAlnum,
	"github-fine-grained-pat": "github_pat_" +
		sampleLowerAlnum + sampleLowerAlnum + sampleLowerAlnum[:10],
	"gitlab-pat":                         "glpat-" + sampleLowerAlnum[:20],
	"gitlab-ptt":                         "glptt-" + sampleHex + sampleHex + sampleHex[:8],
	"gitlab-rrt":                         "GR1348941" + sampleLowerAlnum[:20],
	"gitlab-runner-authentication-token": "glrt-" + sampleLowerAlnum[:20],
	"gitlab-oauth-app-secret": "gloas-" +
		sampleLowerAlnum + sampleUpperAlpha + "01",
	"grafana-api-key": "eyJrIjoi" + sampleLowerAlnum + sampleLowerAlnum,
	"grafana-cloud-api-token": "glc_" +
		sampleLowerAlnum[:32],
	"grafana-service-account-token": "glsa_" +
		sampleLowerAlnum[:32] + "_" + sampleHex[:8],
	"hashicorp-tf-api-token": sampleLowerAlnum[:14] + ".atlasv1." +
		sampleLowerAlnum + sampleLowerAlnum[:24],
	"huggingface-access-token": "hf_" +
		sampleLowerAlnum[:26] + sampleUpperAlpha[:8],
	"jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
		".eyJzdWIiOiIxMjM0NTY3ODkwIn0" +
		".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
	"linear-api-key":   "lin_api_" + sampleLowerAlnum + sampleLowerAlnum[:4],
	"npm-access-token": "npm_" + sampleLowerAlnum,
	"1password-service-account-token": "ops_eyJ" +
		strings.Repeat(sampleLowerAlnum, 7),
	"openai-api-key": "sk-" + sampleLowerAlnum[:20] +
		"T3BlbkFJ" + sampleLowerAlnum[:20],
	"perplexity-api-key": "pplx-" + sampleLowerAlnum + sampleLowerAlnum[:12],
	"planetscale-token":  "pscale_tkn_" + sampleLowerAlnum[:32],
	"postman-api-token": "PMAK-" + sampleHex + sampleHex[:8] +
		"-" + sampleHex + sampleHex + sampleHex[:2],
	"private-key": "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		sampleLowerAlnum + "\n" + sampleUpperAlpha + sampleLowerAlnum + "\n" +
		"-----END OPENSSH PRIVATE KEY-----",
	"pulumi-api-token":  "pul-" + sampleHex + sampleHex + sampleHex[:8],
	"pypi-upload-token": "pypi-AgEIcHlwaS5vcmc" + sampleLowerAlnum + sampleLowerAlnum[:14],
	"rubygems-api-token": "rubygems_" +
		sampleHex + sampleHex + sampleHex,
	"sendgrid-api-token": "SG." + sampleLowerAlnum + sampleLowerAlnum[:30],
	"shopify-token":      "shpat_" + sampleHex + sampleHex,
	"slack-bot-token": "xoxb-123456789012-109876543210-" +
		sampleLowerAlnum[:24],
	"slack-user-token": "xoxp-12345678901-12345678901-12345678901-" +
		sampleLowerAlnum[:28],
	"slack-app-token": "xapp-1-A0B1C2D3E4F-123456789012-" +
		sampleLowerAlnum[:24],
	"slack-legacy-token":           "xoxs-123456-789012-345678-" + sampleHex[:12],
	"slack-legacy-workspace-token": "xoxa-2-" + sampleLowerAlnum[:24],
	"slack-webhook-url": "https://hooks.slack.com/services/" +
		"T12345678/B12345678/" + sampleLowerAlnum[:24],
	"square-access-token": "sq0atp-" + sampleLowerAlnum[:22],
	"stripe-access-token": "sk_live_" + sampleLowerAlnum[:24],
	"vault-token":         "hvs." + strings.Repeat(sampleLowerAlnum, 3),
}

func TestSecretTokenRulesMatchSamples(t *testing.T) {
	for _, rule := range secretTokenRules {
		sample, ok := secretTokenRuleSamples[rule.id]
		if !ok {
			t.Errorf("rule %s has no sample; add one to keep it tested", rule.id)
			continue
		}
		content := []byte("token = " + sample + "\n")
		if !contentContainsSecretToken(content, bytes.ToLower(content)) {
			t.Errorf("rule %s did not match its sample", rule.id)
		}
	}
	for id := range secretTokenRuleSamples {
		found := false
		for _, rule := range secretTokenRules {
			if rule.id == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("sample %s has no matching rule", id)
		}
	}
}

func TestSecretTokenRulesRejectLowEntropyTokens(t *testing.T) {
	for name, content := range map[string]string{
		"filler aws key":     "AWS_KEY=AKIA" + "AAAAAAAAAAAAAAAA\n",
		"filler github pat":  "token = ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
		"filler gitlab pat":  "token = glpat-aaaaaaaaaaaaaaaaaaaa\n",
		"filler stripe key":  "key = sk_live_" + "aaaaaaaaaaaaaaaaaaaaaaaa\n",
		"unrelated prose":    "the dapper keynote speaker thanked everyone\n",
		"age ciphertext tag": "binary age-encryption.org/v1 header only\n",
	} {
		data := []byte(content)
		if contentContainsSecretToken(data, bytes.ToLower(data)) {
			t.Errorf("%s was reported as a secret token", name)
		}
	}
}

func TestSecretTokenRulesDetectInsideRealisticFiles(t *testing.T) {
	env := "# deployment configuration\n" +
		"DEBUG=false\n" +
		"OPENAI_API_KEY=" + secretTokenRuleSamples["openai-api-key"] + "\n"
	data := []byte(env)
	if !contentContainsSecretToken(data, bytes.ToLower(data)) {
		t.Fatal("OpenAI key inside .env content was not detected")
	}

	identity := "# created: 2026-08-01\n" +
		"# public key: age1qqpszry9x8gf2tvdw0s3jn54khce6mua7lqqpszry9x8gf2tvdw0s\n" +
		secretTokenRuleSamples["age-secret-key"] + "\n"
	data = []byte(identity)
	if !contentContainsSecretToken(data, bytes.ToLower(data)) {
		t.Fatal("age identity file was not detected")
	}
}

func TestShannonEntropy(t *testing.T) {
	if entropy := shannonEntropy(""); entropy != 0 {
		t.Fatalf("entropy of empty string = %v, want 0", entropy)
	}
	if entropy := shannonEntropy("aaaaaaaa"); entropy != 0 {
		t.Fatalf("entropy of uniform string = %v, want 0", entropy)
	}
	low := shannonEntropy("aabbaabb")
	high := shannonEntropy(sampleLowerAlnum)
	if low >= high {
		t.Fatalf("entropy ordering wrong: %v >= %v", low, high)
	}
	if high < 5 || high > 5.2 {
		t.Fatalf("entropy of 36 distinct characters = %v, want ~5.17", high)
	}
}

func TestPlaceholderValuePatternsRejectSubstitutions(t *testing.T) {
	for _, value := range []string{
		"${DB_PASSWORD}",
		"$(vault read secret)",
		"$DATABASE_PASSWORD",
		"${12}",
		"{{ secrets.api_token }}",
		"%API_KEY%",
		"@PROJECT_SECRET@",
		"<your-api-key>",
		"process.env.SECRET",
	} {
		if !isPlaceholderSecret(value) {
			t.Errorf("%q was not treated as a placeholder", value)
		}
	}
	for _, value := range []string{
		"hunter2!x9",
		"a3f9c27d18e450b6",
		"pa$$word-with-symbols",
	} {
		if isPlaceholderSecret(value) {
			t.Errorf("%q was wrongly treated as a placeholder", value)
		}
	}
}
