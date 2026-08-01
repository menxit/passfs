package main

import (
	"bytes"
	"math"
	"regexp"
)

// High-confidence secret token rules, adapted from the gitleaks default
// configuration (https://github.com/gitleaks/gitleaks, MIT License,
// Copyright (c) 2019 Zachary Rice). Only self-identifying token formats are
// included; keyword-proximity detection stays in likelySecretAssignment.
//
// keywords are lowercase substrings; a rule's pattern runs only when at least
// one keyword appears in the lowercased content. entropy is the minimum
// Shannon entropy required of the matched token (0 disables the check).
type secretTokenRule struct {
	id       string
	keywords []string
	pattern  *regexp.Regexp
	entropy  float64
}

var secretTokenRules = []secretTokenRule{
	{
		id:       "age-secret-key",
		keywords: []string{"age-secret-key-1"},
		pattern:  regexp.MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`),
	},
	{
		id:       "anthropic-api-key",
		keywords: []string{"sk-ant-"},
		pattern:  regexp.MustCompile(`\b(sk-ant-(?:admin01|api03)-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`),
	},
	{
		id:       "aws-access-token",
		keywords: []string{"a3t", "akia", "asia", "abia", "acca"},
		pattern:  regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`),
		entropy:  3,
	},
	{
		id:       "azure-ad-client-secret",
		keywords: []string{"q~"},
		pattern:  regexp.MustCompile(`(?:^|[\\'"` + "`" + `\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"` + "`" + `\s<),])`),
		entropy:  3,
	},
	{
		id:       "databricks-api-token",
		keywords: []string{"dapi"},
		pattern:  regexp.MustCompile(`\b(dapi[a-f0-9]{32}(?:-\d)?)(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  3,
	},
	{
		id:       "digitalocean-token",
		keywords: []string{"doo_v1_", "dop_v1_", "dor_v1_"},
		pattern:  regexp.MustCompile(`\b(do[opr]_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  3,
	},
	{
		id:       "doppler-api-token",
		keywords: []string{"dp.pt."},
		pattern:  regexp.MustCompile(`dp\.pt\.(?i)[a-z0-9]{43}`),
		entropy:  2,
	},
	{
		id:       "gcp-api-key",
		keywords: []string{"aiza"},
		pattern:  regexp.MustCompile(`\b(AIza[\w-]{35})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  4,
	},
	{
		id:       "github-token",
		keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
		pattern:  regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}`),
		entropy:  3,
	},
	{
		id:       "github-fine-grained-pat",
		keywords: []string{"github_pat_"},
		pattern:  regexp.MustCompile(`github_pat_\w{82}`),
		entropy:  3,
	},
	{
		id:       "gitlab-pat",
		keywords: []string{"glpat-"},
		pattern:  regexp.MustCompile(`glpat-[\w-]{20}`),
		entropy:  3,
	},
	{
		id:       "gitlab-ptt",
		keywords: []string{"glptt-"},
		pattern:  regexp.MustCompile(`glptt-[0-9a-f]{40}`),
		entropy:  3,
	},
	{
		id:       "gitlab-rrt",
		keywords: []string{"gr1348941"},
		pattern:  regexp.MustCompile(`GR1348941[\w-]{20}`),
		entropy:  3,
	},
	{
		id:       "gitlab-runner-authentication-token",
		keywords: []string{"glrt-"},
		pattern:  regexp.MustCompile(`glrt-[0-9a-zA-Z_\-]{20}`),
		entropy:  3,
	},
	{
		id:       "gitlab-oauth-app-secret",
		keywords: []string{"gloas-"},
		pattern:  regexp.MustCompile(`gloas-[0-9a-zA-Z_\-]{64}`),
		entropy:  3,
	},
	{
		id:       "grafana-api-key",
		keywords: []string{"eyjrijoi"},
		pattern:  regexp.MustCompile(`(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  3,
	},
	{
		id:       "grafana-cloud-api-token",
		keywords: []string{"glc_"},
		pattern:  regexp.MustCompile(`(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  3,
	},
	{
		id:       "grafana-service-account-token",
		keywords: []string{"glsa_"},
		pattern:  regexp.MustCompile(`(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  3,
	},
	{
		id:       "hashicorp-tf-api-token",
		keywords: []string{"atlasv1"},
		pattern:  regexp.MustCompile(`(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}`),
		entropy:  3.5,
	},
	{
		id:       "huggingface-access-token",
		keywords: []string{"hf_"},
		pattern:  regexp.MustCompile(`\b(hf_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  2,
	},
	{
		id:       "jwt",
		keywords: []string{"ey"},
		pattern:  regexp.MustCompile(`\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.(?:[a-zA-Z0-9/\\_-]{10,}={0,2})?)(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  3,
	},
	{
		id:       "linear-api-key",
		keywords: []string{"lin_api_"},
		pattern:  regexp.MustCompile(`lin_api_(?i)[a-z0-9]{40}`),
		entropy:  2,
	},
	{
		id:       "npm-access-token",
		keywords: []string{"npm_"},
		pattern:  regexp.MustCompile(`(?i)\b(npm_[a-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  2,
	},
	{
		id:       "1password-service-account-token",
		keywords: []string{"ops_"},
		pattern:  regexp.MustCompile(`ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}`),
		entropy:  4,
	},
	{
		id:       "openai-api-key",
		keywords: []string{"t3blbkfj"},
		pattern:  regexp.MustCompile(`\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  3,
	},
	{
		id:       "perplexity-api-key",
		keywords: []string{"pplx-"},
		pattern:  regexp.MustCompile(`\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)`),
		entropy:  4,
	},
	{
		id:       "planetscale-token",
		keywords: []string{"pscale_"},
		pattern:  regexp.MustCompile(`\b(pscale_(?:tkn|oauth|pw)_(?i)[\w=.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  3,
	},
	{
		id:       "postman-api-token",
		keywords: []string{"pmak-"},
		pattern:  regexp.MustCompile(`\b(PMAK-(?i)[a-f0-9]{24}-[a-f0-9]{34})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  3,
	},
	{
		id:       "private-key",
		keywords: []string{"-----begin"},
		pattern:  regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`),
	},
	{
		id:       "pulumi-api-token",
		keywords: []string{"pul-"},
		pattern:  regexp.MustCompile(`\b(pul-[a-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  2,
	},
	{
		id:       "pypi-upload-token",
		keywords: []string{"pypi-ageichlwas5vcmc"},
		pattern:  regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`),
		entropy:  3,
	},
	{
		id:       "rubygems-api-token",
		keywords: []string{"rubygems_"},
		pattern:  regexp.MustCompile(`\b(rubygems_[a-f0-9]{48})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  2,
	},
	{
		id:       "sendgrid-api-token",
		keywords: []string{"sg."},
		pattern:  regexp.MustCompile(`\b(SG\.(?i)[a-z0-9=_.\-]{66})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  2,
	},
	{
		id:       "shopify-token",
		keywords: []string{"shpat_", "shpca_", "shppa_", "shpss_"},
		pattern:  regexp.MustCompile(`shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}`),
		entropy:  2,
	},
	{
		id:       "slack-bot-token",
		keywords: []string{"xoxb"},
		pattern:  regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
		entropy:  3,
	},
	{
		id:       "slack-user-token",
		keywords: []string{"xoxp-", "xoxe-"},
		pattern:  regexp.MustCompile(`xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`),
		entropy:  2,
	},
	{
		id:       "slack-app-token",
		keywords: []string{"xapp"},
		pattern:  regexp.MustCompile(`(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+`),
		entropy:  2,
	},
	{
		id:       "slack-legacy-token",
		keywords: []string{"xoxo", "xoxs"},
		pattern:  regexp.MustCompile(`xox[os]-\d+-\d+-\d+-[a-fA-F\d]+`),
		entropy:  2,
	},
	{
		id:       "slack-legacy-workspace-token",
		keywords: []string{"xoxa", "xoxr"},
		pattern:  regexp.MustCompile(`xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}`),
		entropy:  2,
	},
	{
		id:       "slack-webhook-url",
		keywords: []string{"hooks.slack.com"},
		pattern:  regexp.MustCompile(`(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}`),
	},
	{
		id:       "square-access-token",
		keywords: []string{"sq0atp-", "eaaa"},
		pattern:  regexp.MustCompile(`\b((?:EAAA|sq0atp-)[\w-]{22,60})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  2,
	},
	{
		// Deliberate deviation from gitleaks: test-mode keys are excluded
		// because they cannot access live data and would only add noise.
		id:       "stripe-access-token",
		keywords: []string{"sk_live", "sk_prod", "rk_live", "rk_prod"},
		pattern:  regexp.MustCompile(`\b((?:sk|rk)_(?:live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  2,
	},
	{
		id:       "vault-token",
		keywords: []string{"hvs.", "hvb."},
		pattern:  regexp.MustCompile(`\b(hv[sb]\.[\w-]{90,300})(?:[\x60'"\s;]|\\[nr]|$)`),
		entropy:  3.5,
	},
}

func contentContainsSecretToken(data, lower []byte) bool {
	for index := range secretTokenRules {
		rule := &secretTokenRules[index]
		if !containsAnyKeyword(lower, rule.keywords) {
			continue
		}
		for _, match := range rule.pattern.FindAllSubmatch(data, -1) {
			token := match[0]
			if len(match) > 1 && len(match[1]) != 0 {
				token = match[1]
			}
			if rule.entropy == 0 ||
				shannonEntropy(string(token)) > rule.entropy {
				return true
			}
		}
	}
	return false
}

func containsAnyKeyword(lower []byte, keywords []string) bool {
	for _, keyword := range keywords {
		if bytes.Contains(lower, []byte(keyword)) {
			return true
		}
	}
	return false
}

// shannonEntropy returns the average number of bits needed to encode one
// character of data. Random secrets score noticeably higher than words,
// identifiers, or repeated filler.
func shannonEntropy(data string) float64 {
	if data == "" {
		return 0
	}
	counts := make(map[rune]int)
	for _, character := range data {
		counts[character]++
	}
	entropy := 0.0
	inverseLength := 1.0 / float64(len(data))
	for _, count := range counts {
		frequency := float64(count) * inverseLength
		entropy -= frequency * math.Log2(frequency)
	}
	return entropy
}
