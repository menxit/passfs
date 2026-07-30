package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFindsSecretsAndPrunesDependencies(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, ".env")
	placeholder := filepath.Join(root, ".env.example")
	dependencySecret := filepath.Join(root, "node_modules", "package", ".env")
	vendorSecret := filepath.Join(root, "vendor", "sdk", "credentials.json")
	for path, contents := range map[string]string{
		secret:           "API_KEY=real-secret-value\n",
		placeholder:      "API_KEY=your_api_key\n",
		dependencySecret: "TOKEN=dependency-secret\n",
		vendorSecret:     `{"client_secret":"vendored-secret"}`,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runScan([]string{root}, &stdout, &stderr); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	lines := strings.Fields(stdout.String())
	if len(lines) != 1 || lines[0] != secret {
		t.Fatalf("scan result = %#v, want only %q", lines, secret)
	}
	if strings.Contains(stdout.String(), "real-secret-value") {
		t.Fatal("scan printed secret contents")
	}
}

func TestScannerSkipsTrackedAndProtectedLinks(t *testing.T) {
	root := t.TempDir()
	tracked := filepath.Join(root, ".env")
	untracked := filepath.Join(root, "credentials.json")
	target := filepath.Join(root, "mount", "protected")
	protectedLink := filepath.Join(root, "protected.env")
	for path, contents := range map[string]string{
		tracked:   "PASSWORD=tracked-secret\n",
		untracked: `{"access_token":"untracked-secret"}`,
		target:    "TOKEN=protected-secret\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(target, protectedLink); err != nil {
		t.Fatal(err)
	}
	if found, err := fileContainsLikelySecret(untracked); err != nil || !found {
		t.Fatalf("direct credentials detection = %v, %v", found, err)
	}

	scanner := secretScanner{
		tracked: map[string]struct{}{tracked: {}},
	}
	findings, err := scanner.scan([]scanRoot{{
		path:     root,
		maxDepth: -1,
		explicit: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0] != untracked {
		t.Fatalf("findings = %#v, want only %q", findings, untracked)
	}
}

func TestScannerSkipsIgnoredFile(t *testing.T) {
	root := t.TempDir()
	ignored := filepath.Join(root, ".env")
	if err := os.WriteFile(
		ignored,
		[]byte("API_KEY=real-secret-value\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	scanner := secretScanner{
		ignored: map[string]struct{}{ignored: {}},
	}
	findings, err := scanner.scan([]scanRoot{{
		path:     root,
		maxDepth: -1,
		explicit: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
}

func TestScannerSkipsTrackedFilesInEveryRepository(t *testing.T) {
	root := t.TempDir()
	firstRepository := filepath.Join(root, "first")
	secondRepository := filepath.Join(root, "second")
	for _, repository := range []string{firstRepository, secondRepository} {
		if err := os.MkdirAll(repository, 0o700); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("git", "-C", repository, "init", "-q")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git init: %v: %s", err, output)
		}
		tracked := filepath.Join(repository, ".env")
		if err := os.WriteFile(
			tracked,
			[]byte("API_KEY=tracked-private-value\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		command = exec.Command("git", "-C", repository, "add", ".env")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git add: %v: %s", err, output)
		}
	}
	untracked := filepath.Join(secondRepository, "credentials.json")
	if err := os.WriteFile(
		untracked,
		[]byte(`{"access_token":"untracked-private-value"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	scanner := secretScanner{}
	findings, err := scanner.scan([]scanRoot{{
		path:     root,
		maxDepth: -1,
		explicit: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0] != untracked {
		t.Fatalf("findings = %#v, want only %q", findings, untracked)
	}
}

func TestScanIgnoreListRoundTrip(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "passfs", "config.json")
	first := filepath.Join(t.TempDir(), ".env")
	second := filepath.Join(t.TempDir(), "credentials.json")
	if err := updateScanIgnoredPaths(
		configPath,
		[]string{second, first},
		false,
	); err != nil {
		t.Fatal(err)
	}
	ignored, err := loadScanIgnoredPaths(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ignored[first]; !ok {
		t.Fatalf("ignore list does not contain %q", first)
	}
	if _, ok := ignored[second]; !ok {
		t.Fatalf("ignore list does not contain %q", second)
	}
	if err := updateScanIgnoredPaths(
		configPath,
		[]string{first},
		true,
	); err != nil {
		t.Fatal(err)
	}
	ignored, err = loadScanIgnoredPaths(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ignored[first]; ok {
		t.Fatalf("ignore list still contains restored path %q", first)
	}
	if _, ok := ignored[second]; !ok {
		t.Fatalf("ignore list lost %q", second)
	}
}

func TestParseScanSelection(t *testing.T) {
	for input, expected := range map[string][]int{
		"all":     {0, 1, 2, 3, 4},
		"1 3-5":   {0, 2, 3, 4},
		"2, 2, 4": {1, 3},
	} {
		actual, err := parseScanSelection(input, 5)
		if err != nil {
			t.Fatalf("parseScanSelection(%q): %v", input, err)
		}
		if fmt.Sprint(actual) != fmt.Sprint(expected) {
			t.Fatalf(
				"parseScanSelection(%q) = %v, want %v",
				input,
				actual,
				expected,
			)
		}
	}
	for _, input := range []string{"", "0", "6", "4-2", "nope"} {
		if _, err := parseScanSelection(input, 5); err == nil {
			t.Fatalf("parseScanSelection(%q) succeeded", input)
		}
	}
}

func TestMaskedScanPreviewNeverIncludesValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	const secret = "private-value-that-must-stay-hidden"
	if err := os.WriteFile(
		path,
		[]byte("API_KEY="+secret+"\nCLIENT_SECRET=another-private-value\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	preview := maskedScanPreview(path)
	if strings.Contains(preview, secret) ||
		strings.Contains(preview, "another-private-value") {
		t.Fatalf("masked preview exposed a secret: %q", preview)
	}
	if !strings.Contains(preview, "API_KEY=••••••") {
		t.Fatalf("masked preview = %q", preview)
	}
}

func TestScanRepositoryNameUsesOrigin(t *testing.T) {
	root := t.TempDir()
	gitDirectory := filepath.Join(root, ".git")
	if err := os.MkdirAll(gitDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(gitDirectory, "config"),
		[]byte("[remote \"origin\"]\n\turl = git@github.com:menxit/passfs.git\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if got := scanRepositoryName(root, gitDirectory); got != "passfs" {
		t.Fatalf("repository name = %q, want passfs", got)
	}
}

func TestLikelySecretAssignmentRejectsPlaceholders(t *testing.T) {
	for _, line := range []string{
		"API_KEY=your_api_key",
		`"client_secret": "${CLIENT_SECRET}"`,
		"PASSWORD=changeme",
		"token_file=/run/token",
	} {
		if likelySecretAssignment(line) {
			t.Errorf("placeholder %q was classified as a secret", line)
		}
	}
	for _, line := range []string{
		"API_KEY=sk_test_but-still-private",
		`"client_secret": "actual-value"`,
		"aws_secret_access_key = abcdefghijklmnop",
		"machine example.com login person password private-value",
	} {
		if !likelySecretAssignment(line) {
			t.Errorf("secret %q was not classified", line)
		}
	}
}

func TestScanJSONContainsOnlyPaths(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".npmrc")
	if err := os.WriteFile(
		path,
		[]byte("//registry.npmjs.org/:_authToken=private-token\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if found, err := fileContainsLikelySecret(path); err != nil || !found {
		t.Fatalf("direct npm token detection = %v, %v", found, err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runScan([]string{"--json", root}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), path) {
		t.Fatalf("JSON result %q does not contain path", stdout.String())
	}
	if strings.Contains(stdout.String(), "private-token") {
		t.Fatal("JSON result exposed a secret")
	}
}
