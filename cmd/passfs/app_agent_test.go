package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppAgentAllowsOnlyNarrowUICommands(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	secret := filepath.Join(home, ".env")
	if err := os.WriteFile(secret, []byte("API_KEY=real-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(home, "existing-backup")
	if err := os.MkdirAll(filepath.Join(backup, "vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(backup, "passfs-backup.json"),
		[]byte(`{"version":1}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	newBackup := filepath.Join(home, "new-backup")
	restoredVault := filepath.Join(home, "restored-vault")
	canonicalHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	canonicalBackup := filepath.Join(canonicalHome, "existing-backup")
	canonicalNewBackup := filepath.Join(canonicalHome, "new-backup")
	canonicalRestoredVault := filepath.Join(canonicalHome, "restored-vault")

	allowed := []struct {
		request appAgentRequest
		want    []string
	}{
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentUISnapshot, IncludeScan: true}, []string{"__ui-status"}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentUISnapshot}, []string{"__ui-status", "--no-scan"}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentInitializeSetup}, []string{"init", "--prompt", "native", "--no-open"}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentTouchIDDisable}, []string{"touchid", "disable"}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentConfigureUnlock, Duration: "5m", Scope: "file"}, []string{"config", "--unlock-for", "5m", "--unlock-scope", "file"}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentEncrypt, Path: secret}, []string{"encrypt", secret}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentIgnore, Path: secret}, []string{"ignore", secret}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentUnignore, Path: secret}, []string{"unignore", secret}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentReload}, []string{"reload"}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentUnmount}, []string{"unmount"}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentUpdate}, []string{"update"}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentChangePassphrase}, []string{"passwd", "--prompt", "native"}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentBackupCreate, Path: newBackup}, []string{"backup", "create", "--prompt", "native", "--restart-service", canonicalNewBackup}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentBackupVerify, Path: backup}, []string{"backup", "verify", "--prompt", "native", canonicalBackup}},
		{appAgentRequest{Version: appAgentProtocolVersion, Operation: appAgentBackupRestore, Path: backup, Destination: restoredVault, Activate: true}, []string{"backup", "restore", "--prompt", "native", "--vault", canonicalRestoredVault, "--activate", canonicalBackup}},
	}
	for _, test := range allowed {
		got, err := appAgentCommand(test.request)
		if err != nil {
			t.Errorf("appAgentCommand(%#v): %v", test.request, err)
		} else if strings.Join(got, "\x00") != strings.Join(test.want, "\x00") {
			t.Errorf("appAgentCommand(%#v) = %q, want %q", test.request, got, test.want)
		}
	}

	forbidden := []appAgentRequest{
		{Version: appAgentProtocolVersion},
		{Version: appAgentProtocolVersion, Operation: "serve"},
		{Version: appAgentProtocolVersion, Operation: "scan", Path: "/"},
		{Version: appAgentProtocolVersion, Operation: "backup-create"},
		{Version: appAgentProtocolVersion, Operation: appAgentBackupCreate, Path: backup},
		{Version: appAgentProtocolVersion, Operation: appAgentBackupRestore, Path: backup},
		{Version: appAgentProtocolVersion, Operation: appAgentBackupRestore, Path: backup, Destination: restoredVault, IncludeScan: true},
		{Version: appAgentProtocolVersion, Operation: appAgentInitialize, Path: filepath.Join(home, "other")},
		{Version: appAgentProtocolVersion, Operation: appAgentConfigureUnlock, Duration: "5m", Scope: "anything"},
		{Version: appAgentProtocolVersion, Operation: appAgentConfigureUnlock, Duration: "-5m", Scope: "file"},
		{Version: appAgentProtocolVersion, Operation: appAgentTouchIDDisable, Duration: "native"},
		{Version: appAgentProtocolVersion, Operation: appAgentEncrypt, Path: "/etc/hosts"},
		{Version: appAgentProtocolVersion, Operation: appAgentReload, IncludeScan: true},
	}
	for _, request := range forbidden {
		if _, err := appAgentCommand(request); err == nil {
			t.Errorf("appAgentCommand(%#v) unexpectedly succeeded", request)
		}
	}
}

func TestAppAgentRejectsARegularNonFinding(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ordinary := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(ordinary, []byte("nothing sensitive here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := appAgentCommand(appAgentRequest{
		Version:   appAgentProtocolVersion,
		Operation: appAgentEncrypt,
		Path:      ordinary,
	})
	if err == nil ||
		!strings.Contains(err.Error(), "not a current scan finding") {
		t.Fatalf("non-finding validation error = %v", err)
	}
}

func TestAppAgentStatusRoundTripDoesNotRequireInitialization(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	response := executeAppAgentRequest(appAgentRequest{
		Version:   appAgentProtocolVersion,
		Operation: appAgentUISnapshot,
	})
	if !response.Success || response.Error != "" {
		t.Fatalf("response = %#v", response)
	}
	var snapshot uiSnapshot
	if err := json.Unmarshal([]byte(response.Output), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Initialized {
		t.Fatal("empty test home was reported as initialized")
	}
}

func TestAppAgentRejectsUnknownProtocol(t *testing.T) {
	response := executeAppAgentRequest(appAgentRequest{
		Version:     appAgentProtocolVersion + 1,
		Operation:   appAgentUISnapshot,
		IncludeScan: true,
	})
	if response.Success || !strings.Contains(response.Error, "protocol") {
		t.Fatalf("response = %#v", response)
	}
}

func TestAppAgentWireRequestCannotContainCLIArguments(t *testing.T) {
	data, err := json.Marshal(appAgentRequest{
		Version:   appAgentProtocolVersion,
		Operation: appAgentEncrypt,
		Path:      "/Users/example/.env",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "arguments") ||
		strings.Contains(string(data), "--") {
		t.Fatalf("typed request leaked CLI syntax: %s", data)
	}
}

func TestAppAgentBackupPathsRejectSymlinks(t *testing.T) {
	root := t.TempDir()
	realBackup := filepath.Join(root, "backup")
	if err := os.MkdirAll(filepath.Join(realBackup, "vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(realBackup, "passfs-backup.json"),
		[]byte(`{"version":1}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	linkedBackup := filepath.Join(root, "linked-backup")
	if err := os.Symlink(realBackup, linkedBackup); err != nil {
		t.Fatal(err)
	}
	if _, err := validateAgentBackupDirectory(linkedBackup); err == nil {
		t.Fatal("backup symlink unexpectedly accepted")
	}

	realParent := filepath.Join(root, "destinations")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(root, "linked-destinations")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := validateAgentNewDirectory(
		filepath.Join(linkedParent, "new-vault"),
	); err == nil {
		t.Fatal("destination below a symlink unexpectedly accepted")
	}
}

func TestAppAgentRejectsParentDirectorySymlinkOutsideHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	safeParent := filepath.Join(home, "project")
	if err := os.Mkdir(safeParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateAgentHomeParent(filepath.Join(safeParent, ".env")); err != nil {
		t.Fatalf("safe parent rejected: %v", err)
	}

	outside := t.TempDir()
	linkedParent := filepath.Join(home, "linked-project")
	if err := os.Symlink(outside, linkedParent); err != nil {
		t.Fatal(err)
	}
	err := validateAgentHomeParent(filepath.Join(linkedParent, ".env"))
	if err == nil || !strings.Contains(err.Error(), "outside the user home") {
		t.Fatalf("outside parent validation error = %v", err)
	}
}

func TestAppAgentSerializesMutatingOperations(t *testing.T) {
	request := appAgentRequest{
		Version:   appAgentProtocolVersion,
		Operation: appAgentReload,
	}
	release, err := acquireAppAgentOperation(request)
	if err != nil {
		t.Fatal(err)
	}
	if releaseSecond, err := acquireAppAgentOperation(request); err == nil {
		releaseSecond()
		release()
		t.Fatal("second mutating operation unexpectedly acquired the slot")
	}
	release()
	releaseAgain, err := acquireAppAgentOperation(request)
	if err != nil {
		t.Fatalf("released mutation slot remained unavailable: %v", err)
	}
	releaseAgain()
}

func TestAppAgentCachedScanDropsRemovedSecretImmediately(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	secret := filepath.Join(home, ".env")
	if err := os.WriteFile(
		secret,
		[]byte("API_KEY=real-secret-value\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	appAgentSnapshot.findings = []string{secret}
	appAgentSnapshot.scanned = time.Now()
	defer func() {
		appAgentSnapshot.findings = nil
		appAgentSnapshot.scanned = time.Time{}
	}()

	var first bytes.Buffer
	if err := runAppAgentUISnapshot(true, &first, io.Discard); err != nil {
		t.Fatal(err)
	}
	var firstSnapshot uiSnapshot
	if err := json.Unmarshal(first.Bytes(), &firstSnapshot); err != nil {
		t.Fatal(err)
	}
	if len(firstSnapshot.Unprotected) != 1 ||
		firstSnapshot.Unprotected[0].Path != secret {
		t.Fatalf("initial cached findings = %#v", firstSnapshot.Unprotected)
	}

	if err := os.WriteFile(secret, []byte("nothing sensitive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	if err := runAppAgentUISnapshot(true, &second, io.Discard); err != nil {
		t.Fatal(err)
	}
	var secondSnapshot uiSnapshot
	if err := json.Unmarshal(second.Bytes(), &secondSnapshot); err != nil {
		t.Fatal(err)
	}
	if len(secondSnapshot.Unprotected) != 0 {
		t.Fatalf("removed secret remained visible: %#v", secondSnapshot.Unprotected)
	}
}
