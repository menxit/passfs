//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMacOSMajorVersion(t *testing.T) {
	for input, expected := range map[string]int{
		"26.5.2\n": 26,
		"15.7":     15,
	} {
		actual, err := parseMacOSMajorVersion(input)
		if err != nil {
			t.Fatalf("parseMacOSMajorVersion(%q): %v", input, err)
		}
		if actual != expected {
			t.Fatalf(
				"parseMacOSMajorVersion(%q) = %d, want %d",
				input,
				actual,
				expected,
			)
		}
	}
	if _, err := parseMacOSMajorVersion("invalid"); err == nil {
		t.Fatal("parseMacOSMajorVersion accepted an invalid version")
	}
}

func TestFSKitModuleDisabledOutput(t *testing.T) {
	for input, expected := range map[string]bool{
		"Module com.menxit.passfs.filesystem is disabled!\n": true,
		"module COM.MENXIT.PASSFS.FILESYSTEM is disabled":    true,
		"the FSKit filesystem did not become ready":          false,
		"Module com.example.other is disabled":               false,
	} {
		if actual := fsKitModuleDisabledOutput([]byte(input)); actual != expected {
			t.Fatalf(
				"fsKitModuleDisabledOutput(%q) = %t, want %t",
				input,
				actual,
				expected,
			)
		}
	}
}

func TestLiveFSMountRegistrationsContain(t *testing.T) {
	registrations := []byte(`[
		{
			"mountedOn": "/Users/test/.passfs/mnt",
			"displayName": "passfs"
		}
	]`)
	if !liveFSMountRegistrationsContain(
		registrations,
		"/Users/test/.passfs/mnt",
	) {
		t.Fatal("matching LiveFS mount registration was not found")
	}
	if liveFSMountRegistrationsContain(
		registrations,
		"/Users/other/.passfs/mnt",
	) {
		t.Fatal("unrelated LiveFS mount registration matched")
	}
	if liveFSMountRegistrationsContain(
		[]byte("not JSON"),
		"/Users/test/.passfs/mnt",
	) {
		t.Fatal("invalid LiveFS settings matched")
	}
}

func TestPlatformFilesystemApprovalIgnoresOldLogEntries(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "passfs.log")
	oldEntry := []byte(
		"Module com.menxit.passfs.filesystem is disabled!\n",
	)
	if err := os.WriteFile(logPath, oldEntry, 0o600); err != nil {
		t.Fatal(err)
	}
	offset := int64(len(oldEntry))
	if platformFilesystemApprovalRequired(
		adapterFSKit,
		logPath,
		offset,
	) {
		t.Fatal("old disabled entry requested approval")
	}
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(oldEntry); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if !platformFilesystemApprovalRequired(
		adapterFSKit,
		logPath,
		offset,
	) {
		t.Fatal("new disabled entry did not request approval")
	}
}

func TestEmbeddedFSKitExtensionPathFindsOuterBundleFromCLIHelper(
	t *testing.T,
) {
	root := t.TempDir()
	extension := filepath.Join(
		root,
		"PassFS.app",
		"Contents",
		"Extensions",
		"PassFSFileSystem.appex",
	)
	if err := os.MkdirAll(extension, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(
		root,
		"PassFS.app",
		"Contents",
		"Helpers",
		"PassFSCLI.bundle",
		"Contents",
		"MacOS",
		"passfs-cli",
	)
	got, err := embeddedFSKitExtensionPathForExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	if got != extension {
		t.Fatalf("extension path = %q, want %q", got, extension)
	}
}

func TestFSKitExtensionInstalledRequiresBundleDirectory(t *testing.T) {
	root := t.TempDir()
	extension := filepath.Join(root, "PassFSFileSystem.appex")
	if err := os.Mkdir(extension, 0o700); err != nil {
		t.Fatal(err)
	}
	if !fsKitExtensionInstalled(extension) {
		t.Fatal("extension bundle directory was reported as not installed")
	}

	regularFile := filepath.Join(root, "not-an-extension")
	if err := os.WriteFile(regularFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if fsKitExtensionInstalled(regularFile) {
		t.Fatal("regular file was reported as an installed extension")
	}
	if fsKitExtensionInstalled(filepath.Join(root, "missing.appex")) {
		t.Fatal("missing extension was reported as installed")
	}
}

func TestPassFSAppPathForExecutable(t *testing.T) {
	executable := filepath.Join(
		"/Applications",
		"PassFS.app",
		"Contents",
		"Helpers",
		"PassFSCLI.bundle",
		"Contents",
		"MacOS",
		"passfs-cli",
	)
	got, err := passFSAppPathForExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(
		"/Applications",
		"PassFS.app",
	)
	if got != want {
		t.Fatalf("app path = %q, want %q", got, want)
	}
}
