//go:build darwin || linux

package passfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"passfs/internal/fuseadapter"
)

func registerMarkedTarget(_ string, targetPath string) error {
	return MarkProtectedLink(targetPath)
}

func TestFUSEEndToEnd(t *testing.T) {
	if os.Getenv("PASSFS_FUSE_TEST") != "1" {
		t.Skip("set PASSFS_FUSE_TEST=1 to run the FUSE integration test")
	}

	const passphrase = "integration test password"
	vault := filepath.Join(t.TempDir(), "vault")
	initPrompter := &recordingPrompter{responses: []string{passphrase, passphrase}}
	if err := InitVolume(t.Context(), vault, initPrompter); err != nil {
		t.Fatalf("InitVolume: %v", err)
	}
	prompter := &recordingPrompter{fallback: passphrase}
	volume, err := LoadVolume(vault, prompter, 1024*1024, 0)
	if err != nil {
		t.Fatalf("LoadVolume: %v", err)
	}

	mountPoint := filepath.Join(t.TempDir(), "mnt")
	if err := os.Mkdir(mountPoint, 0o700); err != nil {
		t.Fatal(err)
	}
	zero := time.Duration(0)
	server, err := fs.Mount(
		mountPoint,
		fuseadapter.NewRootNode(NewFileSystem(volume)),
		&fs.Options{
			AttrTimeout:     &zero,
			EntryTimeout:    &zero,
			NegativeTimeout: &zero,
			UID:             uint32(os.Getuid()),
			GID:             uint32(os.Getgid()),
			MountOptions: fuse.MountOptions{
				Options:            PlatformMountOptions(),
				FsName:             "passfs",
				Name:               "passfs",
				DisableReadDirPlus: true,
			},
		},
	)
	if err != nil {
		t.Fatalf("mount test filesystem: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Unmount()
		server.Wait()
		volume.Lock()
	})

	batchDirectory := t.TempDir()
	batchPaths := []string{
		filepath.Join(batchDirectory, ".env"),
		filepath.Join(batchDirectory, "credentials.json"),
	}
	for index, path := range batchPaths {
		if err := os.WriteFile(
			path,
			[]byte(fmt.Sprintf("SECRET_%d=value\n", index)),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	promptsBeforeBatch := prompter.requestCount()
	batchToken, err := BeginEncryptSession(mountPoint)
	if err != nil {
		t.Fatalf("begin encrypt session: %v", err)
	}
	for _, path := range batchPaths {
		if _, err := ImportThroughMount(
			path,
			mountPoint,
			1024*1024,
			registerMarkedTarget,
		); err != nil {
			t.Fatalf("batch ImportThroughMount(%s): %v", path, err)
		}
	}
	if err := EndEncryptSession(mountPoint, batchToken); err != nil {
		t.Fatalf("end encrypt session: %v", err)
	}
	if got, want := prompter.requestCount(), promptsBeforeBatch+1; got != want {
		t.Fatalf("batch prompts = %d, want %d", got, want)
	}

	projectDirectory := t.TempDir()
	sourcePath := filepath.Join(projectDirectory, ".env")
	initialPlaintext := []byte("TOKEN=before\n")
	if err := os.WriteFile(sourcePath, initialPlaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ImportThroughMount(
		sourcePath,
		mountPoint,
		1024*1024,
		registerMarkedTarget,
	)
	if err != nil {
		t.Fatalf("ImportThroughMount: %v", err)
	}
	if !result.Imported || !result.LinkCreated {
		t.Fatalf("import result = %#v", result)
	}
	if info, err := os.Lstat(sourcePath); err != nil ||
		info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("source is not a symbolic link: %v, %v", info, err)
	}

	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read through protected link: %v", err)
	}
	if !bytes.Equal(data, initialPlaintext) {
		t.Fatalf("plaintext = %q, want %q", data, initialPlaintext)
	}

	vimPath, err := exec.LookPath("vim")
	if err != nil {
		t.Fatalf("find Vim: %v", err)
	}
	promptsBeforeEdit := prompter.requestCount()
	editToken, err := BeginEditSession(result.TargetPath)
	if err != nil {
		t.Fatalf("begin edit session: %v", err)
	}
	vimCommand := exec.Command(
		vimPath,
		"--clean",
		"-n",
		"-i",
		"NONE",
		"-es",
		"-c",
		"setlocal noswapfile nobackup nowritebackup noundofile backupcopy=yes",
		"-c",
		"call setline(1, 'TOKEN=vim')",
		"-c",
		"wq",
		"--",
		sourcePath,
	)
	output, vimErr := vimCommand.CombinedOutput()
	endEditErr := EndEditSession(result.TargetPath, editToken)
	if vimErr != nil {
		t.Fatalf("Vim save: %v: %s", vimErr, output)
	}
	if endEditErr != nil {
		t.Fatalf("end edit session: %v", endEditErr)
	}
	if got, want := prompter.requestCount(), promptsBeforeEdit+1; got != want {
		t.Fatalf("edit session prompts = %d, want %d", got, want)
	}
	vimPlaintext := []byte("TOKEN=vim\n")
	if data, err := os.ReadFile(sourcePath); err != nil {
		t.Fatalf("read Vim update: %v", err)
	} else if !bytes.Equal(data, vimPlaintext) {
		t.Fatalf("Vim plaintext = %q, want %q", data, vimPlaintext)
	}
	if got, want := prompter.requestCount(), promptsBeforeEdit+2; got != want {
		t.Fatalf("post-edit open prompts = %d, want %d", got, want)
	}

	mountedSwapPath := result.TargetPath + ".swp"
	if err := os.WriteFile(mountedSwapPath, nil, 0o600); err != nil {
		t.Fatalf("create mounted editor temporary: %v", err)
	}
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(volume, mountPoint))
	if _, err := os.Lstat(sourcePath + ".swp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unregistered editor temporary was published: %v", err)
	}
	if err := os.Remove(mountedSwapPath); err != nil {
		t.Fatalf("remove mounted editor temporary: %v", err)
	}

	updatedPlaintext := []byte("TOKEN=after\n")
	if err := os.WriteFile(sourcePath, updatedPlaintext, 0o600); err != nil {
		t.Fatalf("write through protected link: %v", err)
	}
	data, err = os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read updated protected file: %v", err)
	}
	if !bytes.Equal(data, updatedPlaintext) {
		t.Fatalf("updated plaintext = %q, want %q", data, updatedPlaintext)
	}

	atomicallyReplacedPlaintext := []byte("TOKEN=atomic-replace\n")
	temporaryMountedPath := result.TargetPath + ".tmp"
	if err := os.WriteFile(temporaryMountedPath, atomicallyReplacedPlaintext, 0o600); err != nil {
		t.Fatalf("write mounted temporary file: %v", err)
	}
	if err := os.Rename(temporaryMountedPath, result.TargetPath); err != nil {
		t.Fatalf("atomically replace mounted file: %v", err)
	}
	data, err = os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read atomically replaced protected file: %v", err)
	}
	if !bytes.Equal(data, atomicallyReplacedPlaintext) {
		t.Fatalf(
			"atomically replaced plaintext = %q, want %q",
			data,
			atomicallyReplacedPlaintext,
		)
	}

	storagePath := testStoragePath(t, sourcePath)
	cipherPath, err := volume.encryptedPath(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if bytes.Contains(ciphertext, atomicallyReplacedPlaintext) ||
		bytes.Contains(ciphertext, []byte("TOKEN")) {
		t.Fatal("ciphertext contains plaintext")
	}

	records := volume.linkRecords()
	linkPersisted := false
	for _, record := range records {
		if record.linkTarget == result.TargetPath {
			linkPersisted = true
			break
		}
	}
	if !linkPersisted {
		t.Fatalf("link marker was not persisted synchronously: %#v", records)
	}

	repeated, err := ImportThroughMount(
		sourcePath,
		mountPoint,
		1024*1024,
		registerMarkedTarget,
	)
	if err != nil {
		t.Fatalf("repeat ImportThroughMount: %v", err)
	}
	if repeated.Imported || repeated.LinkCreated ||
		repeated.TargetPath != result.TargetPath {
		t.Fatalf("repeated import result = %#v", repeated)
	}

	openFile, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("hold protected file open: %v", err)
	}
	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("remove protected link: %v", err)
	}
	issues := synchronizeLinksOnce(volume, mountPoint)
	if issue := issues[sourcePath]; !errors.Is(issue, syscall.EBUSY) {
		t.Fatalf("synchronization while open = %v, want EBUSY", issues)
	}
	if _, err := os.Lstat(cipherPath); err != nil {
		t.Fatalf("ciphertext was removed while its file was open: %v", err)
	}
	openData, err := io.ReadAll(openFile)
	if err != nil {
		t.Fatalf("read already-open protected file: %v", err)
	}
	if !bytes.Equal(openData, atomicallyReplacedPlaintext) {
		t.Fatalf("already-open plaintext = %q", openData)
	}
	if err := openFile.Close(); err != nil {
		t.Fatalf("close protected file: %v", err)
	}
	assertNoLinkSyncIssues(t, synchronizeLinksOnce(volume, mountPoint))
	if _, err := os.Lstat(result.TargetPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mounted target still exists or returned an unexpected error: %v", err)
	}
	if _, err := os.Lstat(cipherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ciphertext still exists or returned an unexpected error: %v", err)
	}

	unusualDirectory := filepath.Join(projectDirectory, ".passfs")
	if err := os.Mkdir(unusualDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	unusualSource := filepath.Join(unusualDirectory, ".passfs-tmp-config.age")
	unusualPlaintext := []byte("unusual filename remains supported\n")
	if err := os.WriteFile(unusualSource, unusualPlaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	unusualResult, err := ImportThroughMount(
		unusualSource,
		mountPoint,
		1024*1024,
		registerMarkedTarget,
	)
	if err != nil {
		t.Fatalf("import unusual pathname: %v", err)
	}
	if data, err := os.ReadFile(unusualSource); err != nil {
		t.Fatalf("read unusual pathname: %v", err)
	} else if !bytes.Equal(data, unusualPlaintext) {
		t.Fatalf("unusual pathname plaintext = %q", data)
	}
	entries, err := os.ReadDir(filepath.Dir(unusualResult.TargetPath))
	if err != nil {
		t.Fatalf("list unusual mounted directory: %v", err)
	}
	found := false
	for _, entry := range entries {
		if entry.Name() == filepath.Base(unusualSource) {
			found = true
		}
	}
	if !found {
		t.Fatal("valid filename with an internal-looking prefix was hidden")
	}

	if got := prompter.requestCount(); got < 8 {
		t.Fatalf("passphrase prompts = %d, want at least 8", got)
	}
}
