package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"passfs/internal/passfs"
)

const appAgentProtocolVersion = 3

type appAgentOperation string

const (
	appAgentUISnapshot           appAgentOperation = "ui-snapshot"
	appAgentGatekeeperAssessment appAgentOperation = "gatekeeper-assessment"
	appAgentReload               appAgentOperation = "reload"
	appAgentUnmount              appAgentOperation = "unmount"
	appAgentUpdate               appAgentOperation = "update"
	appAgentInitialize           appAgentOperation = "initialize"
	appAgentInitializeNative     appAgentOperation = "initialize-native"
	appAgentInitializeSetup      appAgentOperation = "initialize-setup"
	appAgentTouchIDEnable        appAgentOperation = "touch-id-enable"
	appAgentTouchIDDisable       appAgentOperation = "touch-id-disable"
	appAgentChangePassphrase     appAgentOperation = "change-passphrase"
	appAgentConfigureUnlock      appAgentOperation = "configure-unlock"
	appAgentEncrypt              appAgentOperation = "encrypt"
	appAgentIgnore               appAgentOperation = "ignore"
	appAgentUnignore             appAgentOperation = "unignore"
	appAgentUnprotect            appAgentOperation = "unprotect"
	appAgentRecoveryRestore      appAgentOperation = "recovery-restore"
	appAgentRecoveryPurge        appAgentOperation = "recovery-purge"
	appAgentBackupCreate         appAgentOperation = "backup-create"
	appAgentBackupVerify         appAgentOperation = "backup-verify"
	appAgentBackupRestore        appAgentOperation = "backup-restore"
	appAgentFullScanInterval                       = 15 * time.Second
)

type appAgentRequest struct {
	Version     int                `json:"version"`
	Operation   appAgentOperation  `json:"operation"`
	Path        string             `json:"path,omitempty"`
	Destination string             `json:"destination,omitempty"`
	Duration    string             `json:"duration,omitempty"`
	Scope       passfs.UnlockScope `json:"scope,omitempty"`
	IncludeScan bool               `json:"includeScan,omitempty"`
	Activate    bool               `json:"activate,omitempty"`
}

type appAgentResponse struct {
	Version int    `json:"version"`
	Success bool   `json:"success"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

var (
	appAgentScanSlot     = make(chan struct{}, 1)
	appAgentMutationSlot = make(chan struct{}, 1)
	appAgentSnapshot     struct {
		findings []string
		scanned  time.Time
	}
)

func executeAppAgentRequest(request appAgentRequest) appAgentResponse {
	response := appAgentResponse{Version: appAgentProtocolVersion}
	arguments, err := appAgentCommand(request)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	release, err := acquireAppAgentOperation(request)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	defer release()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if request.Operation == appAgentUISnapshot {
		err = runAppAgentUISnapshot(
			request.IncludeScan,
			&stdout,
			&stderr,
		)
	} else {
		err = runCLI(arguments, &stdout, &stderr)
	}
	if errors.Is(err, flag.ErrHelp) {
		err = nil
	}
	response.Output = stdout.String()
	if err == nil {
		response.Success = true
		return response
	}
	if stderr.Len() != 0 && !strings.HasSuffix(stderr.String(), "\n") {
		stderr.WriteByte('\n')
	}
	fmt.Fprintf(&stderr, "passfs: %s\n", terminalSafeError(err))
	response.Error = stderr.String()
	return response
}

// runAppAgentUISnapshot keeps deletion and content-removal updates cheap and
// responsive while the manager is open. Known findings are revalidated on
// every UI refresh; the more expensive directory traversal is periodic.
func runAppAgentUISnapshot(
	includeScan bool,
	stdout io.Writer,
	stderr io.Writer,
) error {
	if !includeScan {
		return runUISnapshot([]string{"--no-scan"}, stdout, stderr)
	}
	if appAgentSnapshot.scanned.IsZero() ||
		time.Since(appAgentSnapshot.scanned) >= appAgentFullScanInterval {
		var output bytes.Buffer
		if err := runUISnapshot(nil, &output, stderr); err != nil {
			return err
		}
		var snapshot uiSnapshot
		if err := json.Unmarshal(output.Bytes(), &snapshot); err != nil {
			return fmt.Errorf("cache PassFS UI scan: %w", err)
		}
		appAgentSnapshot.findings = appAgentSnapshot.findings[:0]
		for _, record := range snapshot.Unprotected {
			appAgentSnapshot.findings = append(
				appAgentSnapshot.findings,
				record.Path,
			)
		}
		appAgentSnapshot.scanned = time.Now()
		_, err := io.Copy(stdout, &output)
		return err
	}

	var output bytes.Buffer
	if err := runUISnapshot([]string{"--no-scan"}, &output, stderr); err != nil {
		return err
	}
	var snapshot uiSnapshot
	if err := json.Unmarshal(output.Bytes(), &snapshot); err != nil {
		return fmt.Errorf("refresh PassFS UI state: %w", err)
	}
	excluded := make(map[string]struct{}, len(snapshot.Ignored)+len(snapshot.Protected))
	for _, record := range snapshot.Ignored {
		excluded[filepath.Clean(record.Path)] = struct{}{}
	}
	for _, record := range snapshot.Protected {
		excluded[filepath.Clean(record.Path)] = struct{}{}
	}
	validated := make([]string, 0, len(appAgentSnapshot.findings))
	findings := make([]string, 0, len(appAgentSnapshot.findings))
	for _, path := range appAgentSnapshot.findings {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		found, err := fileContainsLikelySecret(path)
		if err == nil && found {
			validated = append(validated, path)
			if _, skip := excluded[filepath.Clean(path)]; !skip {
				findings = append(findings, path)
			}
		}
	}
	appAgentSnapshot.findings = validated
	snapshot.Unprotected = uiFileRecords(findings, true)
	return writeJSON(stdout, snapshot)
}

// appAgentCommand translates a closed, typed protocol into CLI calls. No
// command name or flag crosses the trust boundary, so adding a public CLI flag
// cannot accidentally expand what a compromised UI may ask the agent to do.
func appAgentCommand(request appAgentRequest) ([]string, error) {
	if request.Version != appAgentProtocolVersion {
		return nil, errors.New("unsupported PassFS control agent protocol")
	}
	if len(request.Operation) == 0 || len(request.Operation) > 64 ||
		len(request.Path) > 4096 || strings.ContainsRune(request.Path, 0) ||
		len(request.Destination) > 4096 ||
		strings.ContainsRune(request.Destination, 0) ||
		len(request.Duration) > 64 || strings.ContainsRune(request.Duration, 0) ||
		len(request.Scope) > 32 || strings.ContainsRune(string(request.Scope), 0) {
		return nil, errors.New("invalid PassFS control agent request")
	}

	noParameters := func() bool {
		return request.Path == "" && request.Destination == "" &&
			request.Duration == "" && request.Scope == "" &&
			!request.IncludeScan && !request.Activate
	}
	pathOnly := func() bool {
		return request.Path != "" && request.Destination == "" &&
			request.Duration == "" && request.Scope == "" &&
			!request.IncludeScan && !request.Activate
	}
	switch request.Operation {
	case appAgentUISnapshot:
		if request.Path != "" || request.Destination != "" ||
			request.Duration != "" || request.Scope != "" || request.Activate {
			break
		}
		arguments := []string{"__ui-status"}
		if !request.IncludeScan {
			arguments = append(arguments, "--no-scan")
		}
		return arguments, nil
	case appAgentGatekeeperAssessment:
		if noParameters() {
			return []string{"__gatekeeper-assessment"}, nil
		}
	case appAgentReload:
		if noParameters() {
			return []string{"reload"}, nil
		}
	case appAgentUnmount:
		if noParameters() {
			return []string{"unmount"}, nil
		}
	case appAgentUpdate:
		if noParameters() {
			return []string{"update"}, nil
		}
	case appAgentInitialize:
		if noParameters() {
			return []string{"init"}, nil
		}
	case appAgentInitializeNative:
		if noParameters() {
			return []string{"init", "--prompt", "native"}, nil
		}
	case appAgentInitializeSetup:
		if noParameters() {
			return []string{"init", "--prompt", "native", "--no-open"}, nil
		}
	case appAgentTouchIDEnable:
		if noParameters() {
			return []string{"touchid", "enable", "--prompt", "native"}, nil
		}
	case appAgentTouchIDDisable:
		if noParameters() {
			return []string{"touchid", "disable"}, nil
		}
	case appAgentChangePassphrase:
		if noParameters() {
			return []string{"passwd", "--prompt", "native"}, nil
		}
	case appAgentConfigureUnlock:
		if request.Path != "" || request.Destination != "" ||
			request.IncludeScan || request.Activate ||
			request.Duration == "" || request.Scope == "" {
			break
		}
		duration, err := time.ParseDuration(request.Duration)
		if err != nil || duration < 0 {
			return nil, errors.New("invalid unlock duration")
		}
		switch request.Scope {
		case passfs.UnlockOnce, passfs.UnlockFile,
			passfs.UnlockProcess, passfs.UnlockVault:
			return []string{
				"config", "--unlock-for", request.Duration,
				"--unlock-scope", string(request.Scope),
			}, nil
		}
		return nil, errors.New("invalid unlock scope")
	case appAgentEncrypt:
		if pathOnly() {
			if err := validateAgentPlaintextPath(request.Path, true); err != nil {
				return nil, err
			}
			return []string{"encrypt", request.Path}, nil
		}
	case appAgentIgnore:
		if pathOnly() {
			if err := validateAgentPlaintextPath(request.Path, false); err != nil {
				return nil, err
			}
			return []string{"ignore", request.Path}, nil
		}
	case appAgentUnignore:
		if pathOnly() {
			if _, err := validateAgentHomePath(request.Path, false); err != nil {
				return nil, err
			}
			return []string{"unignore", request.Path}, nil
		}
	case appAgentUnprotect:
		if pathOnly() {
			if err := validateAgentProtectedPath(request.Path); err != nil {
				return nil, err
			}
			return []string{"unprotect", "--yes", "--prompt", "native", "--", request.Path}, nil
		}
	case appAgentRecoveryRestore:
		if pathOnly() {
			if err := validateAgentRecoveryPath(request.Path, true); err != nil {
				return nil, err
			}
			return []string{"recovery", "restore", request.Path}, nil
		}
	case appAgentRecoveryPurge:
		if pathOnly() {
			if err := validateAgentRecoveryPath(request.Path, false); err != nil {
				return nil, err
			}
			return []string{"recovery", "purge", "--yes", request.Path}, nil
		}
	case appAgentBackupCreate:
		if pathOnly() {
			destination, err := validateAgentNewDirectory(request.Path)
			if err != nil {
				return nil, err
			}
			return []string{
				"backup", "create", "--prompt", "native",
				"--restart-service", destination,
			}, nil
		}
	case appAgentBackupVerify:
		if pathOnly() {
			backup, err := validateAgentBackupDirectory(request.Path)
			if err != nil {
				return nil, err
			}
			return []string{
				"backup", "verify", "--prompt", "native", backup,
			}, nil
		}
	case appAgentBackupRestore:
		if request.Path != "" && request.Destination != "" &&
			request.Duration == "" && request.Scope == "" &&
			!request.IncludeScan {
			backup, err := validateAgentBackupDirectory(request.Path)
			if err != nil {
				return nil, err
			}
			destination, err := validateAgentNewDirectory(
				request.Destination,
			)
			if err != nil {
				return nil, err
			}
			arguments := []string{
				"backup", "restore", "--prompt", "native",
				"--vault", destination,
			}
			if request.Activate {
				arguments = append(arguments, "--activate")
			}
			return append(arguments, backup), nil
		}
	}
	return nil, errors.New("operation is not available to the PassFS app")
}

func validateAgentBackupDirectory(path string) (string, error) {
	clean, err := validateAgentExistingRealDirectory(path)
	if err != nil {
		return "", fmt.Errorf("invalid app-selected backup: %w", err)
	}
	for _, entry := range []struct {
		path      string
		directory bool
	}{
		{path: filepath.Join(clean, "passfs-backup.json")},
		{path: filepath.Join(clean, "vault"), directory: true},
	} {
		info, err := os.Lstat(entry.path)
		if err != nil {
			return "", fmt.Errorf("invalid app-selected backup: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 ||
			(entry.directory && !info.IsDir()) ||
			(!entry.directory && !info.Mode().IsRegular()) {
			return "", errors.New("the app-selected directory is not a PassFS backup")
		}
	}
	return clean, nil
}

func validateAgentExistingRealDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return "", errors.New("path must be absolute")
	}
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("path is not a real directory")
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

func validateAgentNewDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return "", errors.New("the app-selected destination must be absolute")
	}
	clean := filepath.Clean(path)
	if clean == string(os.PathSeparator) {
		return "", errors.New("the app-selected destination cannot be the filesystem root")
	}
	if _, err := os.Lstat(clean); err == nil {
		return "", errors.New("the app-selected destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect app-selected destination: %w", err)
	}
	parent, err := validateAgentExistingRealDirectory(filepath.Dir(clean))
	if err != nil {
		return "", fmt.Errorf("invalid app-selected destination parent: %w", err)
	}
	return filepath.Join(parent, filepath.Base(clean)), nil
}

func acquireAppAgentOperation(request appAgentRequest) (func(), error) {
	var slot chan struct{}
	switch request.Operation {
	case appAgentUISnapshot:
		if !request.IncludeScan {
			return func() {}, nil
		}
		slot = appAgentScanSlot
	case appAgentGatekeeperAssessment:
		return func() {}, nil
	default:
		slot = appAgentMutationSlot
	}
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, nil
	default:
		return nil, errors.New("another PassFS app operation is already in progress")
	}
}

func validateAgentPlaintextPath(path string, requireFinding bool) error {
	clean, err := validateAgentHomePath(path, true)
	if err != nil {
		return err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("inspect app-selected file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("the app-selected path is not a regular file")
	}
	if requireFinding {
		found, scanErr := fileContainsLikelySecret(clean)
		if scanErr != nil {
			return fmt.Errorf("verify app-selected secret: %w", scanErr)
		}
		if !found {
			return errors.New("the app-selected file is not a current scan finding")
		}
	}
	return nil
}

func validateAgentHomePath(path string, requireExisting bool) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return "", errors.New("the app-selected path must be absolute")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate user home: %w", err)
	}
	clean := filepath.Clean(path)
	if !pathWithinLexically(home, clean) {
		return "", errors.New("the app-selected path is outside the user home")
	}
	if requireExisting {
		resolvedHome, err := filepath.EvalSymlinks(home)
		if err != nil {
			return "", fmt.Errorf("resolve user home: %w", err)
		}
		resolved, err := filepath.EvalSymlinks(clean)
		if err != nil {
			return "", fmt.Errorf("resolve app-selected path: %w", err)
		}
		if !pathWithinLexically(resolvedHome, resolved) {
			return "", errors.New("the app-selected path resolves outside the user home")
		}
	}
	return clean, nil
}

func validateAgentProtectedPath(path string) error {
	clean, err := validateAgentHomePath(path, false)
	if err != nil {
		return err
	}
	if err := validateAgentHomeParent(clean); err != nil {
		return err
	}
	settings, err := loadDefaultAgentSettings()
	if err != nil {
		return err
	}
	protected, err := passfs.ProtectedFiles(settings.Vault)
	if err != nil {
		return err
	}
	for _, file := range protected {
		if filepath.Clean(file.Path) == clean {
			return nil
		}
	}
	return errors.New("the app-selected file is not protected by PassFS")
}

func validateAgentRecoveryPath(path string, restoring bool) error {
	clean, err := validateAgentHomePath(path, false)
	if err != nil {
		return err
	}
	if restoring {
		if err := validateAgentHomeParent(clean); err != nil {
			return err
		}
	}
	settings, err := loadDefaultAgentSettings()
	if err != nil {
		return err
	}
	items, err := passfs.RecoveryItems(settings.Vault)
	if err != nil {
		return err
	}
	for _, item := range items {
		if filepath.Clean(item.Path) == clean {
			return nil
		}
	}
	return errors.New("the app-selected recovery item no longer exists")
}

func validateAgentHomeParent(path string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("locate user home: %w", err)
	}
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return fmt.Errorf("resolve user home: %w", err)
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("resolve app-selected parent directory: %w", err)
	}
	if !pathWithinLexically(resolvedHome, resolvedParent) {
		return errors.New("the app-selected parent directory resolves outside the user home")
	}
	return nil
}

func loadDefaultAgentSettings() (*passfs.Settings, error) {
	path, err := passfs.DefaultSettingsPath()
	if err != nil {
		return nil, err
	}
	return passfs.LoadSettings(path)
}
