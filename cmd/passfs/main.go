package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"

	"passfs/internal/passfs"
)

var version = "0.1.0-dev"
var errPlatformFilesystemApprovalRequired = errors.New(
	"platform filesystem approval required",
)

const (
	defaultMaxFileSize = 16 * 1024 * 1024
	serviceWaitTimeout = 10 * time.Second
)

func main() {
	if len(os.Args) == 1 {
		launched, err := launchPlatformApp()
		if err != nil {
			fmt.Fprintf(os.Stderr, "passfs: %s\n", terminalSafeError(err))
			os.Exit(1)
		}
		if launched {
			return
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "__touchid-helper" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}
	if err := runCLI(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "passfs: %s\n", terminalSafeError(err))
		os.Exit(1)
	}
}

func terminalPath(path string) string {
	for _, character := range path {
		if unicode.IsControl(character) ||
			unicode.In(character, unicode.Cf, unicode.Zl, unicode.Zp) {
			return strconv.QuoteToGraphic(path)
		}
	}
	return path
}

func terminalSafeError(err error) string {
	if err == nil {
		return ""
	}
	var result strings.Builder
	for _, character := range err.Error() {
		switch {
		case character == '\n' || character == '\t':
			result.WriteRune(character)
		case unicode.IsControl(character) ||
			unicode.In(character, unicode.Cf, unicode.Zl, unicode.Zp):
			fmt.Fprintf(&result, "\\u%04x", character)
		default:
			result.WriteRune(character)
		}
	}
	return result.String()
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func runCLI(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("missing command")
	}
	printCachedUpdateNotice(args[0], stderr)

	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "encrypt":
		return runEncrypt(args[1:], stdout, stderr)
	case "unprotect":
		return runUnprotect(args[1:], stdout, stderr)
	case "edit":
		return runEdit(args[1:], stdout, stderr)
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "ignore":
		return runIgnore(args[1:], false, stdout, stderr)
	case "unignore":
		return runIgnore(args[1:], true, stdout, stderr)
	case "ignored":
		return runIgnored(args[1:], stdout, stderr)
	case "protected":
		return runProtected(args[1:], stdout, stderr)
	case "mount":
		return runMount(args[1:], stdout, stderr)
	case "unmount":
		return runUnmount(args[1:], stdout, stderr)
	case "reload":
		return runReload(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr)
	case "setup":
		return runSetup(args[1:], stdout, stderr)
	case "update":
		return runUpdate(args[1:], stdout, stderr)
	case "__update-status":
		return runCachedUpdateStatus(args[1:], stdout)
	case "passwd":
		return runPasswd(args[1:], stdout, stderr)
	case "config":
		return runConfig(args[1:], stdout, stderr)
	case "touchid":
		return runTouchID(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stderr)
	case "__touchid-helper":
		return runTouchIDHelper(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "passfs %s\n", version)
		return nil
	case "help", "--help", "-h":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, `passfs exposes age-encrypted files through one local virtual filesystem.

Usage:
  passfs init [options]
  passfs scan [options] [PATH...]
  passfs ignore [options] FILE...
  passfs unignore [options] FILE...
  passfs encrypt [options] FILE...
  passfs protected [options]
  passfs unprotect [options] [FILE]
  passfs edit [options] FILE
  passfs status [options]
  passfs config [options]
  passfs touchid enable|disable|status|verify [options]
  passfs update [options]
  passfs version

Advanced service and recovery commands:
  passfs mount|unmount|reload|doctor|setup [options]
  passfs passwd [options]

Run "passfs COMMAND -h" for command-specific options.
Machine-readable documentation: https://getpassfs.com/llms.txt`)
}

type commonFlags struct {
	configPath string
}

func addCommonFlags(flags *flag.FlagSet, values *commonFlags) error {
	defaultPath, err := passfs.DefaultSettingsPath()
	if err != nil {
		return err
	}
	flags.StringVar(&values.configPath, "config", defaultPath, "path to the passfs settings file")
	return nil
}

func parseCommonOnlyFlags(
	command string,
	args []string,
	stderr io.Writer,
) (commonFlags, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	if err := addCommonFlags(flags, &common); err != nil {
		return common, err
	}
	if err := flags.Parse(args); err != nil {
		return common, err
	}
	if flags.NArg() != 0 {
		return common, fmt.Errorf("usage: passfs %s [options]", command)
	}
	return common, nil
}

type promptFlags struct {
	mode     string
	pinentry string
}

func addPromptFlags(flags *flag.FlagSet, values *promptFlags) {
	flags.StringVar(&values.mode, "prompt", "auto", `prompt backend: "tty", "native", "pinentry", or "auto"`)
	flags.StringVar(&values.pinentry, "pinentry", "", "path to an optional pinentry executable")
}

func (values promptFlags) build() (passfs.Prompter, error) {
	return passfs.NewPrompter(values.mode, values.pinentry)
}

func addMaxFileSizeFlag(flags *flag.FlagSet, value *int64) {
	flags.Int64Var(
		value,
		"max-file-size",
		defaultMaxFileSize,
		"maximum plaintext file size in bytes",
	)
}

func validateMaxFileSize(value int64) error {
	if value <= 0 {
		return errors.New("--max-file-size must be greater than zero")
	}
	return nil
}

func runInit(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var promptOptions promptFlags
	var vaultPath string
	var mountPoint string
	var unlockFor time.Duration
	var disableTouchID bool
	var adapterName string
	var noMount bool
	var noOpen bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	addPromptFlags(flags, &promptOptions)
	defaultVault, err := passfs.DefaultVaultPath()
	if err != nil {
		return err
	}
	defaultMountPoint, err := passfs.DefaultMountPoint()
	if err != nil {
		return err
	}
	flags.StringVar(&vaultPath, "vault", defaultVault, "directory that stores encrypted data")
	flags.StringVar(&mountPoint, "mount-point", defaultMountPoint, "directory where passfs is mounted")
	flags.DurationVar(&unlockFor, "unlock-for", 0, "per-file authorization duration")
	flags.BoolVar(
		&disableTouchID,
		"no-touchid",
		false,
		"disable the default Touch ID setup on macOS",
	)
	flags.StringVar(
		&adapterName,
		"adapter",
		"",
		`filesystem adapter: "auto", "fskit", or "fuse"`,
	)
	flags.BoolVar(
		&noMount,
		"no-mount",
		false,
		"initialize the vault without starting the filesystem",
	)
	flags.BoolVar(
		&noOpen,
		"no-open",
		false,
		"do not open platform settings while completing setup",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs init [options]")
	}
	requested, err := normalizeFilesystemAdapter(
		adapterName,
		platformFilesystemAdapters(),
	)
	if err != nil {
		return err
	}

	settings, loadErr := passfs.LoadSettings(common.configPath)
	switch {
	case loadErr == nil:
		var incompatible []string
		flags.Visit(func(value *flag.Flag) {
			switch value.Name {
			case "adapter", "config", "no-mount", "no-open",
				"pinentry", "prompt":
			default:
				incompatible = append(incompatible, "--"+value.Name)
			}
		})
		if len(incompatible) != 0 {
			return fmt.Errorf(
				"passfs is already initialized at %s; %s can only be used for a new vault",
				terminalPath(settings.Path()),
				strings.Join(incompatible, ", "),
			)
		}
		if adapterName != "" && settings.Adapter != requested {
			settings.Adapter = requested
			if err := settings.Save(); err != nil {
				return fmt.Errorf("save filesystem adapter: %w", err)
			}
		}
		fmt.Fprintf(
			stdout,
			"PassFS is initialized at %s; completing filesystem setup.\n",
			terminalPath(settings.Path()),
		)
	case errors.Is(loadErr, os.ErrNotExist):
		prompter, err := promptOptions.build()
		if err != nil {
			return err
		}
		settings, err = passfs.NewSettings(
			common.configPath,
			vaultPath,
			mountPoint,
			unlockFor,
		)
		if err != nil {
			return err
		}
		touchIDEnabled, touchIDWarning, err := initVolumeWithPlatformDefaults(
			context.Background(),
			settings.Vault,
			prompter,
			disableTouchID,
		)
		if err != nil {
			return err
		}
		settings.TouchID = touchIDEnabled
		if adapterName != "" {
			settings.Adapter = requested
		}
		if err := os.MkdirAll(settings.MountPoint, 0o700); err != nil {
			return fmt.Errorf("create mount point: %w", err)
		}
		if err := settings.Save(); err != nil {
			return fmt.Errorf("save settings: %w", err)
		}
		if touchIDWarning != nil {
			fmt.Fprintf(stderr, "Warning: Touch ID was not enabled: %v\n", touchIDWarning)
			fmt.Fprintln(stderr, "passfs will use the volume passphrase for authorization.")
		}

		fmt.Fprintf(
			stdout,
			"Initialized PassFS\nConfig:      %s\nVault:       %s\nMount point: %s\n",
			terminalPath(settings.Path()),
			terminalPath(settings.Vault),
			terminalPath(settings.MountPoint),
		)
		if unlockFor == 0 {
			if settings.TouchID {
				fmt.Fprintln(stdout, "Authorization: Touch ID required for every file open")
			} else {
				fmt.Fprintln(stdout, "Authorization: passphrase required for every file open")
			}
		} else {
			fmt.Fprintf(stdout, "Per-file authorization: %s\n", unlockFor)
		}
	default:
		return loadErr
	}

	if noMount {
		fmt.Fprintln(stdout, "Vault initialized; filesystem startup was skipped.")
		return nil
	}
	if err := preparePlatformFilesystemForInit(
		settings,
		requestedAdapter(settings),
		stdout,
	); err != nil {
		return err
	}
	mountArguments := []string{"--config", settings.Path()}
	if noOpen {
		mountArguments = append(mountArguments, "--no-open")
	}
	return runMount(mountArguments, stdout, stderr)
}

func runEncrypt(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: passfs encrypt [options] FILE...")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Protect one or more files. A batch requires one authorization.")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Options:")
		flags.PrintDefaults()
	}
	var common commonFlags
	var maxFileSize int64
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	addMaxFileSizeFlag(flags, &maxFileSize)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() == 0 {
		return errors.New("passfs encrypt requires at least one FILE")
	}
	if err := validateMaxFileSize(maxFileSize); err != nil {
		return err
	}

	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	if err := requireHealthyMount(settings.MountPoint); err != nil {
		return err
	}

	sourcePaths := make([]string, 0, flags.NArg())
	for _, argument := range flags.Args() {
		sourcePath, err := filepath.Abs(argument)
		if err != nil {
			return err
		}
		internal, err := pathsOverlap(filepath.Dir(settings.Path()), sourcePath)
		if err != nil {
			return fmt.Errorf("resolve passfs internal path: %w", err)
		}
		inVault, err := pathsOverlap(settings.Vault, sourcePath)
		if err != nil {
			return fmt.Errorf("resolve passfs vault path: %w", err)
		}
		if internal || inVault {
			return fmt.Errorf("refusing to encrypt passfs internal path %s", terminalPath(sourcePath))
		}
		sourcePaths = append(sourcePaths, sourcePath)
	}
	for _, sourcePath := range sourcePaths {
		if err := passfs.ValidateImportThroughMount(
			sourcePath,
			settings.MountPoint,
			maxFileSize,
		); err != nil {
			return fmt.Errorf("validate %s: %w", terminalPath(sourcePath), err)
		}
	}

	var sessionToken string
	adapter, err := activeFilesystemAdapter(settings.MountPoint)
	if err != nil {
		return err
	}
	processSessions := adapter.SupportsProcessSessions()
	if len(sourcePaths) > 1 && processSessions {
		sessionToken, err = passfs.BeginEncryptSession(settings.MountPoint)
		if err != nil {
			return fmt.Errorf(
				"authorize encrypting %d files: %w",
				len(sourcePaths),
				err,
			)
		}
	} else if len(sourcePaths) > 1 {
		fmt.Fprintln(
			stderr,
			"FSKit does not expose caller process IDs; each file requires its own authorization.",
		)
	}

	encryptErr := encryptPaths(
		sourcePaths,
		settings.MountPoint,
		maxFileSize,
		settings,
		adapter,
		stdout,
	)
	if sessionToken == "" {
		return encryptErr
	}
	endErr := passfs.EndEncryptSession(settings.MountPoint, sessionToken)
	if endErr != nil {
		endErr = fmt.Errorf("end batch authorization: %w", endErr)
	}
	return errors.Join(encryptErr, endErr)
}

func encryptPaths(
	sourcePaths []string,
	mountPoint string,
	maxFileSize int64,
	settings *passfs.Settings,
	adapter filesystemAdapter,
	stdout io.Writer,
) error {
	for _, sourcePath := range sourcePaths {
		result, err := passfs.ImportThroughMount(
			sourcePath,
			mountPoint,
			maxFileSize,
			func(sourcePath, targetPath string) error {
				return adapter.RegisterProtectedLink(
					settings,
					sourcePath,
					targetPath,
				)
			},
		)
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", terminalPath(sourcePath), err)
		}
		switch {
		case result.Imported:
			fmt.Fprintf(stdout, "Encrypted %s\n", terminalPath(sourcePath))
		case result.LinkCreated:
			fmt.Fprintf(stdout, "Restored protected link %s\n", terminalPath(sourcePath))
		default:
			fmt.Fprintf(stdout, "%s is already protected\n", terminalPath(sourcePath))
		}
		fmt.Fprintf(stdout, "Protected by %s\n", terminalPath(result.TargetPath))
	}
	return nil
}

func runUnprotect(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("unprotect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: passfs unprotect [options] [FILE]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "With FILE, remove protection only from that file.")
		fmt.Fprintln(stderr, "Without FILE, remove protection from every passfs file.")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Options:")
		flags.PrintDefaults()
	}
	var common commonFlags
	var maxFileSize int64
	var promptMode string
	var pinentryPath string
	var confirmed bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	addMaxFileSizeFlag(flags, &maxFileSize)
	flags.StringVar(
		&promptMode,
		"prompt",
		"configured",
		`authorization backend: "configured", "tty", "native", "pinentry", or "auto"`,
	)
	flags.StringVar(
		&pinentryPath,
		"pinentry",
		"",
		"path to an optional pinentry executable",
	)
	flags.BoolVar(
		&confirmed,
		"yes",
		false,
		"confirm unprotecting the specified FILE (for trusted UI clients)",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 1 {
		return errors.New("usage: passfs unprotect [options] [FILE]")
	}
	if confirmed && flags.NArg() != 1 {
		return errors.New("--yes requires exactly one FILE")
	}
	if err := validateMaxFileSize(maxFileSize); err != nil {
		return err
	}

	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	var sourcePath string
	if flags.NArg() == 1 {
		sourcePath, err = filepath.Abs(flags.Arg(0))
		if err != nil {
			return err
		}
		sourcePath = filepath.Clean(sourcePath)
	}
	if !confirmed {
		if err := confirmUnprotect(stderr, sourcePath); err != nil {
			return err
		}
	}

	var prompter passfs.Prompter
	if promptMode == "configured" {
		prompter, err = newServicePrompter(settings)
	} else {
		prompter, err = passfs.NewPrompter(promptMode, pinentryPath)
	}
	if err != nil {
		return err
	}

	restoreService := false
	if sourcePath != "" {
		status, err := queryService()
		if err != nil {
			return err
		}
		mount, err := inspectMount(settings.MountPoint)
		if err != nil {
			return err
		}
		if mount.mounted && !mount.passfs {
			return fmt.Errorf(
				"%s is mounted by another filesystem",
				settings.MountPoint,
			)
		}
		restoreService = status.Installed || mount.mounted
	}
	restore := func() error {
		if !restoreService {
			return nil
		}
		return runReload(
			[]string{"--config", settings.Path()},
			stdout,
			stderr,
		)
	}

	if err := runUnmount(
		[]string{"--config", settings.Path()},
		stdout,
		stderr,
	); err != nil {
		return errors.Join(err, restore())
	}
	report, err := unprotectFiles(
		settings,
		prompter,
		maxFileSize,
		sourcePath,
	)
	if err != nil {
		return errors.Join(err, restore())
	}
	restoreErr := restore()

	if report.Err != nil {
		operationErr := fmt.Errorf(
			"authorize unprotect: %w\nencrypted data was preserved",
			report.Err,
		)
		if !restoreService {
			operationErr = fmt.Errorf(
				"%w; remount it with:\n  passfs mount",
				operationErr,
			)
		}
		return errors.Join(operationErr, restoreErr)
	}
	for _, path := range report.Unprotected {
		fmt.Fprintf(stdout, "Unprotected %s\n", terminalPath(path))
	}
	for _, issue := range report.Warnings {
		fmt.Fprintf(
			stderr,
			"Warning: %s was unprotected but cleanup needs attention: %v\n",
			terminalPath(issue.Path),
			issue.Err,
		)
	}
	for _, issue := range report.Failed {
		fmt.Fprintf(
			stderr,
			"Could not unprotect %s: %v\n",
			terminalPath(issue.Path),
			issue.Err,
		)
	}
	if len(report.Failed) != 0 {
		var operationErr error
		if sourcePath != "" {
			operationErr = actionableError{
				fmt.Sprintf(
					"%s could not be unprotected; its encrypted data was preserved",
					terminalPath(sourcePath),
				),
			}
		} else {
			operationErr = actionableError{
				fmt.Sprintf(
					"%d protected file(s) could not be unprotected; their encrypted data was preserved",
					len(report.Failed),
				),
				"resolve the reported conflicts and run:",
				"  passfs unprotect",
				"or remount the remaining protected files with:",
				"  passfs mount",
			}
		}
		return errors.Join(operationErr, restoreErr)
	}
	if restoreErr != nil {
		return actionableError{
			"the file was unprotected, but the passfs service could not be restored: " +
				restoreErr.Error(),
			"recover the remaining protected files with:",
			"  passfs reload",
		}
	}
	if sourcePath != "" {
		fmt.Fprintf(
			stdout,
			"%s is now a regular plaintext file; its encrypted copy was permanently deleted.\n",
			sourcePath,
		)
		return nil
	}
	if len(report.Unprotected) == 0 {
		fmt.Fprintln(stdout, "No protected files found")
		return nil
	}
	fmt.Fprintln(stdout, "All passfs files are now regular plaintext files.")
	fmt.Fprintln(stdout, "Their encrypted copies were permanently deleted.")
	fmt.Fprintln(stdout, "passfs is unmounted and automatic startup is disabled.")
	return nil
}

func unprotectFiles(
	settings *passfs.Settings,
	prompter passfs.Prompter,
	maxFileSize int64,
	sourcePath string,
) (passfs.UnprotectReport, error) {
	instanceLock, err := passfs.AcquireInstanceLock()
	if err != nil {
		return passfs.UnprotectReport{}, err
	}
	defer instanceLock.Close()

	volume, err := passfs.LoadVolume(settings.Vault, prompter, maxFileSize, 0)
	if err != nil {
		return passfs.UnprotectReport{}, err
	}
	defer volume.Lock()

	forbiddenRoots := []string{
		filepath.Dir(settings.Path()),
		settings.Vault,
		settings.MountPoint,
	}
	if sourcePath != "" {
		return volume.UnprotectFile(
			context.Background(),
			sourcePath,
			forbiddenRoots,
		), nil
	}
	return volume.UnprotectAll(
		context.Background(),
		forbiddenRoots,
	), nil
}

func confirmUnprotect(writer io.Writer, sourcePath string) error {
	printUnprotectWarning(writer, sourcePath)

	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open terminal for confirmation: %w", err)
	}
	defer terminal.Close()
	return readUnprotectConfirmation(terminal)
}

func printUnprotectWarning(writer io.Writer, sourcePath string) {
	fmt.Fprintln(writer, "WARNING: passfs protection will be permanently removed.")
	if sourcePath == "" {
		fmt.Fprintln(writer, "All protected links will become regular plaintext files on disk.")
	} else {
		fmt.Fprintf(
			writer,
			"%s will become a regular plaintext file on disk.\n",
			terminalPath(sourcePath),
		)
	}
	fmt.Fprintln(writer, "After each plaintext is safely written, its encrypted copy will be permanently deleted.")
	fmt.Fprintln(writer, "The plaintext may remain in backups, snapshots, caches, and free disk space.")
	fmt.Fprint(writer, "Type UNPROTECT to continue: ")
}

func readUnprotectConfirmation(reader io.Reader) error {
	confirmation, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read unprotect confirmation: %w", err)
	}
	if strings.TrimSpace(confirmation) != "UNPROTECT" {
		return passfs.ErrPromptCancelled
	}
	return nil
}

func runEdit(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("edit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var vimExecutable string
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	flags.StringVar(&vimExecutable, "vim", "vim", "Vim executable to use")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: passfs edit [options] FILE")
	}

	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	if err := requireHealthyMount(settings.MountPoint); err != nil {
		return err
	}

	sourcePath, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return err
	}
	targetPath, err := passfs.MountedPath(settings.MountPoint, sourcePath)
	if err != nil {
		return err
	}
	targetInfo, err := os.Lstat(targetPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf(
				"%s is not protected; run \"passfs encrypt %s\" first",
				terminalPath(sourcePath),
				terminalPath(flags.Arg(0)),
			)
		}
		return fmt.Errorf("inspect protected target: %w", err)
	}
	if !targetInfo.Mode().IsRegular() {
		return fmt.Errorf(
			"protected target %s is not a regular file",
			terminalPath(targetPath),
		)
	}
	if _, err := passfs.EnsureProtectedLink(sourcePath, targetPath); err != nil {
		return err
	}
	if err := passfs.MarkProtectedLink(targetPath); err != nil {
		return fmt.Errorf("register protected link with passfs: %w", err)
	}

	vimPath, err := exec.LookPath(vimExecutable)
	if err != nil {
		return fmt.Errorf("find Vim executable %q: %w", vimExecutable, err)
	}
	command := exec.Command(
		vimPath,
		"--clean",
		"-n",
		"-i",
		"NONE",
		"-c",
		"setlocal noswapfile nobackup nowritebackup noundofile backupcopy=yes",
		"--",
		sourcePath,
	)
	command.Stdin = os.Stdin
	command.Stdout = stdout
	command.Stderr = stderr

	adapter, err := activeFilesystemAdapter(settings.MountPoint)
	if err != nil {
		return err
	}
	processSessions := adapter.SupportsProcessSessions()
	var sessionToken string
	if processSessions {
		sessionToken, err = passfs.BeginEditSession(targetPath)
		if err != nil {
			return fmt.Errorf(
				"authorize edit session for %s: %w",
				terminalPath(sourcePath),
				err,
			)
		}
	} else {
		fmt.Fprintln(
			stderr,
			"FSKit does not expose caller process IDs; the editor may request authorization more than once.",
		)
	}
	commandErr := command.Run()
	_, reconcileErr := passfs.ReconcileProtectedEdit(
		sourcePath,
		targetPath,
		defaultMaxFileSize,
		func(sourcePath, targetPath string) error {
			return adapter.RegisterProtectedLink(
				settings,
				sourcePath,
				targetPath,
			)
		},
	)
	var endErr error
	if sessionToken != "" {
		endErr = passfs.EndEditSession(targetPath, sessionToken)
	}
	if commandErr != nil {
		commandErr = fmt.Errorf(
			"edit %s with Vim: %w",
			terminalPath(sourcePath),
			commandErr,
		)
	}
	if reconcileErr != nil {
		reconcileErr = fmt.Errorf(
			"protect edited file %s: %w",
			terminalPath(sourcePath),
			reconcileErr,
		)
	}
	if endErr != nil {
		endErr = fmt.Errorf(
			"close edit session for %s: %w",
			terminalPath(sourcePath),
			endErr,
		)
	}
	return errors.Join(commandErr, reconcileErr, endErr)
}

func runMount(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("mount", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var adapterName string
	var noOpen bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	flags.StringVar(
		&adapterName,
		"adapter",
		"",
		`filesystem adapter: "auto", "fskit", or "fuse"`,
	)
	flags.BoolVar(
		&noOpen,
		"no-open",
		false,
		"do not open platform settings while completing setup",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs mount [options]")
	}

	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	requested := requestedAdapter(settings)
	if adapterName != "" {
		requested = strings.ToLower(strings.TrimSpace(adapterName))
	}
	adapter, err := selectFilesystemAdapter(requested, settings)
	if err != nil {
		return err
	}
	if adapterName != "" && settings.Adapter != requested {
		settings.Adapter = requested
		if err := settings.Save(); err != nil {
			return fmt.Errorf("save filesystem adapter: %w", err)
		}
	}
	service, err := queryService()
	if err != nil {
		return err
	}
	mount, err := inspectMount(settings.MountPoint)
	if err != nil {
		return err
	}
	if mount.mounted {
		if !mount.passfs {
			return fmt.Errorf(
				"%s is mounted by another filesystem",
				terminalPath(settings.MountPoint),
			)
		}
		if mount.healthy {
			if !service.Installed || !service.Running {
				return actionableError{
					"passfs is mounted outside its supervised service",
					"recover it with:",
					"  passfs reload",
				}
			}
			active, activeErr := activeFilesystemAdapter(settings.MountPoint)
			if activeErr == nil && active.Name() != adapter.Name() {
				fmt.Fprintf(
					stdout,
					"Switching filesystem adapter from %s to %s.\n",
					active.Name(),
					adapter.Name(),
				)
				reloadArguments := []string{
					"--config",
					settings.Path(),
				}
				if noOpen {
					reloadArguments = append(
						reloadArguments,
						"--no-open",
					)
				}
				return runReload(reloadArguments, stdout, stderr)
			}
			fmt.Fprintf(
				stdout,
				"passfs is already mounted at %s\n",
				terminalPath(settings.MountPoint),
			)
			return nil
		}
		if err := passfs.UnmountPath(settings.MountPoint); err != nil {
			return fmt.Errorf(
				"remove unavailable passfs mount at %s: %w",
				terminalPath(settings.MountPoint),
				err,
			)
		}
		if err := waitForMountState(settings.MountPoint, false, serviceWaitTimeout); err != nil {
			return err
		}
	}
	if err := ensureMountDirectories(settings); err != nil {
		return err
	}
	if entries, err := os.ReadDir(settings.MountPoint); err != nil {
		return err
	} else if len(entries) != 0 {
		return fmt.Errorf(
			"mount point %s is not empty",
			terminalPath(settings.MountPoint),
		)
	}

	executable, err := currentExecutable()
	if err != nil {
		return err
	}
	logHint := serviceLogHint(settings.Path())
	logOffset := serviceLogOffset(logHint)
	if err := installAndStartService(
		executable,
		settings.Path(),
		adapter.Name(),
	); err != nil {
		return err
	}
	if err := waitForFilesystemMount(
		settings,
		adapter,
		logHint,
		logOffset,
		!noOpen,
		stdout,
	); err != nil {
		return err
	}
	fmt.Fprintf(
		stdout,
		"Mounted passfs at %s using %s\n",
		terminalPath(settings.MountPoint),
		adapter.Name(),
	)
	fmt.Fprintln(stdout, "The service will start automatically after login.")
	return nil
}

func runReload(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("reload", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var noOpen bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	flags.BoolVar(
		&noOpen,
		"no-open",
		false,
		"do not open platform settings while completing setup",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs reload [options]")
	}

	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	adapter, err := selectFilesystemAdapter(requestedAdapter(settings), settings)
	if err != nil {
		return err
	}
	status, err := queryService()
	if err != nil {
		return err
	}
	mount, err := inspectMount(settings.MountPoint)
	if err != nil {
		return err
	}
	if mount.mounted && !mount.passfs {
		return fmt.Errorf(
			"%s is mounted by another filesystem",
			terminalPath(settings.MountPoint),
		)
	}

	if status.Running {
		if err := stopService(); err != nil {
			return fmt.Errorf("stop passfs service: %w", err)
		}
	}
	if mount.mounted {
		var unmountErr error
		if status.Running {
			unmountErr = waitForMountState(
				settings.MountPoint,
				false,
				serviceWaitTimeout,
			)
		} else {
			unmountErr = errors.New("orphaned passfs mount")
		}
		if unmountErr != nil {
			if forceErr := passfs.UnmountPath(settings.MountPoint); forceErr != nil {
				return errors.Join(
					unmountErr,
					fmt.Errorf("force unmount passfs: %w", forceErr),
				)
			}
			if retryErr := waitForMountState(
				settings.MountPoint,
				false,
				serviceWaitTimeout,
			); retryErr != nil {
				return errors.Join(unmountErr, retryErr)
			}
		}
	}
	if err := ensureMountDirectories(settings); err != nil {
		return err
	}

	executable, err := currentExecutable()
	if err != nil {
		return err
	}
	logHint := serviceLogHint(settings.Path())
	logOffset := serviceLogOffset(logHint)
	if err := installAndStartService(
		executable,
		settings.Path(),
		adapter.Name(),
	); err != nil {
		return err
	}
	if err := waitForFilesystemMount(
		settings,
		adapter,
		logHint,
		logOffset,
		!noOpen,
		stdout,
	); err != nil {
		return err
	}
	fmt.Fprintf(
		stdout,
		"Reloaded passfs at %s using %s\n",
		terminalPath(settings.MountPoint),
		adapter.Name(),
	)
	return nil
}

func runUnmount(args []string, stdout, stderr io.Writer) error {
	common, err := parseCommonOnlyFlags("unmount", args, stderr)
	if err != nil {
		return err
	}

	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	status, err := queryService()
	if err != nil {
		return err
	}
	mount, err := inspectMount(settings.MountPoint)
	if err != nil {
		return err
	}
	if mount.mounted && !mount.passfs {
		return fmt.Errorf(
			"%s is mounted by another filesystem",
			terminalPath(settings.MountPoint),
		)
	}
	if !status.Installed && !mount.mounted {
		fmt.Fprintln(stdout, "passfs is not mounted")
		return nil
	}
	if !status.Installed && mount.mounted {
		if err := passfs.UnmountPath(settings.MountPoint); err != nil {
			return fmt.Errorf(
				"unmount passfs at %s: %w",
				terminalPath(settings.MountPoint),
				err,
			)
		}
		if err := waitForMountState(settings.MountPoint, false, serviceWaitTimeout); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "Unmounted passfs")
		return nil
	}
	if err := stopAndRemoveService(); err != nil {
		return err
	}
	if mount.mounted {
		if !status.Running {
			if err := passfs.UnmountPath(settings.MountPoint); err != nil {
				return fmt.Errorf("remove orphaned passfs mount: %w", err)
			}
		}
		if err := waitForMountState(settings.MountPoint, false, serviceWaitTimeout); err != nil {
			if forceErr := passfs.UnmountPath(settings.MountPoint); forceErr != nil {
				return errors.Join(err, fmt.Errorf("force unmount passfs: %w", forceErr))
			}
			if retryErr := waitForMountState(
				settings.MountPoint,
				false,
				serviceWaitTimeout,
			); retryErr != nil {
				return errors.Join(err, retryErr)
			}
		}
	}
	fmt.Fprintln(stdout, "Unmounted passfs and disabled automatic startup")
	return nil
}

func currentExecutable() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	return resolveExecutablePath(executable)
}

func resolveExecutablePath(executable string) (string, error) {
	absolute, err := filepath.Abs(executable)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve passfs executable: %w", err)
	}
	return resolved, nil
}

func runStatus(args []string, stdout, stderr io.Writer) error {
	common, err := parseCommonOnlyFlags("status", args, stderr)
	if err != nil {
		return err
	}

	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	status, err := queryService()
	if err != nil {
		return err
	}
	mount, err := inspectMount(settings.MountPoint)
	if err != nil {
		return err
	}
	serviceDescription := "not installed"
	if status.Installed {
		serviceDescription = "stopped"
	}
	if status.Running {
		serviceDescription = "running"
	}
	filesystemDescription := "not mounted"
	if mount.mounted && mount.passfs && mount.healthy {
		filesystemDescription = "mounted"
	} else if mount.mounted && mount.passfs {
		filesystemDescription = "unavailable"
	} else if mount.mounted {
		filesystemDescription = "occupied by another filesystem"
	}
	activeAdapter := ""
	if mount.mounted && mount.passfs {
		_, activeAdapter, _ = passfs.MountAdapterStatus(settings.MountPoint)
	}
	adapterDescription := requestedAdapter(settings)
	if activeAdapter != "" {
		adapterDescription += " (mounted with " + activeAdapter + ")"
	}
	fmt.Fprintf(
		stdout,
		"Service:     %s\nFilesystem:  %s\nAdapter:     %s\nMount point: %s\nVault:       %s\n",
		serviceDescription,
		filesystemDescription,
		adapterDescription,
		terminalPath(settings.MountPoint),
		terminalPath(settings.Vault),
	)
	return nil
}

func runServe(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var maxFileSize int64
	var debug bool
	var adapterName string
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	addMaxFileSizeFlag(flags, &maxFileSize)
	flags.BoolVar(&debug, "debug", false, "enable verbose FUSE logging")
	flags.StringVar(
		&adapterName,
		"adapter",
		"",
		`filesystem adapter: "auto", "fskit", or "fuse"`,
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs serve [options]")
	}
	if err := validateMaxFileSize(maxFileSize); err != nil {
		return err
	}

	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	requested := requestedAdapter(settings)
	if adapterName != "" {
		requested = adapterName
	}
	adapter, err := selectFilesystemAdapter(requested, settings)
	if err != nil {
		return err
	}
	instanceLock, err := passfs.AcquireInstanceLock()
	if err != nil {
		return err
	}
	defer instanceLock.Close()

	mount, err := inspectMount(settings.MountPoint)
	if err != nil {
		return err
	}
	if mount.mounted {
		if !mount.passfs || mount.healthy {
			return fmt.Errorf(
				"mount point %s is already in use",
				terminalPath(settings.MountPoint),
			)
		}
		if err := passfs.UnmountPath(settings.MountPoint); err != nil {
			return fmt.Errorf("remove unavailable passfs mount: %w", err)
		}
		if err := waitForMountState(settings.MountPoint, false, serviceWaitTimeout); err != nil {
			return err
		}
	}
	if err := ensureMountDirectories(settings); err != nil {
		return err
	}
	if entries, err := os.ReadDir(settings.MountPoint); err != nil {
		return err
	} else if len(entries) != 0 {
		return fmt.Errorf(
			"mount point %s is not empty",
			terminalPath(settings.MountPoint),
		)
	}

	return adapter.Serve(settings, maxFileSize, debug, stderr)
}

func runPasswd(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("passwd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var promptOptions promptFlags
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	addPromptFlags(flags, &promptOptions)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs passwd [options]")
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	prompter, err := promptOptions.build()
	if err != nil {
		return err
	}
	if err := passfs.ChangePassphrase(context.Background(), settings.Vault, prompter); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Passphrase changed")
	return nil
}

func runConfig(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("config", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var unlockFor string
	var mountPoint string
	var adapterName string
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	flags.StringVar(&unlockFor, "unlock-for", "", "set per-file authorization duration")
	flags.StringVar(&mountPoint, "mount-point", "", "set the global mount point")
	flags.StringVar(
		&adapterName,
		"adapter",
		"",
		`set the filesystem adapter: "auto", "fskit", or "fuse"`,
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs config [options]")
	}
	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	changed := false
	if unlockFor != "" {
		duration, err := time.ParseDuration(unlockFor)
		if err != nil || duration < 0 {
			return fmt.Errorf("invalid --unlock-for value %q", unlockFor)
		}
		if err := settings.SetUnlockDuration(duration); err != nil {
			return err
		}
		changed = true
	}
	if mountPoint != "" {
		mounted, _, err := passfs.MountStatus(settings.MountPoint)
		if err != nil {
			return err
		}
		if mounted {
			return errors.New("unmount passfs before changing its mount point")
		}
		if err := settings.SetMountPoint(mountPoint); err != nil {
			return err
		}
		if err := os.MkdirAll(settings.MountPoint, 0o700); err != nil {
			return err
		}
		changed = true
	}
	if adapterName != "" {
		normalized, err := normalizeFilesystemAdapter(
			adapterName,
			platformFilesystemAdapters(),
		)
		if err != nil {
			return err
		}
		settings.Adapter = normalized
		changed = true
	}
	if changed {
		if err := settings.Save(); err != nil {
			return err
		}
	}
	duration, err := settings.UnlockDuration()
	if err != nil {
		return err
	}
	fmt.Fprintf(
		stdout,
		"Config:      %s\nVault:       %s\nMount point: %s\nUnlock for:  %s\nAdapter:     %s\n",
		terminalPath(settings.Path()),
		terminalPath(settings.Vault),
		terminalPath(settings.MountPoint),
		formatUnlockDuration(duration),
		requestedAdapter(settings),
	)
	if changed {
		printReloadNotice(stdout)
	}
	return nil
}

func formatUnlockDuration(duration time.Duration) string {
	if duration == 0 {
		return "0m"
	}
	return duration.String()
}

func printReloadNotice(writer io.Writer) {
	fmt.Fprintln(writer, "Restart passfs to apply the change:")
	fmt.Fprintln(writer, "  passfs reload")
}

func loadSettings(path string) (*passfs.Settings, error) {
	settings, err := passfs.LoadSettings(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w; run \"passfs init\" first", err)
	}
	if err != nil {
		return nil, err
	}
	return settings, nil
}

func ensureMountDirectories(settings *passfs.Settings) error {
	for _, directory := range []string{
		filepath.Join(settings.Vault, "files"),
		settings.MountPoint,
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func requireHealthyMount(mountPoint string) error {
	mount, err := inspectMount(mountPoint)
	if err != nil {
		return fmt.Errorf("inspect passfs mount: %w", err)
	}
	if !mount.mounted {
		return actionableError{
			"passfs is not mounted",
			"start it with:",
			"  passfs mount",
			"then retry the command",
		}
	}
	if !mount.passfs {
		return fmt.Errorf(
			"%s is mounted by another filesystem",
			terminalPath(mountPoint),
		)
	}
	if !mount.healthy {
		return fmt.Errorf(
			"the passfs mount at %s is unavailable: %w\nrecover it with:\n  passfs reload\nthen retry the command",
			mountPoint,
			mount.accessErr,
		)
	}
	return nil
}

type actionableError []string

func (err actionableError) Error() string {
	return strings.Join(err, "\n")
}

type mountState struct {
	mounted   bool
	passfs    bool
	healthy   bool
	accessErr error
}

func inspectMount(mountPoint string) (mountState, error) {
	mounted, isPassFS, err := passfs.MountStatus(mountPoint)
	if err != nil {
		return mountState{}, err
	}
	state := mountState{mounted: mounted, passfs: isPassFS}
	if !mounted || !isPassFS {
		return state, nil
	}
	if _, err := os.ReadDir(mountPoint); err != nil {
		state.accessErr = err
		return state, nil
	}
	state.healthy = true
	return state, nil
}

func waitForMountState(mountPoint string, wantMounted bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		mount, err := inspectMount(mountPoint)
		if err != nil {
			return err
		}
		if wantMounted && mount.mounted && !mount.passfs {
			return fmt.Errorf(
				"%s was mounted by another filesystem",
				terminalPath(mountPoint),
			)
		}
		if wantMounted && mount.mounted && mount.passfs && mount.healthy {
			return nil
		}
		if !wantMounted && !mount.mounted {
			return nil
		}
		if time.Now().After(deadline) {
			state := "mount"
			if !wantMounted {
				state = "unmount"
			}
			return fmt.Errorf("timed out waiting for passfs to %s", state)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func waitForFilesystemMount(
	settings *passfs.Settings,
	adapter filesystemAdapter,
	logHint string,
	logOffset int64,
	openSettings bool,
	writer io.Writer,
) error {
	deadline := time.Now().Add(serviceWaitTimeout)
	for {
		mount, err := inspectMount(settings.MountPoint)
		if err != nil {
			return err
		}
		if mount.mounted && !mount.passfs {
			return fmt.Errorf(
				"%s was mounted by another filesystem",
				terminalPath(settings.MountPoint),
			)
		}
		if mount.mounted && mount.passfs && mount.healthy {
			return nil
		}
		if platformFilesystemApprovalRequired(
			adapter.Name(),
			logHint,
			logOffset,
		) {
			return completePlatformFilesystemApproval(
				settings,
				adapter.Name(),
				openSettings,
				writer,
			)
		}
		if time.Now().After(deadline) {
			err := errors.New("timed out waiting for passfs to mount")
			return adapter.MountWaitError(
				err,
				logHint,
				settings.MountPoint,
			)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func serviceLogOffset(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func pathsOverlap(root, path string) (bool, error) {
	root, err := passfs.ResolvePath(root)
	if err != nil {
		return false, err
	}
	parent, err := passfs.ResolvePath(filepath.Dir(path))
	if err != nil {
		return false, err
	}
	path = filepath.Join(parent, filepath.Base(path))
	return passfs.PathWithin(root, path), nil
}
