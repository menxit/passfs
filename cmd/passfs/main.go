package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"passfs/internal/passfs"
)

var version = "0.1.0-dev"

const (
	defaultMaxFileSize = 16 * 1024 * 1024
	serviceWaitTimeout = 10 * time.Second
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__touchid-helper" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}
	if err := runCLI(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "passfs: %v\n", err)
		os.Exit(1)
	}
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
	fmt.Fprintln(writer, `passfs exposes age-encrypted files through one local FUSE filesystem.

Usage:
  passfs init [options]
  passfs mount [options]
  passfs encrypt [options] FILE...
  passfs unprotect [options] [FILE]
  passfs edit [options] FILE
  passfs status [options]
  passfs unmount [options]
  passfs reload [options]
  passfs doctor [options]
  passfs setup [options]
  passfs update [options]
  passfs passwd [options]
  passfs config [options]
  passfs touchid enable|disable|status|verify [options]
  passfs version

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
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: passfs init [options]")
	}
	if _, err := os.Stat(common.configPath); err == nil {
		return fmt.Errorf("passfs is already initialized at %s", common.configPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	prompter, err := promptOptions.build()
	if err != nil {
		return err
	}
	settings, err := passfs.NewSettings(
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
		"Initialized passfs\nConfig:      %s\nVault:       %s\nMount point: %s\n",
		settings.Path(),
		settings.Vault,
		settings.MountPoint,
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
	fmt.Fprintln(stdout, "Run \"passfs mount\" to start the filesystem.")
	return nil
}

func runEncrypt(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	flags.SetOutput(stderr)
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
			return fmt.Errorf("refusing to encrypt passfs internal path %s", sourcePath)
		}
		result, err := passfs.ImportThroughMount(sourcePath, settings.MountPoint, maxFileSize)
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", sourcePath, err)
		}
		switch {
		case result.Imported:
			fmt.Fprintf(stdout, "Encrypted %s\n", sourcePath)
		case result.LinkCreated:
			fmt.Fprintf(stdout, "Restored protected link %s\n", sourcePath)
		default:
			fmt.Fprintf(stdout, "%s is already protected\n", sourcePath)
		}
		fmt.Fprintf(stdout, "Protected by %s\n", result.TargetPath)
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
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 1 {
		return errors.New("usage: passfs unprotect [options] [FILE]")
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
	if err := confirmUnprotect(stderr, sourcePath); err != nil {
		return err
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

	if err := runUnmount(
		[]string{"--config", settings.Path()},
		stdout,
		stderr,
	); err != nil {
		if restoreService {
			restoreErr := runReload(
				[]string{"--config", settings.Path()},
				stdout,
				stderr,
			)
			return errors.Join(err, restoreErr)
		}
		return err
	}
	report, err := unprotectFiles(
		settings,
		prompter,
		maxFileSize,
		sourcePath,
	)
	if err != nil {
		if !restoreService {
			return err
		}
		restoreErr := runReload(
			[]string{"--config", settings.Path()},
			stdout,
			stderr,
		)
		return errors.Join(err, restoreErr)
	}
	var restoreErr error
	if restoreService {
		restoreErr = runReload(
			[]string{"--config", settings.Path()},
			stdout,
			stderr,
		)
	}

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
		fmt.Fprintf(stdout, "Unprotected %s\n", path)
	}
	for _, issue := range report.Warnings {
		fmt.Fprintf(
			stderr,
			"Warning: %s was unprotected but cleanup needs attention: %v\n",
			issue.Path,
			issue.Err,
		)
	}
	for _, issue := range report.Failed {
		fmt.Fprintf(stderr, "Could not unprotect %s: %v\n", issue.Path, issue.Err)
	}
	if len(report.Failed) != 0 {
		var operationErr error
		if sourcePath != "" {
			operationErr = actionableError{
				fmt.Sprintf(
					"%s could not be unprotected; its encrypted data was preserved",
					sourcePath,
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
		fmt.Fprintf(writer, "%s will become a regular plaintext file on disk.\n", sourcePath)
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
			return fmt.Errorf("%s is not protected; run \"passfs encrypt %s\" first", sourcePath, flags.Arg(0))
		}
		return fmt.Errorf("inspect protected target: %w", err)
	}
	if !targetInfo.Mode().IsRegular() {
		return fmt.Errorf("protected target %s is not a regular file", targetPath)
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

	sessionToken, err := passfs.BeginEditSession(targetPath)
	if err != nil {
		return fmt.Errorf("authorize edit session for %s: %w", sourcePath, err)
	}
	commandErr := command.Run()
	endErr := passfs.EndEditSession(targetPath, sessionToken)
	if commandErr != nil {
		commandErr = fmt.Errorf("edit %s with Vim: %w", sourcePath, commandErr)
	}
	if endErr != nil {
		endErr = fmt.Errorf("close edit session for %s: %w", sourcePath, endErr)
	}
	return errors.Join(commandErr, endErr)
}

func runMount(args []string, stdout, stderr io.Writer) error {
	common, err := parseCommonOnlyFlags("mount", args, stderr)
	if err != nil {
		return err
	}

	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	if err := requirePlatformFUSE(); err != nil {
		return err
	}
	if err := ensureMountDirectories(settings); err != nil {
		return err
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
			return fmt.Errorf("%s is mounted by another filesystem", settings.MountPoint)
		}
		if mount.healthy {
			if !service.Installed || !service.Running {
				return actionableError{
					"passfs is mounted outside its supervised service",
					"recover it with:",
					"  passfs reload",
				}
			}
			fmt.Fprintf(stdout, "passfs is already mounted at %s\n", settings.MountPoint)
			return nil
		}
		if err := passfs.UnmountPath(settings.MountPoint); err != nil {
			return fmt.Errorf("remove unavailable passfs mount at %s: %w", settings.MountPoint, err)
		}
		if err := waitForMountState(settings.MountPoint, false, serviceWaitTimeout); err != nil {
			return err
		}
	}
	if entries, err := os.ReadDir(settings.MountPoint); err != nil {
		return err
	} else if len(entries) != 0 {
		return fmt.Errorf("mount point %s is not empty", settings.MountPoint)
	}

	executable, err := currentExecutable()
	if err != nil {
		return err
	}
	if err := installAndStartService(executable, settings.Path()); err != nil {
		return err
	}
	if err := waitForMountState(settings.MountPoint, true, serviceWaitTimeout); err != nil {
		return platformMountWaitError(err, serviceLogHint(settings.Path()))
	}
	fmt.Fprintf(stdout, "Mounted passfs at %s\n", settings.MountPoint)
	fmt.Fprintln(stdout, "The service will start automatically after login.")
	return nil
}

func runReload(args []string, stdout, stderr io.Writer) error {
	common, err := parseCommonOnlyFlags("reload", args, stderr)
	if err != nil {
		return err
	}

	settings, err := loadSettings(common.configPath)
	if err != nil {
		return err
	}
	if err := ensureMountDirectories(settings); err != nil {
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
		return fmt.Errorf("%s is mounted by another filesystem", settings.MountPoint)
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

	executable, err := currentExecutable()
	if err != nil {
		return err
	}
	if err := installAndStartService(executable, settings.Path()); err != nil {
		return err
	}
	if err := waitForMountState(settings.MountPoint, true, serviceWaitTimeout); err != nil {
		return platformMountWaitError(err, serviceLogHint(settings.Path()))
	}
	fmt.Fprintf(stdout, "Reloaded passfs at %s\n", settings.MountPoint)
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
		return fmt.Errorf("%s is mounted by another filesystem", settings.MountPoint)
	}
	if !status.Installed && !mount.mounted {
		fmt.Fprintln(stdout, "passfs is not mounted")
		return nil
	}
	if !status.Installed && mount.mounted {
		if err := passfs.UnmountPath(settings.MountPoint); err != nil {
			return fmt.Errorf("unmount passfs at %s: %w", settings.MountPoint, err)
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
	fmt.Fprintf(
		stdout,
		"Service:     %s\nFilesystem:  %s\nMount point: %s\nVault:       %s\n",
		serviceDescription,
		filesystemDescription,
		settings.MountPoint,
		settings.Vault,
	)
	return nil
}

func runServe(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	var maxFileSize int64
	var debug bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	addMaxFileSizeFlag(flags, &maxFileSize)
	flags.BoolVar(&debug, "debug", false, "enable verbose FUSE logging")
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
	if err := ensureMountDirectories(settings); err != nil {
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
			return fmt.Errorf("mount point %s is already in use", settings.MountPoint)
		}
		if err := passfs.UnmountPath(settings.MountPoint); err != nil {
			return fmt.Errorf("remove unavailable passfs mount: %w", err)
		}
		if err := waitForMountState(settings.MountPoint, false, serviceWaitTimeout); err != nil {
			return err
		}
	}
	if entries, err := os.ReadDir(settings.MountPoint); err != nil {
		return err
	} else if len(entries) != 0 {
		return fmt.Errorf("mount point %s is not empty", settings.MountPoint)
	}

	prompter, err := newServicePrompter(settings)
	if err != nil {
		return err
	}
	serviceContext, cancelService := context.WithCancel(context.Background())
	defer cancelService()
	prompter = passfs.WithCancellation(prompter, serviceContext)
	unlockFor, err := settings.UnlockDuration()
	if err != nil {
		return err
	}
	volume, err := passfs.LoadVolume(settings.Vault, prompter, maxFileSize, unlockFor)
	if err != nil {
		return err
	}

	zero := time.Duration(0)
	logger := log.New(stderr, "", log.LstdFlags)
	server, err := fs.Mount(settings.MountPoint, passfs.NewRootNode(volume), &fs.Options{
		AttrTimeout:     &zero,
		EntryTimeout:    &zero,
		NegativeTimeout: &zero,
		UID:             uint32(os.Getuid()),
		GID:             uint32(os.Getgid()),
		MountOptions: fuse.MountOptions{
			Options:            passfs.PlatformMountOptions(),
			FsName:             "passfs",
			Name:               "passfs",
			DisableReadDirPlus: true,
			Debug:              debug,
			Logger:             logger,
		},
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("mount passfs at %s: %w", settings.MountPoint, err)
	}

	go passfs.RunLinkSynchronizer(
		serviceContext,
		volume,
		settings.MountPoint,
		logger,
	)
	startUpdateMonitor(serviceContext, logger)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		<-signals
		cancelService()
		if err := server.Unmount(); err != nil {
			logger.Printf("unmount: %v", err)
		}
	}()

	server.Wait()
	volume.Lock()
	return nil
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
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	flags.StringVar(&unlockFor, "unlock-for", "", "set per-file authorization duration")
	flags.StringVar(&mountPoint, "mount-point", "", "set the global mount point")
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
		"Config:      %s\nVault:       %s\nMount point: %s\nUnlock for:  %s\n",
		settings.Path(),
		settings.Vault,
		settings.MountPoint,
		duration,
	)
	if changed {
		printReloadNotice(stdout)
	}
	return nil
}

func printReloadNotice(writer io.Writer) {
	fmt.Fprintln(writer, "Restart passfs to apply the change:")
	fmt.Fprintln(writer, "  passfs reload")
}

func loadSettings(path string) (*passfs.Settings, error) {
	settings, err := passfs.LoadSettings(path)
	if err != nil {
		return nil, fmt.Errorf("%w; run \"passfs init\" first", err)
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
		return fmt.Errorf("%s is mounted by another filesystem", mountPoint)
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
			return fmt.Errorf("%s was mounted by another filesystem", mountPoint)
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
