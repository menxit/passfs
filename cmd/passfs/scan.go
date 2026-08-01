package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"unicode"

	"passfs/internal/passfs"
)

const scanContentLimit = 1024 * 1024

type scanRoot struct {
	path     string
	maxDepth int
	explicit bool
}

type scanDirectory struct {
	path     string
	depth    int
	maxDepth int
}

type secretScanner struct {
	excludedRoots       []string
	tracked             map[string]struct{}
	trackedRepositories map[string]struct{}
	trackedMu           sync.RWMutex
	ignored             map[string]struct{}
}

var assignmentPattern = regexp.MustCompile(
	`^\s*(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9_. -]+))\s*(?:=|:|\s)\s*(.+?)\s*$`,
)

var jsonAssignmentPattern = regexp.MustCompile(
	`"([^"]+)"\s*:\s*"((?:\\.|[^"\\])*)"`,
)

func runScan(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: passfs scan [options] [PATH...]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Find likely plaintext secret files without printing their contents.")
		fmt.Fprintln(stderr, "By default, scans the current project and common credential/config locations.")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Options:")
		flags.PrintDefaults()
	}
	var common commonFlags
	var all bool
	var jsonOutput bool
	var nullOutput bool
	var noInteractive bool
	if err := addCommonFlags(flags, &common); err != nil {
		return err
	}
	flags.BoolVar(
		&all,
		"all",
		false,
		"scan all relevant user-data roots instead of only likely locations",
	)
	flags.BoolVar(&jsonOutput, "json", false, "write the result as a JSON array")
	flags.BoolVar(&nullOutput, "0", false, "separate paths with NUL bytes")
	flags.BoolVar(
		&noInteractive,
		"no-interactive",
		false,
		"print paths without offering actions",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if jsonOutput && nullOutput {
		return errors.New("--json and -0 cannot be used together")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("find current directory: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("find home directory: %w", err)
	}
	tracked, repositoryRoot := currentGitTrackedFiles(cwd)
	if repositoryRoot != "" {
		cwd = repositoryRoot
	} else if cwd == string(os.PathSeparator) ||
		platformExcludedScanDirectory(cwd) {
		cwd = home
	}
	roots, err := buildScanRoots(flags.Args(), home, cwd, all)
	if err != nil {
		return err
	}
	scanner := secretScanner{
		tracked:             tracked,
		trackedRepositories: make(map[string]struct{}),
	}
	if repositoryRoot != "" {
		scanner.trackedRepositories[filepath.Clean(repositoryRoot)] =
			struct{}{}
	}
	scanner.ignored, err = loadScanIgnoredPaths(common.configPath)
	if err != nil {
		return err
	}
	if settings, err := passfs.LoadSettings(common.configPath); err == nil {
		scanner.excludedRoots = append(
			scanner.excludedRoots,
			settings.Vault,
			settings.MountPoint,
		)
	}
	findings, err := scanner.scan(roots)
	if err != nil {
		return err
	}
	if !jsonOutput && !nullOutput && !noInteractive &&
		scanHasInteractiveTerminal(stdout) {
		return runInteractiveScan(
			common.configPath,
			findings,
			stdout,
			stderr,
		)
	}

	switch {
	case jsonOutput:
		return writeJSON(stdout, findings)
	case nullOutput:
		for _, path := range findings {
			if _, err := io.WriteString(stdout, path+"\x00"); err != nil {
				return err
			}
		}
	default:
		for _, path := range findings {
			fmt.Fprintln(stdout, terminalPath(path))
		}
	}
	return nil
}

func buildScanRoots(
	arguments []string,
	home string,
	cwd string,
	all bool,
) ([]scanRoot, error) {
	if len(arguments) != 0 {
		roots := make([]scanRoot, 0, len(arguments))
		for _, argument := range arguments {
			absolute, err := filepath.Abs(argument)
			if err != nil {
				return nil, err
			}
			if _, err := os.Lstat(absolute); err != nil {
				return nil, fmt.Errorf("scan %s: %w", terminalPath(absolute), err)
			}
			roots = append(roots, scanRoot{
				path:     filepath.Clean(absolute),
				maxDepth: -1,
				explicit: true,
			})
		}
		return uniqueScanRoots(roots), nil
	}
	return uniqueScanRoots(platformScanRoots(home, cwd, all)), nil
}

func uniqueScanRoots(roots []scanRoot) []scanRoot {
	result := make([]scanRoot, 0, len(roots))
	for _, root := range roots {
		root.path = filepath.Clean(root.path)
		if _, err := os.Lstat(root.path); err != nil {
			continue
		}
		skip := false
		for _, existing := range result {
			if root.path == existing.path ||
				(!root.explicit && !existing.explicit &&
					(existing.maxDepth < 0 &&
						pathWithinLexically(existing.path, root.path))) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if root.maxDepth < 0 && !root.explicit {
			filtered := result[:0]
			for _, existing := range result {
				if !existing.explicit &&
					pathWithinLexically(root.path, existing.path) {
					continue
				}
				filtered = append(filtered, existing)
			}
			result = filtered
		}
		result = append(result, root)
	}
	return result
}

func (scanner *secretScanner) scan(roots []scanRoot) ([]string, error) {
	for _, root := range roots {
		if root.explicit {
			scanner.loadTrackedFilesForPath(root.path)
		}
	}
	fileJobs := make(chan string, 256)
	findings := make(map[string]struct{})
	var findingsMu sync.Mutex
	cpuCount := runtime.NumCPU()
	directoryWorkers := platformScanDirectoryWorkers(cpuCount)
	fileWorkers := platformScanFileWorkers(cpuCount)
	if os.Getenv("PASSFS_LOW_POWER_MODE") == "1" {
		// Keep enough concurrency to overlap metadata and file reads without
		// fanning a background UI refresh across every performance core.
		directoryWorkers = 2
		fileWorkers = 2
	}
	var filesWG sync.WaitGroup
	for range fileWorkers {
		filesWG.Add(1)
		go func() {
			defer filesWG.Done()
			for path := range fileJobs {
				found, err := fileContainsLikelySecret(path)
				if err != nil || !found {
					continue
				}
				findingsMu.Lock()
				findings[path] = struct{}{}
				findingsMu.Unlock()
			}
		}()
	}

	directories := make([]scanDirectory, 0, len(roots))
	for _, root := range roots {
		info, err := os.Lstat(root.path)
		if err != nil {
			if root.explicit {
				close(fileJobs)
				filesWG.Wait()
				return nil, fmt.Errorf("scan %s: %w", terminalPath(root.path), err)
			}
			continue
		}
		if info.Mode().IsRegular() {
			if !scanner.skipFile(root.path) {
				fileJobs <- root.path
			}
			continue
		}
		if !info.IsDir() {
			continue
		}
		if excludedScanDirectory(root.path, filepath.Base(root.path)) {
			continue
		}
		directories = append(directories, scanDirectory{
			path:     root.path,
			maxDepth: root.maxDepth,
		})
	}
	scanner.walkDirectories(directories, fileJobs, directoryWorkers)
	close(fileJobs)
	filesWG.Wait()

	return sortedPathSet(findings), nil
}

func (scanner *secretScanner) walkDirectories(
	initial []scanDirectory,
	fileJobs chan<- string,
	workerCount int,
) {
	if len(initial) == 0 {
		return
	}
	queue := append([]scanDirectory(nil), initial...)
	pending := len(queue)
	var mutex sync.Mutex
	condition := sync.NewCond(&mutex)
	var workersWG sync.WaitGroup

	for range workerCount {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			for {
				mutex.Lock()
				for len(queue) == 0 && pending != 0 {
					condition.Wait()
				}
				if pending == 0 {
					mutex.Unlock()
					return
				}
				last := len(queue) - 1
				directory := queue[last]
				queue = queue[:last]
				mutex.Unlock()

				children := scanner.readDirectory(directory, fileJobs)

				mutex.Lock()
				queue = append(queue, children...)
				pending += len(children) - 1
				condition.Broadcast()
				mutex.Unlock()
			}
		}()
	}
	workersWG.Wait()
}

func (scanner *secretScanner) readDirectory(
	directory scanDirectory,
	fileJobs chan<- string,
) []scanDirectory {
	if _, err := os.Lstat(filepath.Join(directory.path, ".git")); err == nil {
		scanner.loadTrackedFilesForRepository(directory.path)
	}
	handle, err := os.Open(directory.path)
	if err != nil {
		return nil
	}
	defer handle.Close()

	var children []scanDirectory
	for {
		entries, err := handle.ReadDir(256)
		for _, entry := range entries {
			path := filepath.Join(directory.path, entry.Name())
			entryType := entry.Type()
			if entryType&os.ModeSymlink != 0 {
				continue
			}
			if entry.IsDir() {
				nextDepth := directory.depth + 1
				if directory.maxDepth >= 0 && nextDepth > directory.maxDepth {
					continue
				}
				if excludedScanDirectory(path, entry.Name()) ||
					scanner.insideExcludedRoot(path) {
					continue
				}
				if strings.EqualFold(entry.Name(), "env") {
					if _, err := os.Stat(filepath.Join(path, "pyvenv.cfg")); err == nil {
						continue
					}
				}
				children = append(children, scanDirectory{
					path:     path,
					depth:    nextDepth,
					maxDepth: directory.maxDepth,
				})
				continue
			}
			if !entryType.IsRegular() && entryType != 0 {
				continue
			}
			if !isSecretFileCandidate(path) || scanner.skipFile(path) {
				continue
			}
			fileJobs <- path
		}
		if err != nil {
			return children
		}
	}
}

func (scanner *secretScanner) skipFile(path string) bool {
	clean := filepath.Clean(path)
	scanner.trackedMu.RLock()
	if _, ok := scanner.tracked[clean]; ok {
		scanner.trackedMu.RUnlock()
		return true
	}
	scanner.trackedMu.RUnlock()
	if _, ok := scanner.ignored[clean]; ok {
		return true
	}
	return scanner.insideExcludedRoot(clean)
}

func (scanner *secretScanner) insideExcludedRoot(path string) bool {
	for _, root := range scanner.excludedRoots {
		if pathWithinLexically(root, path) {
			return true
		}
	}
	return false
}

func (scanner *secretScanner) loadTrackedFilesForPath(path string) {
	info, err := os.Lstat(path)
	if err == nil && !info.IsDir() {
		path = filepath.Dir(path)
	}
	root := gitRepositoryRoot(path)
	if root == "" {
		return
	}
	scanner.loadTrackedFilesForRepository(root)
}

func (scanner *secretScanner) loadTrackedFilesForRepository(root string) {
	root = filepath.Clean(root)
	scanner.trackedMu.Lock()
	if scanner.trackedRepositories == nil {
		scanner.trackedRepositories = make(map[string]struct{})
	}
	if _, loaded := scanner.trackedRepositories[root]; loaded {
		scanner.trackedMu.Unlock()
		return
	}
	scanner.trackedRepositories[root] = struct{}{}
	scanner.trackedMu.Unlock()

	paths := gitTrackedFilePaths(root)
	scanner.trackedMu.Lock()
	if scanner.tracked == nil {
		scanner.tracked = make(map[string]struct{}, len(paths))
	}
	for _, path := range paths {
		scanner.tracked[path] = struct{}{}
	}
	scanner.trackedMu.Unlock()
}

func pathWithinLexically(root string, path string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func currentGitTrackedFiles(cwd string) (map[string]struct{}, string) {
	result := make(map[string]struct{})
	root := gitRepositoryRoot(cwd)
	if root == "" {
		return result, ""
	}
	for _, path := range gitTrackedFilePaths(root) {
		result[path] = struct{}{}
	}
	return result, root
}

func gitRepositoryRoot(path string) string {
	output, err := exec.Command(
		"git", "-C", path, "rev-parse", "--show-toplevel",
	).Output()
	if err != nil {
		return ""
	}
	return filepath.Clean(strings.TrimSpace(string(output)))
}

func gitTrackedFilePaths(root string) []string {
	output, err := exec.Command(
		"git", "-C", root, "ls-files", "-z", "--cached",
	).Output()
	if err != nil {
		return nil
	}
	paths := make([]string, 0)
	for _, relative := range bytes.Split(output, []byte{0}) {
		if len(relative) == 0 {
			continue
		}
		paths = append(
			paths,
			filepath.Clean(filepath.Join(root, string(relative))),
		)
	}
	return paths
}

func excludedScanDirectory(path string, name string) bool {
	lowerName := strings.ToLower(name)
	if _, excluded := commonExcludedScanDirectories[lowerName]; excluded {
		return true
	}
	lowerPath := strings.ToLower(filepath.ToSlash(path))
	for _, fragment := range []string{
		"/.cargo/registry",
		"/.cargo/git",
		"/go/pkg/mod",
		"/go/pkg/sumdb",
		"/.local/share/virtualenvs",
	} {
		if strings.Contains(lowerPath, fragment) {
			return true
		}
	}
	if strings.HasSuffix(lowerName, ".app") ||
		strings.HasSuffix(lowerName, ".framework") ||
		strings.HasSuffix(lowerName, ".dSYM") ||
		strings.HasSuffix(lowerName, ".xcarchive") {
		return true
	}
	return platformExcludedScanDirectory(filepath.Clean(path))
}

var commonExcludedScanDirectories = map[string]struct{}{
	".bzr":              {},
	".bundle":           {},
	".cache":            {},
	".dart_tool":        {},
	".git":              {},
	".gradle":           {},
	".hg":               {},
	".idea":             {},
	".ivy2":             {},
	".m2":               {},
	".next":             {},
	".nuget":            {},
	".parcel-cache":     {},
	".pnpm-store":       {},
	".svn":              {},
	".svelte-kit":       {},
	".terraform":        {},
	".terragrunt-cache": {},
	".turbo":            {},
	".venv":             {},
	".yarn":             {},
	"__pycache__":       {},
	"__tests__":         {},
	"_build":            {},
	"bower_components":  {},
	"build":             {},
	"carthage":          {},
	"cmakefiles":        {},
	"coverage":          {},
	"deriveddata":       {},
	"dist":              {},
	"example":           {},
	"examples":          {},
	"fixture":           {},
	"fixtures":          {},
	"generated":         {},
	"jspm_packages":     {},
	"node_modules":      {},
	"obj":               {},
	"pods":              {},
	"sample":            {},
	"samples":           {},
	"site-packages":     {},
	"target":            {},
	"test":              {},
	"testdata":          {},
	"tests":             {},
	"third_party":       {},
	"third-party":       {},
	"vendor":            {},
	"vendors":           {},
	"venv":              {},
	"virtualenv":        {},
}

func isSecretFileCandidate(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	if isIgnoredSecretExample(name) {
		return false
	}
	if name == ".env" || strings.HasPrefix(name, ".env.") {
		return true
	}
	if _, ok := exactSecretFileNames[name]; ok {
		return true
	}
	extension := strings.ToLower(filepath.Ext(name))
	if _, ok := privateKeyExtensions[extension]; ok {
		return true
	}
	if strings.Contains(name, "secret") ||
		strings.Contains(name, "credential") ||
		strings.Contains(name, "access-token") ||
		strings.Contains(name, "access_token") ||
		strings.Contains(name, "service-account") ||
		strings.Contains(name, "service_account") {
		return isConfigExtension(extension)
	}
	parent := strings.ToLower(filepath.Base(filepath.Dir(path)))
	if parent == ".config" || parent == "config" || parent == "configs" {
		return isConfigExtension(extension)
	}
	return knownCredentialPath(path)
}

func isIgnoredSecretExample(name string) bool {
	for _, marker := range []string{
		".example", ".sample", ".template", ".dist", ".default",
		".defaults", ".skeleton", ".stub",
	} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

var exactSecretFileNames = map[string]struct{}{
	".envrc":                               {},
	".netrc":                               {},
	".npmrc":                               {},
	".pypirc":                              {},
	".terraformrc":                         {},
	"accesskeys.csv":                       {},
	"application_default_credentials.json": {},
	"auth.json":                            {},
	"config.json":                          {},
	"credentials":                          {},
	"credentials.json":                     {},
	"credentials.tfrc.json":                {},
	"dockerconfigjson":                     {},
	"id_dsa":                               {},
	"id_ecdsa":                             {},
	"id_ed25519":                           {},
	"id_rsa":                               {},
	"rclone.conf":                          {},
	"secrets":                              {},
}

var privateKeyExtensions = map[string]struct{}{
	".jks":      {},
	".key":      {},
	".keystore": {},
	".p12":      {},
	".pem":      {},
	".pfx":      {},
}

func isConfigExtension(extension string) bool {
	switch extension {
	case "", ".cfg", ".conf", ".config", ".env", ".ini", ".json",
		".properties", ".toml", ".xml", ".yaml", ".yml":
		return true
	default:
		return false
	}
}

func knownCredentialPath(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, suffix := range []string{
		"/.aws/config",
		"/.aws/credentials",
		"/.azure/accesstokens.json",
		"/.azure/azureprofile.json",
		"/.config/gcloud/credentials.db",
		"/.config/gh/hosts.yml",
		"/.config/glab-cli/config.yml",
		"/.docker/config.json",
		"/.gem/credentials",
		"/.kube/config",
	} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func fileContainsLikelySecret(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return false, err
	}
	if info.Size() > scanContentLimit {
		return highConfidenceBinarySecret(path), nil
	}
	if highConfidenceBinarySecret(path) {
		return true, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, scanContentLimit+1))
	if err != nil {
		return false, err
	}
	if len(data) > scanContentLimit || bytes.IndexByte(data, 0) >= 0 {
		return false, nil
	}
	lower := bytes.ToLower(data)
	if bytes.Contains(lower, []byte("age-encryption.org/v1")) {
		return false, nil
	}
	if contentContainsSecretToken(data, lower) {
		return true, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if likelySecretAssignment(line) {
			return true, nil
		}
	}
	return false, nil
}

func highConfidenceBinarySecret(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	switch filepath.Ext(name) {
	case ".jks", ".keystore", ".p12", ".pfx":
		return true
	}
	return knownCredentialPath(path) && name == "credentials.db"
}

func likelySecretAssignment(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, ";") {
		return false
	}
	for _, match := range jsonAssignmentPattern.FindAllStringSubmatch(line, -1) {
		if isSensitiveKey(normalizeSecretKey(match[1])) &&
			!isPlaceholderSecret(match[2]) {
			return true
		}
	}
	lowerLine := strings.ToLower(line)
	for _, marker := range []string{"_authtoken=", "_auth="} {
		if index := strings.Index(lowerLine, marker); index >= 0 {
			return !isPlaceholderSecret(line[index+len(marker):])
		}
	}
	if strings.HasPrefix(line, "//") &&
		!strings.Contains(lowerLine, "_authtoken") {
		return false
	}
	match := assignmentPattern.FindStringSubmatch(line)
	if match == nil {
		return false
	}
	key := match[1]
	if key == "" {
		key = match[2]
	}
	if key == "" {
		key = match[3]
	}
	value := strings.TrimSpace(match[4])
	key = normalizeSecretKey(key)
	if !isSensitiveKey(key) || isPlaceholderSecret(value) {
		return false
	}
	return true
}

func normalizeSecretKey(key string) string {
	var result strings.Builder
	for _, character := range strings.ToLower(strings.TrimSpace(key)) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			result.WriteRune(character)
		}
	}
	return result.String()
}

func isSensitiveKey(key string) bool {
	if key == "" {
		return false
	}
	for _, excluded := range []string{
		"passwordfile", "passwordpath", "secretfile", "secretpath",
		"tokenfile", "tokenpath", "keyfile", "keypath", "secretname",
		"passwordcommand",
	} {
		if key == excluded {
			return false
		}
	}
	for _, sensitive := range []string{
		"password", "passwd", "apikey", "clientsecret", "consumersecret",
		"accesskeyid", "secretaccesskey", "accesstoken", "refreshtoken",
		"authtoken", "bearertoken", "privatekey", "connectionstring",
		"sastoken", "dockerauth",
	} {
		if key == sensitive || strings.HasSuffix(key, sensitive) {
			return true
		}
	}
	return false
}

// Unresolved substitution and template forms, adapted from the gitleaks
// global allowlist (https://github.com/gitleaks/gitleaks, MIT License).
var placeholderValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\$(?:\d+|\{\d+\})$`),
	regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`),
	regexp.MustCompile(`^\{\{[ \t]*[\w ().|]+[ \t]*\}\}$`),
	regexp.MustCompile(`^%[A-Za-z_][A-Za-z0-9_]*%$`),
	regexp.MustCompile(`^@[A-Za-z_][A-Za-z0-9_]*@$`),
	regexp.MustCompile(`^%[+\-# 0]?[bcdeEfFgGoOpqstTUvxX]$`),
	regexp.MustCompile(`^<[^<>]+>$`),
}

func isPlaceholderSecret(value string) bool {
	value = strings.TrimSpace(strings.TrimRight(value, ","))
	value = strings.Trim(value, `"'`)
	if value == "" || len(value) < 4 {
		return true
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(value, "${") || strings.HasPrefix(value, "$(") ||
		strings.HasPrefix(lower, "process.env") ||
		strings.HasPrefix(lower, "os.environ") {
		return true
	}
	for _, pattern := range placeholderValuePatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	for _, placeholder := range []string{
		"changeme", "change-me", "example", "placeholder", "redacted",
		"replace_me", "replace-me", "your_", "your-", "<secret>",
		"<password>", "null", "none", "true", "false",
	} {
		if lower == placeholder || strings.HasPrefix(lower, placeholder) {
			return true
		}
	}
	allFiller := true
	for _, character := range lower {
		if !strings.ContainsRune("x*-_ ", character) {
			allFiller = false
			break
		}
	}
	return allFiller
}
