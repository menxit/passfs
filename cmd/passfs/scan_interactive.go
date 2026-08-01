package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/term"
)

const interactiveScanPreviewLimit = 16 * 1024

type scanDisplayFile struct {
	index      int
	path       string
	title      string
	size       int64
	lastOpened time.Time
	preview    string
}

type scanDisplayGroup struct {
	project    string
	files      []scanDisplayFile
	lastOpened time.Time
}

func scanHasInteractiveTerminal(stdout io.Writer) bool {
	output, ok := stdout.(*os.File)
	return ok &&
		term.IsTerminal(int(output.Fd())) &&
		term.IsTerminal(int(os.Stdin.Fd()))
}

func runInteractiveScan(
	configPath string,
	findings []string,
	stdout io.Writer,
	stderr io.Writer,
) error {
	if len(findings) == 0 {
		fmt.Fprintln(stdout, "PassFS found no unprotected secret files.")
		return nil
	}
	groups := buildScanDisplayGroups(findings)
	fmt.Fprintf(
		stdout,
		"\n\033[1mPassFS found %d unprotected secret file%s\033[0m\n",
		len(findings),
		pluralSuffix(len(findings)),
	)
	fmt.Fprintln(
		stdout,
		"Values remain masked. Results are grouped by repository.",
	)
	fmt.Fprintln(stdout)
	orderedPaths := make([]string, 0, len(findings))
	nextIndex := 1
	for groupIndex := range groups {
		for fileIndex := range groups[groupIndex].files {
			groups[groupIndex].files[fileIndex].index = nextIndex
			orderedPaths = append(
				orderedPaths,
				groups[groupIndex].files[fileIndex].path,
			)
			nextIndex++
		}
	}
	for _, group := range groups {
		fmt.Fprintf(
			stdout,
			"\033[1;36m%s\033[0m  \033[2m%d file%s\033[0m\n",
			group.project,
			len(group.files),
			pluralSuffix(len(group.files)),
		)
		for _, file := range group.files {
			fmt.Fprintf(
				stdout,
				"  \033[1;33m[%d]\033[0m \033[1m%s\033[0m\n",
				file.index,
				file.title,
			)
			fmt.Fprintf(
				stdout,
				"      %s · %s\n",
				formatScanFileSize(file.size),
				formatScanLastOpened(file.lastOpened),
			)
			fmt.Fprintf(stdout, "      \033[2m%s\033[0m\n", file.preview)
			fmt.Fprintf(stdout, "      \033[2m%s\033[0m\n", terminalPath(file.path))
		}
		fmt.Fprintln(stdout)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprint(
			stdout,
			"Select files to protect (for example 1 3-5 or all), "+
				"type \"ignore 2 4\", or press Enter to cancel:\n> ",
		)
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			fmt.Fprintln(stdout, "No files changed.")
			return nil
		}

		action := "protect"
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "ignore ") {
			action = "ignore"
			line = strings.TrimSpace(line[len("ignore "):])
		} else if strings.HasPrefix(lower, "protect ") {
			line = strings.TrimSpace(line[len("protect "):])
		}
		selected, selectionErr := parseScanSelection(line, len(findings))
		if selectionErr != nil {
			fmt.Fprintf(stdout, "Invalid selection: %v\n\n", selectionErr)
			if errors.Is(err, io.EOF) {
				return nil
			}
			continue
		}
		paths := make([]string, 0, len(selected))
		for _, index := range selected {
			paths = append(paths, orderedPaths[index])
		}

		if action == "ignore" {
			if err := updateScanIgnoredPaths(
				configPath,
				paths,
				false,
			); err != nil {
				return err
			}
			fmt.Fprintf(
				stdout,
				"Ignored %d file%s in future scans.\n",
				len(paths),
				pluralSuffix(len(paths)),
			)
			return nil
		}

		if err := runInit(
			[]string{"--config", configPath},
			stdout,
			stderr,
		); err != nil {
			return err
		}
		encryptArguments := []string{"--config", configPath, "--"}
		encryptArguments = append(encryptArguments, paths...)
		if err := runEncrypt(encryptArguments, stdout, stderr); err != nil {
			return err
		}
		fmt.Fprintf(
			stdout,
			"\nProtected %d file%s with PassFS.\n",
			len(paths),
			pluralSuffix(len(paths)),
		)
		return nil
	}
}

func buildScanDisplayGroups(paths []string) []scanDisplayGroup {
	groups := make(map[string][]scanDisplayFile)
	projectCache := make(map[string]string)
	for _, path := range paths {
		info, _ := os.Stat(path)
		var size int64
		var lastOpened time.Time
		if info != nil {
			size = info.Size()
			lastOpened = scanFileLastOpened(info)
		}
		project := scanProjectName(path, projectCache)
		groups[project] = append(groups[project], scanDisplayFile{
			path:       path,
			title:      filepath.Base(path),
			size:       size,
			lastOpened: lastOpened,
			preview:    maskedScanPreview(path),
		})
	}

	result := make([]scanDisplayGroup, 0, len(groups))
	for project, files := range groups {
		sort.Slice(files, func(first, second int) bool {
			return files[first].lastOpened.After(files[second].lastOpened)
		})
		var latest time.Time
		if len(files) != 0 {
			latest = files[0].lastOpened
		}
		result = append(result, scanDisplayGroup{
			project:    project,
			files:      files,
			lastOpened: latest,
		})
	}
	sort.Slice(result, func(first, second int) bool {
		if result[first].lastOpened.Equal(result[second].lastOpened) {
			return result[first].project < result[second].project
		}
		return result[first].lastOpened.After(result[second].lastOpened)
	})
	return result
}

func scanProjectName(path string, cache map[string]string) string {
	directory := filepath.Dir(path)
	for {
		if cached, ok := cache[directory]; ok {
			return cached
		}
		gitPath := filepath.Join(directory, ".git")
		if _, err := os.Lstat(gitPath); err == nil {
			name := scanRepositoryName(directory, gitPath)
			cache[directory] = name
			return name
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	home, _ := os.UserHomeDir()
	parent := filepath.Base(filepath.Dir(path))
	if home != "" && pathWithinLexically(home, path) &&
		strings.HasPrefix(parent, ".") {
		return "Personal credentials"
	}
	if parent == "" || parent == string(os.PathSeparator) {
		return "Personal files"
	}
	return parent
}

func scanRepositoryName(root string, gitPath string) string {
	configPath := filepath.Join(gitPath, "config")
	if info, err := os.Stat(gitPath); err == nil && !info.IsDir() {
		data, readErr := os.ReadFile(gitPath)
		if readErr == nil {
			line := strings.TrimSpace(string(data))
			if value, ok := strings.CutPrefix(line, "gitdir:"); ok {
				gitDirectory := strings.TrimSpace(value)
				if !filepath.IsAbs(gitDirectory) {
					gitDirectory = filepath.Join(root, gitDirectory)
				}
				configPath = filepath.Join(
					filepath.Clean(gitDirectory),
					"config",
				)
			}
		}
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return filepath.Base(root)
	}
	inOrigin := false
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "[") {
			inOrigin = line == `[remote "origin"]`
			continue
		}
		if !inOrigin {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "url" {
			continue
		}
		remote := strings.TrimSpace(value)
		remote = strings.ReplaceAll(remote, "\\", "/")
		fields := strings.FieldsFunc(
			remote,
			func(character rune) bool {
				return character == '/' || character == ':'
			},
		)
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimSuffix(fields[len(fields)-1], ".git")
		if name != "" {
			return name
		}
	}
	return filepath.Base(root)
}

func maskedScanPreview(path string) string {
	if highConfidenceBinarySecret(path) {
		return "Binary credential"
	}
	file, err := os.Open(path)
	if err != nil {
		return "Secret-bearing file"
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, interactiveScanPreviewLimit))
	if err != nil || bytes.IndexByte(data, 0) >= 0 {
		return "Secret-bearing file"
	}
	text := string(data)
	if strings.Contains(text, "PRIVATE KEY-----") {
		return "Private key material"
	}
	var keys []string
	seen := make(map[string]struct{})
	addKey := func(key string) {
		key = strings.TrimSpace(strings.Trim(key, `"'`))
		if key == "" || len(key) > 64 {
			return
		}
		for _, character := range key {
			if unicode.IsControl(character) {
				return
			}
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		keys = append(keys, key+"=••••••")
	}
	for _, line := range strings.Split(text, "\n") {
		for _, match := range jsonAssignmentPattern.FindAllStringSubmatch(
			line,
			-1,
		) {
			if isSensitiveKey(normalizeSecretKey(match[1])) {
				addKey(match[1])
			}
		}
		match := assignmentPattern.FindStringSubmatch(line)
		if match != nil {
			key := match[1]
			if key == "" {
				key = match[2]
			}
			if key == "" {
				key = match[3]
			}
			if isSensitiveKey(normalizeSecretKey(key)) {
				addKey(key)
			}
		}
		if len(keys) >= 2 {
			break
		}
	}
	if len(keys) == 0 {
		return "Secret token detected"
	}
	return strings.Join(keys, "  ")
}

func parseScanSelection(value string, count int) ([]int, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "all" {
		result := make([]int, count)
		for index := range count {
			result[index] = index
		}
		return result, nil
	}
	value = strings.ReplaceAll(value, ",", " ")
	selected := make(map[int]struct{})
	for _, field := range strings.Fields(value) {
		firstText := field
		lastText := field
		if first, last, ok := strings.Cut(field, "-"); ok {
			firstText = first
			lastText = last
		}
		first, err := strconv.Atoi(firstText)
		if err != nil {
			return nil, fmt.Errorf("%q is not a file number", field)
		}
		last, err := strconv.Atoi(lastText)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid range", field)
		}
		if first < 1 || last < first || last > count {
			return nil, fmt.Errorf("%q is outside 1-%d", field, count)
		}
		for number := first; number <= last; number++ {
			selected[number-1] = struct{}{}
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("select at least one file")
	}
	result := make([]int, 0, len(selected))
	for index := range selected {
		result = append(result, index)
	}
	sort.Ints(result)
	return result, nil
}

func formatScanFileSize(size int64) string {
	const unit = int64(1024)
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	value := float64(size)
	for _, suffix := range []string{"KB", "MB", "GB", "TB"} {
		value /= float64(unit)
		if value < float64(unit) || suffix == "TB" {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%d B", size)
}

func formatScanLastOpened(value time.Time) string {
	if value.IsZero() {
		return "last opened unknown"
	}
	elapsed := time.Since(value)
	switch {
	case elapsed < 0:
		return "opened just now"
	case elapsed < time.Minute:
		return "opened just now"
	case elapsed < time.Hour:
		return fmt.Sprintf("opened %dm ago", int(elapsed/time.Minute))
	case elapsed < 24*time.Hour:
		return fmt.Sprintf("opened %dh ago", int(elapsed/time.Hour))
	case elapsed < 30*24*time.Hour:
		return fmt.Sprintf("opened %dd ago", int(elapsed/(24*time.Hour)))
	default:
		return "opened " + value.Format("2006-01-02")
	}
}

func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}
