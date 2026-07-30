//go:build darwin

package main

import (
	"path/filepath"
	"strings"
)

func platformScanRoots(home string, cwd string, all bool) []scanRoot {
	if all {
		roots := userDirectoriesUnder("/Users")
		if !pathCoveredByRoots(cwd, roots) {
			roots = append(roots, scanRoot{path: cwd, maxDepth: -1})
		}
		return roots
	}
	return commonLikelyScanRoots(home, cwd, []string{
		filepath.Join(home, "Library", "Application Support", "Google", "Cloud SDK"),
	})
}

func platformExcludedScanDirectory(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, fragment := range []string{
		"/library/caches",
		"/library/developer",
		"/library/logs",
		"/library/mail",
		"/library/metadata",
		"/library/safari",
		"/library/saved application state",
		"/library/containers",
		"/library/group containers",
		"/photos library.photoslibrary",
		"/.trash",
	} {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return lower == "/system" ||
		strings.HasPrefix(lower, "/system/") ||
		lower == "/applications" ||
		strings.HasPrefix(lower, "/applications/") ||
		lower == "/library" ||
		strings.HasPrefix(lower, "/library/") ||
		lower == "/usr" ||
		strings.HasPrefix(lower, "/usr/") ||
		lower == "/private/var" ||
		strings.HasPrefix(lower, "/private/var/")
}

func platformScanDirectoryWorkers(cpu int) int {
	return boundedWorkers(cpu, 4, 12)
}

func platformScanFileWorkers(cpu int) int {
	return boundedWorkers(cpu*2, 4, 24)
}
