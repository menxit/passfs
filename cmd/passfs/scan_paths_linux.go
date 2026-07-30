//go:build linux

package main

import (
	"path/filepath"
	"strings"
)

func platformScanRoots(home string, cwd string, all bool) []scanRoot {
	if all {
		roots := userDirectoriesUnder("/home")
		if home == "/root" {
			roots = append(roots, scanRoot{path: home, maxDepth: -1})
		}
		if !pathCoveredByRoots(cwd, roots) {
			roots = append(roots, scanRoot{path: cwd, maxDepth: -1})
		}
		return roots
	}
	return commonLikelyScanRoots(home, cwd, nil)
}

func platformExcludedScanDirectory(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, fragment := range []string{
		"/.local/share/trash",
		"/.var/app",
		"/snap/",
	} {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	for _, root := range []string{
		"/boot", "/dev", "/proc", "/run", "/sys", "/usr",
		"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/lost+found",
	} {
		if lower == root || strings.HasPrefix(lower, root+"/") {
			return true
		}
	}
	return false
}

func platformScanDirectoryWorkers(cpu int) int {
	return boundedWorkers(cpu*2, 4, 24)
}

func platformScanFileWorkers(cpu int) int {
	return boundedWorkers(cpu*2, 4, 32)
}
