package main

import (
	"os"
	"path/filepath"
	"sort"
)

func commonLikelyScanRoots(
	home string,
	cwd string,
	platformSpecific []string,
) []scanRoot {
	roots := []scanRoot{
		{path: cwd, maxDepth: -1},
		{path: home, maxDepth: 1},
	}
	for _, relative := range []string{
		".aws",
		".azure",
		".cargo",
		".config",
		".docker",
		".gem",
		".gnupg",
		".kube",
		".local/share",
		".ssh",
		"Code",
		"code",
		"Developer",
		"Development",
		"Projects",
		"projects",
		"Repositories",
		"repos",
		"Sources",
		"src",
		"Workspace",
		"workspace",
		"work",
	} {
		roots = append(roots, scanRoot{
			path:     filepath.Join(home, filepath.FromSlash(relative)),
			maxDepth: -1,
		})
	}
	for _, path := range platformSpecific {
		roots = append(roots, scanRoot{path: path, maxDepth: -1})
	}
	return roots
}

func userDirectoriesUnder(parent string) []scanRoot {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil
	}
	var roots []scanRoot
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != "lost+found" {
			roots = append(roots, scanRoot{
				path:     filepath.Join(parent, entry.Name()),
				maxDepth: -1,
			})
		}
	}
	return roots
}

func pathCoveredByRoots(path string, roots []scanRoot) bool {
	for _, root := range roots {
		if pathWithinLexically(root.path, path) {
			return true
		}
	}
	return false
}

func boundedWorkers(value int, minimum int, maximum int) int {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func sortedPathSet(paths map[string]struct{}) []string {
	sorted := make([]string, 0, len(paths))
	for path := range paths {
		sorted = append(sorted, path)
	}
	sort.Strings(sorted)
	return sorted
}
