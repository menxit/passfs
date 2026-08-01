package passfs

import (
	"path/filepath"
	"sort"
)

type ProtectedFile struct {
	Path             string `json:"path"`
	Size             uint64 `json:"size"`
	ModifiedUnixNano int64  `json:"modifiedUnixNano"`
	AccessedUnixNano int64  `json:"accessedUnixNano"`
}

// ProtectedFiles returns a stable snapshot of active project-side protected
// links. It inspects only the symbolic link itself, never its plaintext mount
// target, and therefore never triggers authorization. Ciphertext whose link
// was removed remains recoverable in the vault but is not reported as active.
func ProtectedFiles(vault string) ([]ProtectedFile, error) {
	var result []ProtectedFile
	err := withMetadataFileLock(vault, func() error {
		metadata, err := readMetadata(vault)
		if err != nil {
			return err
		}
		result = make([]ProtectedFile, 0, len(metadata.Files))
		for key, file := range metadata.Files {
			path, registered := metadata.Links[key]
			if !registered || path == "" || metadata.Orphaned[key] != 0 ||
				metadata.Recovery[key].State != "" {
				continue
			}
			link, err := inspectProtectedLink(path)
			if err != nil {
				return err
			}
			if !link.isSymlink || !targetMatchesStorage(
				link.target,
				filepath.FromSlash(key),
			) {
				continue
			}
			result = append(result, ProtectedFile{
				Path:             path,
				Size:             file.Size,
				ModifiedUnixNano: file.MTime,
				AccessedUnixNano: file.ATime,
			})
		}
		return nil
	})
	sort.Slice(result, func(left int, right int) bool {
		return result[left].Path < result[right].Path
	})
	return result, err
}
