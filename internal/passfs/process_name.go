package passfs

import (
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

func processDisplayName(pid uint32) string {
	name := sanitizeProcessName(platformProcessName(pid))
	if name != "" {
		return name
	}
	return "process " + strconv.FormatUint(uint64(pid), 10)
}

func processIsOrDescendsFrom(pid, ancestor uint32) bool {
	if pid == 0 || ancestor == 0 {
		return false
	}
	visited := make(map[uint32]struct{})
	for depth := 0; pid != 0 && depth < 64; depth++ {
		if pid == ancestor {
			return true
		}
		if _, exists := visited[pid]; exists {
			return false
		}
		visited[pid] = struct{}{}
		parent := platformParentProcessID(pid)
		if parent == pid {
			return false
		}
		pid = parent
	}
	return false
}

func sanitizeProcessName(name string) string {
	name = strings.TrimSpace(name)
	for _, component := range strings.Split(filepath.ToSlash(name), "/") {
		if strings.HasSuffix(strings.ToLower(component), ".app") {
			name = strings.TrimSuffix(component, filepath.Ext(component))
		}
	}
	name = filepath.Base(name)
	var clean strings.Builder
	for _, character := range name {
		if unicode.IsPrint(character) && !unicode.IsControl(character) {
			clean.WriteRune(character)
		}
		if clean.Len() >= 64 {
			break
		}
	}
	return strings.TrimSpace(clean.String())
}
