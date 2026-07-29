//go:build linux

package passfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const maxTerminalPassphraseBytes = 4096

func openProcessTerminal(pid uint32) (*os.File, string, error) {
	if pid == 0 {
		return nil, "", errors.New("requesting process is unavailable")
	}
	visited := make(map[uint32]struct{})
	current := pid
	for depth := 0; current != 0 && depth < 32; depth++ {
		if _, exists := visited[current]; exists {
			break
		}
		visited[current] = struct{}{}
		if processOwnedByCurrentUser(current) {
			for _, descriptor := range []string{"0", "2", "1"} {
				target, err := os.Readlink(
					filepath.Join("/proc", strconv.FormatUint(uint64(current), 10), "fd", descriptor),
				)
				if err != nil || !isAllowedTerminalPath(target) {
					continue
				}
				file, err := openTerminalPath(target)
				if err == nil {
					return file, target, nil
				}
			}
		}
		parent, err := linuxParentPID(current)
		if err != nil {
			break
		}
		current = parent
	}
	return nil, "", errors.New("no usable TTY found in the process ancestry")
}

func processOwnedByCurrentUser(pid uint32) bool {
	info, err := os.Stat(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10)))
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid())
}

func linuxParentPID(pid uint32) (uint32, error) {
	data, err := os.ReadFile(
		filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "stat"),
	)
	if err != nil {
		return 0, err
	}
	closing := strings.LastIndexByte(string(data), ')')
	if closing < 0 || closing+2 >= len(data) {
		return 0, errors.New("invalid process stat")
	}
	fields := strings.Fields(string(data[closing+2:]))
	if len(fields) < 2 {
		return 0, errors.New("invalid process stat")
	}
	parent, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(parent), nil
}

func isAllowedTerminalPath(path string) bool {
	clean := filepath.Clean(path)
	return clean == "/dev/tty" ||
		clean == "/dev/console" ||
		strings.HasPrefix(clean, "/dev/pts/") ||
		strings.HasPrefix(clean, "/dev/tty")
}

func openTerminalPath(path string) (*os.File, error) {
	descriptor, err := unix.Open(
		path,
		unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	if !term.IsTerminal(descriptor) {
		_ = unix.Close(descriptor)
		return nil, errors.New("path is not a terminal")
	}
	return os.NewFile(uintptr(descriptor), path), nil
}

func promptLinuxTerminal(
	ctx context.Context,
	terminal *os.File,
	request PromptRequest,
) (passphrase string, err error) {
	descriptor := int(terminal.Fd())
	if !term.IsTerminal(descriptor) {
		return "", errors.New("authorization terminal is unavailable")
	}
	state, err := term.MakeRaw(descriptor)
	if err != nil {
		return "", fmt.Errorf("enable terminal password mode: %w", err)
	}
	defer func() {
		_, _ = io.WriteString(terminal, "\x1b[0m\x1b[?25h\x1b[?1049l")
		restoreErr := term.Restore(descriptor, state)
		if err == nil && restoreErr != nil {
			err = fmt.Errorf("restore terminal: %w", restoreErr)
		}
	}()

	password := make([]byte, 0, 64)
	defer wipe(password)
	message := ""
	lastColumns, lastRows := 0, 0
	redraw := func(force bool) error {
		columns, rows := terminalPromptDimensions(descriptor)
		if !force && columns == lastColumns && rows == lastRows {
			return nil
		}
		lastColumns, lastRows = columns, rows
		return drawTerminalPrompt(
			terminal,
			request,
			utf8.RuneCount(password),
			message,
			columns,
			rows,
		)
	}
	if err := redraw(true); err != nil {
		return "", err
	}

	input := make([]byte, 64)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		poll := []unix.PollFd{{Fd: int32(descriptor), Events: unix.POLLIN}}
		ready, pollErr := unix.Poll(poll, 200)
		if pollErr != nil {
			if errors.Is(pollErr, syscall.EINTR) {
				continue
			}
			return "", fmt.Errorf("wait for terminal input: %w", pollErr)
		}
		if ready == 0 {
			if err := redraw(false); err != nil {
				return "", err
			}
			continue
		}
		if poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return "", errors.New("authorization terminal was disconnected")
		}
		count, readErr := unix.Read(descriptor, input)
		if readErr != nil {
			if errors.Is(readErr, syscall.EINTR) ||
				errors.Is(readErr, syscall.EAGAIN) {
				continue
			}
			return "", fmt.Errorf("read terminal input: %w", readErr)
		}
		if count == 0 {
			return "", io.EOF
		}
		for _, value := range input[:count] {
			switch value {
			case '\r', '\n':
				if len(password) == 0 {
					return "", ErrPromptCancelled
				}
				return string(password), nil
			case 0x03, 0x1b:
				return "", ErrPromptCancelled
			case 0x7f, 0x08:
				if len(password) != 0 {
					_, size := utf8.DecodeLastRune(password)
					if size <= 0 {
						size = 1
					}
					password = password[:len(password)-size]
				}
			case 0x15:
				wipe(password)
				password = password[:0]
			default:
				if value >= 0x20 && len(password) < maxTerminalPassphraseBytes {
					password = append(password, value)
				}
			}
		}
		message = ""
		if len(password) == maxTerminalPassphraseBytes {
			message = "Maximum passphrase length reached"
		}
		if err := redraw(true); err != nil {
			return "", err
		}
	}
}

func terminalPromptDimensions(descriptor int) (int, int) {
	columns, rows, err := term.GetSize(descriptor)
	if err != nil || columns <= 0 || rows <= 0 {
		return 80, 24
	}
	return columns, rows
}

func drawTerminalPrompt(
	writer io.Writer,
	request PromptRequest,
	passwordRunes int,
	message string,
	columns int,
	rows int,
) error {
	if columns <= 0 {
		columns = 80
	}
	if rows <= 0 {
		rows = 24
	}
	description := DescribePrompt(request)
	fieldWidth := min(58, max(1, columns-4))
	maskedWidth := min(passwordRunes, fieldWidth)
	masked := strings.Repeat("*", maskedWidth)
	if passwordRunes > fieldWidth && fieldWidth >= 4 {
		masked = "..." + strings.Repeat("*", fieldWidth-3)
	}
	field := "[" + masked +
		strings.Repeat(" ", max(0, fieldWidth-utf8.RuneCountInString(masked))) +
		"]"

	startRow := max(1, (rows-10)/2)
	titleRow := startRow
	separatorRow := startRow + 1
	descriptionRow := startRow + 3
	labelRow := startRow + 5
	fieldRow := startRow + 6
	messageRow := startRow + 8
	footerRow := rows
	if rows < 10 {
		titleRow = 1
		separatorRow = 2
		descriptionRow = 3
		labelRow = max(3, rows-4)
		fieldRow = max(4, rows-3)
		messageRow = max(5, rows-2)
	}

	var screen strings.Builder
	screen.WriteString("\x1b[?1049h\x1b[?25l\x1b[44;97m\x1b[2J\x1b[H")
	writeTerminalPromptRow(&screen, titleRow, columns, "PASSFS AUTHORIZATION")
	writeTerminalPromptRow(
		&screen,
		separatorRow,
		columns,
		strings.Repeat("-", max(1, columns-1)),
	)
	writeTerminalPromptRow(&screen, descriptionRow, columns, description)
	writeTerminalPromptRow(&screen, labelRow, columns, "Passphrase")
	writeTerminalPromptRow(&screen, fieldRow, columns, field)
	writeTerminalPromptRow(&screen, messageRow, columns, message)
	writeTerminalPromptRow(
		&screen,
		footerRow,
		columns,
		"Enter: unlock    Esc: cancel",
	)
	_, err := io.WriteString(writer, screen.String())
	return err
}

func writeTerminalPromptRow(
	writer *strings.Builder,
	row int,
	columns int,
	value string,
) {
	if row <= 0 {
		return
	}
	value = centerTerminalLine(value, columns)
	fmt.Fprintf(writer, "\x1b[%d;1H\x1b[2K%s", row, value)
}

func centerTerminalLine(value string, width int) string {
	value = fitTerminalLine(value, width)
	padding := max(0, (width-utf8.RuneCountInString(value))/2)
	return strings.Repeat(" ", padding) + value
}

func fitTerminalLine(value string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(value)
	for index, value := range runes {
		if unicode.IsControl(value) {
			runes[index] = '?'
		}
	}
	if len(runes) <= width {
		return string(runes)
	}
	if width <= 3 {
		return string(runes[:width])
	}
	return string(runes[:width-3]) + "..."
}
