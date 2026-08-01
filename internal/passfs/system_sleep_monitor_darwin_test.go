//go:build darwin && cgo

package passfs

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestSystemSleepEventResetsUnlockWindow(t *testing.T) {
	const passphrase = "sleep reset passphrase"
	initialized, _ := initializeTestVolume(t, passphrase, 1024*1024)
	createTestFile(t, initialized, "sleep.env", []byte("TOKEN=value\n"))

	prompter := &recordingPrompter{fallback: passphrase}
	volume, err := LoadVolume(
		initialized.root,
		prompter,
		1024*1024,
		5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	open := func() {
		handle, openErr := volume.openFile(
			context.Background(),
			"sleep.env",
			syscall.O_RDONLY,
		)
		if openErr != nil {
			t.Fatal(openErr)
		}
		if errno := handle.Close(context.Background()); errno != 0 {
			t.Fatal(errno)
		}
	}
	open()
	open()
	if got := prompter.requestCount(); got != 1 {
		t.Fatalf("prompts before sleep = %d, want 1", got)
	}

	eventReader, eventWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	monitor := newSystemSleepMonitor(volume, eventReader, func() {
		_ = eventWriter.Close()
	})
	t.Cleanup(func() {
		if err := monitor.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := eventWriter.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		volume.unlockMu.Lock()
		locked := volume.cachedIdentity == nil && len(volume.authorized) == 0
		volume.unlockMu.Unlock()
		if locked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sleep event did not clear cached authorization")
		}
		time.Sleep(time.Millisecond)
	}

	open()
	if got := prompter.requestCount(); got != 2 {
		t.Fatalf("prompts after sleep = %d, want 2", got)
	}
}

func TestSystemSleepMonitorStartsAndStops(t *testing.T) {
	const passphrase = "sleep monitor passphrase"
	initialized, _ := initializeTestVolume(t, passphrase, 1024*1024)
	volume, err := LoadVolume(
		initialized.root,
		&recordingPrompter{fallback: passphrase},
		1024*1024,
		5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}

	monitor, err := NewSystemSleepMonitor(volume)
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := monitor.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}
