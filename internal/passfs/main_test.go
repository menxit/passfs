package passfs

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Scrypt's production work factor is intentionally expensive and is encoded
	// in every age stanza. Test vaults are disposable and only need to exercise
	// the same format and code paths, so reduce their creation cost before any
	// tests (including parallel tests) start.
	passphraseScryptWorkFactor = 10
	os.Exit(m.Run())
}

func TestProductionPassphraseScryptWorkFactor(t *testing.T) {
	if productionPassphraseScryptWorkFactor != 18 {
		t.Fatalf(
			"production scrypt work factor = %d, want 18",
			productionPassphraseScryptWorkFactor,
		)
	}
}
