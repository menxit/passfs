package updater

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLatestAndVerifiedDownload(t *testing.T) {
	asset := []byte("passfs test binary")
	checksum := fmt.Sprintf("%x", sha256.Sum256(asset))
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(map[string]any{
		"version": "1.2.3",
		"checksums": map[string]string{
			"passfs-linux-x64.gz": checksum,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.StdEncoding.EncodeToString(
		ed25519.Sign(privateKey, manifest),
	)
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/latest/MANIFEST.json":
			_, _ = writer.Write(manifest)
		case "/latest/MANIFEST.sig":
			fmt.Fprintln(writer, signature)
		case "/latest/passfs-linux-x64.gz":
			_, _ = writer.Write(asset)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client := NewClientWithPublicKey(server.URL, publicKey)
	release, err := client.Latest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if release.Version != "1.2.3" {
		t.Fatalf("version = %q", release.Version)
	}
	var downloaded bytes.Buffer
	if err := client.Download(
		t.Context(),
		release,
		"passfs-linux-x64.gz",
		&downloaded,
	); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloaded.Bytes(), asset) {
		t.Fatalf("downloaded %q, want %q", downloaded.Bytes(), asset)
	}
}

func TestDownloadRejectsChecksumMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		_, _ = writer.Write([]byte("tampered"))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	var destination bytes.Buffer
	err := client.Download(t.Context(), Release{
		Version: "1.0.0",
		Checksums: map[string]string{
			"passfs-linux-x64.gz": fmt.Sprintf("%x", sha256.Sum256([]byte("expected"))),
		},
	}, "passfs-linux-x64.gz", &destination)
	if err == nil {
		t.Fatal("checksum mismatch was accepted")
	}
}

func TestSemanticVersionComparison(t *testing.T) {
	for _, test := range []struct {
		candidate string
		current   string
		newer     bool
	}{
		{candidate: "1.2.4", current: "1.2.3", newer: true},
		{candidate: "2.0.0", current: "1.99.99", newer: true},
		{candidate: "1.2.3", current: "1.2.3-dev", newer: true},
		{candidate: "1.2.3-beta.10", current: "1.2.3-beta.2", newer: true},
		{candidate: "1.2.3", current: "1.2.3", newer: false},
		{candidate: "1.2.2", current: "1.2.3", newer: false},
	} {
		got, err := IsNewer(test.candidate, test.current)
		if err != nil {
			t.Fatalf("%s vs %s: %v", test.candidate, test.current, err)
		}
		if got != test.newer {
			t.Fatalf(
				"IsNewer(%q, %q) = %t, want %t",
				test.candidate,
				test.current,
				got,
				test.newer,
			)
		}
	}
}

func TestVersionRejectsPathAndInvalidIdentifiers(t *testing.T) {
	for _, value := range []string{
		"1.2.3-../../escape",
		"1.2.3-alpha_1",
		"1.2.3-01",
		"1.2.3+",
	} {
		if _, err := NormalizeVersion(value); err == nil {
			t.Fatalf("invalid version %q was accepted", value)
		}
	}
}
