package analyzer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestScanObjectsForSecretsBounds is the safety test: even with a huge candidate
// set containing a "1 TB" object and many matches, the scanner stays bounded —
// binaries are never fetched, downloads are capped, and only the secret-bearing
// file is reported.
func TestScanObjectsForSecretsBounds(t *testing.T) {
	var names []string
	names = append(names, "leak.env")  // index 0: matches, holds a secret
	names = append(names, "huge.bin")  // binary → must never be fetched
	names = append(names, "video.mp4") // binary → must never be fetched
	// Many more matching files than the download cap, beyond the candidate cap.
	for i := 0; i < 1000; i++ {
		names = append(names, fmt.Sprintf("config%d.env", i))
	}

	var mu sync.Mutex
	fetched := map[string]bool{}
	fetch := func(name string) []byte {
		mu.Lock()
		fetched[name] = true
		mu.Unlock()
		if name == "leak.env" {
			return []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
		}
		return []byte("nothing-here")
	}

	hits := scanObjectsForSecrets(names, fetch)

	if fetched["huge.bin"] || fetched["video.mp4"] {
		t.Fatalf("binary objects must never be fetched: %v", fetched)
	}
	if len(fetched) > scanMaxDownloads {
		t.Fatalf("downloads exceeded cap: %d > %d", len(fetched), scanMaxDownloads)
	}
	var found bool
	for _, h := range hits {
		if strings.HasPrefix(h, "leak.env: ") && strings.Contains(h, "AWS access key") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the .env AWS secret to be reported, got: %v", hits)
	}
	// Nothing past the candidate cap should ever be fetched.
	if fetched[fmt.Sprintf("config%d.env", 1000-1)] {
		t.Fatalf("a candidate beyond scanMaxCandidates was fetched")
	}
}

// TestDoGetCapped confirms a large response is truncated to maxBytes even if the
// server ignores the Range header.
func TestDoGetCapped(t *testing.T) {
	Client = &http.Client{Timeout: 10 * time.Second}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("A", 10<<20))) // 10 MiB, Range ignored
	}))
	defer srv.Close()

	code, body, err := doGetCapped(context.Background(), srv.URL, nil, scanRangeBytes)
	if err != nil {
		t.Fatalf("doGetCapped error: %v", err)
	}
	if code/100 != 2 {
		t.Fatalf("unexpected status %d", code)
	}
	if int64(len(body)) > scanRangeBytes {
		t.Fatalf("read %d bytes, exceeds cap %d", len(body), scanRangeBytes)
	}
}
