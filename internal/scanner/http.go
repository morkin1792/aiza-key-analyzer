package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// isStaleConnError detects Go's "http: server closed idle connection" race
// (and its EOF variants on HTTP/2). The stdlib auto-retry skips POST in
// some HTTP/2 cases; we catch the leftover errors here and retry once at
// the call site.
func isStaleConnError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "server closed idle connection") ||
		strings.Contains(s, "http2: server sent GOAWAY") ||
		strings.Contains(s, "http2: client connection lost") ||
		strings.Contains(s, "use of closed network connection")
}

// isTransientNetError detects errors that should clear up on a short retry:
// stale connection races (above) AND transient DNS resolver pressure (EAI_AGAIN
// surfaces as "Temporary failure in name resolution" from glibc / systemd-
// resolved when the resolver is saturated by a burst of parallel queries; the
// resolver typically recovers within a few hundred ms). Also covers connection
// resets and timeouts that occasionally hit when a proxy or upstream is busy.
func isTransientNetError(err error) bool {
	if err == nil {
		return false
	}
	if isStaleConnError(err) {
		return true
	}
	// net.DNSError has an explicit IsTemporary flag — preferable to string
	// matching when it's set. IsNotFound (NXDOMAIN) is intentionally NOT
	// retried since that's a permanent answer.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTemporary || dnsErr.IsTimeout {
			return true
		}
	}
	s := err.Error()
	return strings.Contains(s, "Temporary failure in name resolution") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "connection refused")
}

// transientBackoffs are the sleep durations between retries on transient
// errors. Three retries lets the local DNS resolver recover from a burst
// without bloating wall-clock for genuinely-broken hosts.
var transientBackoffs = []time.Duration{
	150 * time.Millisecond,
	400 * time.Millisecond,
	1000 * time.Millisecond,
}

// doCustomCtx is the call-site equivalent of doRequestCtx for inline HTTP
// that needs custom headers (Authorization, x-goog-api-key, etc.). It
// applies the same stale-keep-alive retry. Use this instead of building
// http.NewRequestWithContext + Client.Do inline — those sites bypass our
// retry and silently fail in proxy-fronted scans where idle conns die
// faster than the server normally closes them.
func doCustomCtx(parent context.Context, method, url string, body []byte, headers map[string]string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(parent, Client.Timeout)
	defer cancel()
	build := func() (*http.Request, error) {
		var b io.Reader
		if body != nil {
			b = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, b)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "aiza-key-scanner/1.0")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return req, nil
	}
	req, err := build()
	if err != nil {
		return 0, nil, err
	}
	resp, err := Client.Do(req)
	for attempt := 0; err != nil && isTransientNetError(err) && attempt < len(transientBackoffs); attempt++ {
		time.Sleep(transientBackoffs[attempt])
		req, err = build()
		if err != nil {
			return 0, nil, err
		}
		resp, err = Client.Do(req)
	}
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}

// ─── HTTP helpers ────────────────────────────────────────────────────────────

func doGet(url string) (int, []byte, error) {
	return doRequestCtx(context.Background(), "GET", url, nil)
}

// doMapsGet is the Maps-Platform variant of doGet: it sends every request with
// an attacker-controlled Referer header so a 200 response *with a successful
// body* constitutes evidence that the key works for that specific Maps API
// from an attacker origin. Each Maps API can be independently allow-listed, so
// we probe each one rigorously rather than inferring from the per-key Maps Key
// Restriction summary.
func doMapsGet(u string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), Client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "aiza-key-scanner/1.0")
	req.Header.Set("Referer", "https://aiza-poc.example.com")
	resp, err := Client.Do(req)
	for attempt := 0; err != nil && isTransientNetError(err) && attempt < len(transientBackoffs); attempt++ {
		time.Sleep(transientBackoffs[attempt])
		req, err = http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("User-Agent", "aiza-key-scanner/1.0")
		req.Header.Set("Referer", "https://aiza-poc.example.com")
		resp, err = Client.Do(req)
	}
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

func doPost(url string, body interface{}) (int, []byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	return doRequestCtx(context.Background(), "POST", url, data)
}

func doGetCtx(parent context.Context, url string) (int, []byte, error) {
	return doRequestCtx(parent, "GET", url, nil)
}

func doPostCtx(parent context.Context, url string, body interface{}) (int, []byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	return doRequestCtx(parent, "POST", url, data)
}

func doRequestCtx(parent context.Context, method, url string, body []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(parent, Client.Timeout)
	defer cancel()

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "aiza-key-scanner/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := Client.Do(req)
	// Retry on transient errors: stale-keep-alive races AND local-resolver
	// pressure (EAI_AGAIN as "Temporary failure in name resolution"). Body
	// is safe to replay because nothing was written on a connection that
	// failed before reaching the server.
	for attempt := 0; err != nil && isTransientNetError(err) && attempt < len(transientBackoffs); attempt++ {
		time.Sleep(transientBackoffs[attempt])
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}
		req, err = http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("User-Agent", "aiza-key-scanner/1.0")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err = Client.Do(req)
	}
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	// Retry once on 429
	if resp.StatusCode == 429 {
		time.Sleep(2 * time.Second)
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}
		ctx2, cancel2 := context.WithTimeout(parent, Client.Timeout)
		req2, err2 := http.NewRequestWithContext(ctx2, method, url, bodyReader)
		if err2 != nil {
			cancel2()
			return 429, respBody, nil
		}
		req2.Header.Set("User-Agent", "aiza-key-scanner/1.0")
		if body != nil {
			req2.Header.Set("Content-Type", "application/json")
		}
		resp2, err2 := Client.Do(req2)
		cancel2()
		if err2 != nil {
			return 429, respBody, nil
		}
		defer resp2.Body.Close()
		respBody2, err2 := io.ReadAll(resp2.Body)
		if err2 != nil {
			return resp2.StatusCode, nil, err2
		}
		return resp2.StatusCode, respBody2, nil
	}

	return resp.StatusCode, respBody, nil
}
