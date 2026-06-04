package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
)

// ─── Tiny utility helpers ────────────────────────────────────────────────────

// parallelProbe runs `work` over each input concurrently, bounded by
// `concurrency` workers. It's the in-check equivalent of validateKey's
// per-check fan-out — used by probes that have to walk many candidate
// names (common-path enumeration, function-name bruteforce, etc.) so a
// single check doesn't serialize 50 HTTP requests on the critical path.
//
// `work` is expected to guard any shared state with its own mutex.
func parallelProbe[T any](items []T, concurrency int, work func(T)) {
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, item := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(it T) {
			defer wg.Done()
			defer func() { <-sem }()
			work(it)
		}(item)
	}
	wg.Wait()
}

// rawIf returns the body as a string in Verbose mode only. Used by `cr` so
// JSONL/raw-output retain the response body only when the operator asked for
// it via -v.
func rawIf(data []byte) string {
	if Verbose {
		return string(data)
	}
	return ""
}

// unmarshal wraps json.Unmarshal with a stderr warning in Verbose mode when
// decoding fails. Many Google APIs return non-JSON content on error paths and
// we don't want every check to log its own decode failure noise.
func unmarshal(body []byte, v interface{}) error {
	err := json.Unmarshal(body, v)
	if err != nil && Verbose {
		fmt.Fprintf(os.Stderr, "[WARN] JSON decode error: %v (body prefix: %.120s)\n", err, body)
	}
	return err
}

// cr is the constructor checks use to build a CheckResult. Keeps the Status
// string copy and raw-JSON capture in one place.
func cr(service, category string, status Status, detail string, rawBody []byte) CheckResult {
	return CheckResult{
		Service:  service,
		Category: category,
		Status:   status,
		StatusS:  status.String(),
		Detail:   detail,
		RawJSON:  rawIf(rawBody),
	}
}

// shortName returns the last `/`-separated segment of a fully-qualified name
// (e.g. "projects/foo/instances/bar" → "bar").
func shortName(full string) string {
	parts := strings.Split(full, "/")
	return parts[len(parts)-1]
}

// isInvalidKeyResponse returns true when a Google API response body indicates
// the API key itself was rejected (vs. the request payload being malformed).
// Google returns HTTP 400 with reason=API_KEY_INVALID when a key cannot access
// a service — this must NOT be treated as evidence the API is enabled.
func isInvalidKeyResponse(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	s := string(body)
	for _, marker := range []string{
		"API_KEY_INVALID",
		"API_KEY_SERVICE_BLOCKED",
		"API_KEY_HTTP_REFERRER_BLOCKED",
		"API_KEY_IP_ADDRESS_BLOCKED",
		"API_KEY_ANDROID_APP_BLOCKED",
		"API_KEY_IOS_APP_BLOCKED",
		"API_KEY_EXPIRED",
		"API key not valid",
		"The provided API key is invalid",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// fillPoC substitutes {KEY}, {PROJECT}, {PROJECT_NUMBER} placeholders in a
// PoC template. The raw (un-encoded) key is intentionally used — copy-pasted
// curl commands must contain the literal key the user already has on disk.
func fillPoC(template, key, projectID, projectNumber string) string {
	out := strings.ReplaceAll(template, "{KEY}", key)
	// Replace {PROJECT_NUMBER} before {PROJECT} so the shorter prefix doesn't
	// eat the longer placeholder's leading substring.
	out = strings.ReplaceAll(out, "{PROJECT_NUMBER}", projectNumber)
	out = strings.ReplaceAll(out, "{PROJECT}", projectID)
	return out
}

// httpError classifies an HTTP response that didn't match any explicit branch.
// Google returns HTTP 400 with reason=API_KEY_INVALID for many APIs when the
// key is not authorized for the service — those are demoted to Forbidden so
// they don't clutter the output as "errors".
func httpError(service, category string, code int, body []byte) CheckResult {
	if code == 400 && isInvalidKeyResponse(body) {
		return cr(service, category, StatusForbidden, "Key rejected for this service", body)
	}
	// 404 typically means the API is reachable but the resource path doesn't
	// exist for this project (e.g. no default Firestore database, no IAP web
	// resources, no Firebase App Check apps registered). The key works, but
	// there's nothing to exploit — same effective severity as "API not enabled".
	if code == 404 {
		return cr(service, category, StatusForbidden, "Key valid, no resources of this type in project", body)
	}
	return cr(service, category, StatusError, fmt.Sprintf("HTTP %d", code), body)
}

// ─── Secret scanning (used by Cloud Logging finding enrichment) ─────────────

// secretPatterns lists regexes for high-confidence secret tokens that
// occasionally leak through Cloud Logging. We keep the list short and
// high-signal — false positives in a finding detail are worse than missing
// some classes of secret.
var secretPatterns = []struct {
	label string
	re    *regexp.Regexp
}{
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Google API key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{"Google OAuth token", regexp.MustCompile(`ya29\.[A-Za-z0-9_-]{20,}`)},
	{"Slack token", regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"GitHub PAT", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"Private key block", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----`)},
}

// scanForSecrets returns labels for any secret patterns matched in body.
// De-duplicated, so a body with three AWS keys yields one entry.
func scanForSecrets(body []byte) []string {
	seen := map[string]bool{}
	var hits []string
	for _, p := range secretPatterns {
		if p.re.Match(body) && !seen[p.label] {
			hits = append(hits, p.label)
			seen[p.label] = true
		}
	}
	return hits
}

// isProjectNumber returns true when the given identifier is purely digits,
// indicating it's a GCP project NUMBER (e.g. 1033944876380) rather than a
// project ID slug (e.g. my-project-prod1). Both are valid project identifiers
// for most GCP APIs, but Firebase-specific endpoints (RTDB host, Storage
// bucket name) require the slug — so callers may want to flag this.
func isProjectNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
