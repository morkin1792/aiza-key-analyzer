package analyzer

import (
	"regexp"
	"strings"
)

// ─── Bounded content secret-scanning ─────────────────────────────────────────
//
// When a datastore or bucket is *confirmed* exposed, we pull a strictly bounded
// sample of its content and run scanForSecrets over it — turning "readable,
// review manually" into "confirmed secret exposed". Safety against pathological
// targets (a bucket with millions of files, or a single multi-TB object) comes
// from four independent bounds: a candidate cap, a download cap, a per-file
// range cap (applied by the caller's fetch via doGetCapped), and a total byte
// budget. Nothing is ever fully listed or fully downloaded.

const (
	scanMaxCandidates = 500      // object names we look at (no full-listing pagination)
	scanMaxDownloads  = 50       // objects we actually fetch
	scanRangeBytes    = 10 << 20  // bytes fetched per object (first 10 MiB)
	scanTotalBudget   = 500 << 20 // total bytes fetched per store (500 MiB)
	scanRTDBBytes     = 40 << 20  // bytes read from an open RTDB /.json (40 MiB)
)

// secretFileRe matches object names worth downloading — config/credential/dump
// files where secrets actually live. Matched case-insensitively against the
// full object path.
var secretFileRe = regexp.MustCompile(`(?i)(\.env\b|\.envrc|\.pem|\.key\b|\.p12|\.pfx|\.json|\.ya?ml|\.sql|\.bak|\.cfg|\.conf|\.config|\.ini|\.properties|\.tfstate|\.npmrc|\.git-credentials|\.htpasswd|credential|secret|backup|dump|password|service[_-]?account)`)

// binaryExtRe hard-skips obviously-binary/large media regardless of any loose
// secretFileRe match, so we never spend a fetch on images/video/archives.
var binaryExtRe = regexp.MustCompile(`(?i)\.(png|jpe?g|gif|bmp|webp|svg|mp4|mov|avi|mkv|webm|mp3|wav|flac|ogg|zip|tar|t?gz|bz2|7z|rar|xz|pdf|woff2?|ttf|otf|eot|ico|bin|exe|dll|so|dylib|class|jar|war|apk|aab|wasm|iso|dmg|psd|mp4)$`)

// scanObjectsForSecrets downloads a bounded sample of secret-shaped objects and
// returns deduped "<object>: <label>" hits. fetch must return the (already
// range-capped) bytes for an object name, or nil to skip. The loop stops as soon
// as ANY bound is hit, so cost is constant regardless of bucket size.
func scanObjectsForSecrets(names []string, fetch func(name string) []byte) []string {
	seen := map[string]bool{}
	var hits []string
	var downloads, total int
	for i, name := range names {
		if i >= scanMaxCandidates || downloads >= scanMaxDownloads || total >= scanTotalBudget {
			break
		}
		if binaryExtRe.MatchString(name) || !secretFileRe.MatchString(name) {
			continue
		}
		data := fetch(name)
		if len(data) == 0 {
			continue
		}
		downloads++
		total += len(data)
		for _, label := range scanForSecrets(data) {
			key := name + ": " + label
			if !seen[key] {
				seen[key] = true
				hits = append(hits, key)
			}
		}
	}
	return hits
}

// mergeSecretHits folds content-scan hits into a check result: it appends the
// evidence to the detail and elevates the status to Confirmed (a real secret in
// an exposed store is no longer "review manually"). No-op when there are no hits.
func mergeSecretHits(res CheckResult, hits []string, where string) CheckResult {
	if len(hits) == 0 {
		return res
	}
	res.Detail += " — SECRETS DETECTED IN " + where + ": " + strings.Join(hits, ", ")
	res.Status = StatusConfirmed
	res.StatusS = StatusConfirmed.String()
	return res
}
