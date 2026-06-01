package analyzer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

// extractProjectIDFromJWT decodes a JWT's payload (without verification) and
// returns the audience, which for Firebase ID tokens equals the project ID.
// Falls back to the trailing segment of "iss" (e.g. https://securetoken.google.com/<projectId>).
func extractProjectIDFromJWT(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Aud json.RawMessage `json:"aud"`
		Iss string          `json:"iss"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	var audStr string
	if len(claims.Aud) > 0 {
		if json.Unmarshal(claims.Aud, &audStr) == nil && audStr != "" {
			return audStr
		}
		var audArr []string
		if json.Unmarshal(claims.Aud, &audArr) == nil && len(audArr) > 0 {
			return audArr[0]
		}
	}
	if idx := strings.LastIndex(claims.Iss, "/"); idx >= 0 && idx < len(claims.Iss)-1 {
		return claims.Iss[idx+1:]
	}
	return ""
}

// extractUIDFromJWT pulls the `sub` (or `user_id`) claim from a Firebase ID
// token. That value is the Firebase Auth UID, needed by probes that want to
// test rules referencing `request.auth.uid` (e.g. `/users/{uid}` patterns).
func extractUIDFromJWT(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub    string `json:"sub"`
		UserID string `json:"user_id"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	if claims.Sub != "" {
		return claims.Sub
	}
	return claims.UserID
}

// runFirebaseSignUp performs an anonymous Firebase Auth signup and returns
// the corresponding CheckResult, the project ID extracted from the returned
// ID token (if any), and the resulting session (idToken/refreshToken/localID)
// for downstream authenticated probes and cleanup. The key must already be
// URL-encoded.
func runFirebaseSignUp(escKey string) (CheckResult, string, firebaseSession) {
	u := "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" + escKey
	code, body, err := doPost(u, map[string]interface{}{"returnSecureToken": true})
	if err != nil {
		return cr("Firebase Auth Signup", "Firebase", StatusError, err.Error(), nil), "", firebaseSession{}
	}
	if code == 200 {
		var resp struct {
			IDToken      string `json:"idToken"`
			LocalID      string `json:"localId"`
			RefreshToken string `json:"refreshToken"`
		}
		unmarshal(body, &resp)
		pid := extractProjectIDFromJWT(resp.IDToken)
		detail := "Anonymous signup enabled — JWT obtained (UID " + resp.LocalID + "). Means-to-an-end; impact is reported on the Firestore/RTDB/Storage auth-bypass rows."
		sess := firebaseSession{
			idToken:      resp.IDToken,
			refreshToken: resp.RefreshToken,
			localID:      resp.LocalID,
		}
		// Not Vulnerable: signup alone has no impact. Every downstream use we
		// can probe (Firestore/RTDB/Storage read+write) is its own check; if
		// any of those bypass rules, that's where the CONFIRMED row lives.
		// Hidden by default; visible with -v.
		return cr("Firebase Auth Signup", "Firebase", StatusNotVulnerable, detail, body), pid, sess
	}
	if code == 400 || code == 401 || code == 403 {
		return cr("Firebase Auth Signup", "Firebase", StatusForbidden, "Key valid, API not enabled or signup disabled", body), "", firebaseSession{}
	}
	return httpError("Firebase Auth Signup", "Firebase", code, body), "", firebaseSession{}
}

// deleteAnonymousUser removes an anonymous user we created earlier so the scan
// leaves no trace. Failure surfaces in Verbose mode only; cleanup is
// best-effort hygiene and does not block the scan.
func deleteAnonymousUser(escKey, idToken string) {
	if idToken == "" {
		return
	}
	u := "https://identitytoolkit.googleapis.com/v1/accounts:delete?key=" + escKey
	code, body, err := doPost(u, map[string]interface{}{"idToken": idToken})
	if Verbose {
		if err != nil {
			fmt.Fprintf(os.Stderr, "[CLEANUP] accounts:delete failed: %v\n", err)
		} else if code != 200 {
			fmt.Fprintf(os.Stderr, "[CLEANUP] accounts:delete returned HTTP %d — anon user may remain: %.200s\n", code, body)
		} else {
			fmt.Fprintln(os.Stderr, "[CLEANUP] anonymous user deleted")
		}
	}
}

// ─── Project ID discovery pipeline ──────────────────────────────────────────
//
// Google API keys are commonly leaked with no Cloud Resource Manager access,
// so listing projects via the canonical endpoint fails. The methods below
// each try to recover the project ID (or project number) through a different
// side channel — Firebase Auth tokens, error-message leaks, public listing
// endpoints, etc. They run concurrently; the first non-empty result wins.
//
// Project numbers are accepted in place of project IDs by virtually all
// project-scoped GCP/Firebase REST URLs, so a number is almost as useful as
// the alphanumeric slug.

// projectPathPattern matches a project segment in API responses, capturing
// either a GCP project ID (6-30 lowercase alphanum-with-hyphens, leading letter)
// or a project number (5+ digits).
var projectPathPattern = regexp.MustCompile(`projects/([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{5,})`)

// scanBodyForProject extracts a project ID or number from a response body.
func scanBodyForProject(body []byte) (id string, num string) {
	m := projectPathPattern.FindSubmatch(body)
	if len(m) < 2 {
		return "", ""
	}
	val := string(m[1])
	allDigits := true
	for _, c := range val {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "", val
	}
	return val, ""
}

func newDiscoveryAccum() *discoveryAccum {
	ctx, cancel := context.WithCancel(context.Background())
	return &discoveryAccum{ctx: ctx, cancel: cancel}
}

func (d *discoveryAccum) noteID(method, id string) {
	if id == "" {
		return
	}
	d.mu.Lock()
	d.ids = append(d.ids, id)
	d.methodHits = append(d.methodHits, method+"="+id)
	d.mu.Unlock()
	// Abort any remaining discovery probes — we have an answer.
	d.cancel()
}

func (d *discoveryAccum) noteNumber(method, num string) {
	if num == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.numbers = append(d.numbers, num)
	d.methodHits = append(d.methodHits, method+" (num)="+num)
}

func (d *discoveryAccum) setSession(s firebaseSession) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.session = s
}

func (d *discoveryAccum) cacheCheck(name string, c CheckResult) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cachedChecks == nil {
		d.cachedChecks = make(map[string]CheckResult)
	}
	d.cachedChecks[name] = c
}

// pickProjectID returns the best discovered project value, preferring
// alphanumeric IDs over numeric project numbers.
func (d *discoveryAccum) pickProjectID() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.ids) > 0 {
		return d.ids[0]
	}
	if len(d.numbers) > 0 {
		return d.numbers[0]
	}
	return ""
}

// pickProjectNumber returns the first discovered project number, independent
// of any slug. Used by checks whose target resource names embed the project
// number (Cloud Functions source buckets, etc.).
func (d *discoveryAccum) pickProjectNumber() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.numbers) > 0 {
		return d.numbers[0]
	}
	return ""
}

// refreshTokenExchange uses a Firebase refresh token to call the securetoken
// endpoint, which returns the project_id directly in the JSON response.
// Uses application/x-www-form-urlencoded, not JSON, so we bypass doPost.
func refreshTokenExchange(parent context.Context, escKey, refreshToken string) string {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	bodyData := []byte(form.Encode())

	ctx, cancel := context.WithTimeout(parent, Client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://securetoken.googleapis.com/v1/token?key="+escKey,
		bytes.NewReader(bodyData))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "aiza-key-analyzer/1.0")
	resp, err := Client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	var parsed struct {
		ProjectID string `json:"project_id"`
	}
	if json.Unmarshal(respBody, &parsed) != nil {
		return ""
	}
	return parsed.ProjectID
}

// discoverProjectID fan-outs all discovery methods in parallel and collects
// findings. Methods that double as service checks (Firebase Auth Signup) leave
// their CheckResult in d.cachedChecks so the main scan can skip them.
//
// Once any method records an alphanumeric project ID via noteID, d.cancel
// fires and remaining methods abort their HTTP calls. Methods that only find
// a numeric project number (via noteNumber) do not cancel, since a slug ID
// from another method is still preferable.
func discoverProjectID(key, escKey string) *discoveryAccum {
	d := newDiscoveryAccum()
	defer d.cancel() // release resources once fan-out completes

	var wg sync.WaitGroup

	// Method 1+2: Firebase anonymous signup → JWT aud; then securetoken refresh
	// exchange (sequential, since #2 needs the refreshToken from #1). This
	// branch ignores d.ctx because the signup also doubles as the Firebase
	// Auth Signup service check — we always want its CheckResult cached.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, pid, sess := runFirebaseSignUp(escKey)
		d.setSession(sess)
		if pid != "" {
			d.noteID("firebase-signup-jwt", pid)
		}
		if sess.refreshToken != "" && d.ctx.Err() == nil {
			if rtPID := refreshTokenExchange(d.ctx, escKey, sess.refreshToken); rtPID != "" {
				d.noteID("securetoken-exchange", rtPID)
			}
		}
	}()

	// Method 3: identitytoolkit /v2/recaptchaConfig — the response contains
	// "recaptchaKey": "projects/<number>/keys/..." for projects with Identity
	// Platform/Firebase Auth enabled.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if d.ctx.Err() != nil {
			return
		}
		u := "https://identitytoolkit.googleapis.com/v2/recaptchaConfig?key=" + escKey + "&clientType=CLIENT_TYPE_WEB"
		_, body, err := doGetCtx(d.ctx, u)
		if err != nil {
			return
		}
		if id, num := scanBodyForProject(body); id != "" {
			d.noteID("identitytoolkit-recaptcha", id)
		} else if num != "" {
			d.noteNumber("identitytoolkit-recaptcha", num)
		}
	}()

	// Method 4: Firebase Management availableProjects — lists projects the key
	// has Firebase Management access to. Rare, but a direct hit when it works.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if d.ctx.Err() != nil {
			return
		}
		u := "https://firebase.googleapis.com/v1beta1/availableProjects?key=" + escKey
		code, body, err := doGetCtx(d.ctx, u)
		if err != nil || code != 200 {
			return
		}
		var resp struct {
			ProjectInfo []struct {
				Project string `json:"project"` // "projects/<projectId>"
			} `json:"projectInfo"`
		}
		if json.Unmarshal(body, &resp) != nil {
			return
		}
		for _, p := range resp.ProjectInfo {
			if idx := strings.LastIndex(p.Project, "/"); idx >= 0 && idx < len(p.Project)-1 {
				d.noteID("firebase-availableProjects", p.Project[idx+1:])
			}
		}
	}()

	// Method 5: Firebase Dynamic Links — send a deliberately malformed body
	// to get a 400 without creating any link. Error responses often quote
	// the project number.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if d.ctx.Err() != nil {
			return
		}
		u := "https://firebasedynamiclinks.googleapis.com/v1/shortLinks?key=" + escKey
		_, body, err := doPostCtx(d.ctx, u, map[string]interface{}{"dynamicLinkInfo": map[string]interface{}{}})
		if err != nil {
			return
		}
		if id, num := scanBodyForProject(body); id != "" {
			d.noteID("firebase-dynamic-links", id)
		} else if num != "" {
			d.noteNumber("firebase-dynamic-links", num)
		}
	}()

	// Method 6: Maps Static API — the error body for restricted/misconfigured
	// keys sometimes contains the GCP project number.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if d.ctx.Err() != nil {
			return
		}
		u := "https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key=" + escKey
		_, body, err := doGetCtx(d.ctx, u)
		if err != nil {
			return
		}
		if id, num := scanBodyForProject(body); id != "" {
			d.noteID("maps-static-error", id)
		} else if num != "" {
			d.noteNumber("maps-static-error", num)
		}
	}()

	// Method 7: Generic 403 body scrape — a small set of project-agnostic
	// endpoints whose error bodies tend to include project paths. This is the
	// cheapest catch-all when more targeted methods fail.
	wg.Add(1)
	go func() {
		defer wg.Done()
		probes := []string{
			"https://serviceusage.googleapis.com/v1/services?key=" + escKey,
			"https://cloudbilling.googleapis.com/v1/billingAccounts?key=" + escKey,
			"https://iam.googleapis.com/v1/roles?key=" + escKey,
		}
		for _, u := range probes {
			if d.ctx.Err() != nil {
				return
			}
			_, body, err := doGetCtx(d.ctx, u)
			if err != nil {
				continue
			}
			if id, num := scanBodyForProject(body); id != "" {
				d.noteID("generic-403-scrape", id)
				return
			} else if num != "" {
				d.noteNumber("generic-403-scrape", num)
				return
			}
		}
	}()

	// Method 8: Firebase Installations — sending a request with a placeholder
	// project routes through the key's default project; the error body or
	// (rarely) a 200 response includes the real project number. We send a
	// minimal-but-malformed body so no installation is registered.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if d.ctx.Err() != nil {
			return
		}
		ctx, cancel := context.WithTimeout(d.ctx, Client.Timeout)
		defer cancel()
		body := []byte(`{"appId":"-","authVersion":"FIS_v2","sdkVersion":"a:0"}`)
		req, err := http.NewRequestWithContext(ctx, "POST",
			"https://firebaseinstallations.googleapis.com/v1/projects/-/installations",
			bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-goog-api-key", escKey)
		req.Header.Set("User-Agent", "aiza-key-analyzer/1.0")
		resp, err := Client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}
		if id, num := scanBodyForProject(respBody); id != "" {
			d.noteID("firebase-installations", id)
		} else if num != "" {
			d.noteNumber("firebase-installations", num)
		}
	}()

	// Method 9: Identity Toolkit getProjectConfig (legacy v3 relyingparty).
	// Returns the project NUMBER (under the misleadingly-named "projectId"
	// field) and the project's authorizedDomains list. Works whenever the key
	// has the Firebase Auth / Identity Toolkit API enabled, which is broader
	// than anonymous signup (e.g. anonymous can be disabled while this still
	// responds).
	wg.Add(1)
	go func() {
		defer wg.Done()
		if d.ctx.Err() != nil {
			return
		}
		u := "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key=" + escKey
		code, body, err := doGetCtx(d.ctx, u)
		if err != nil || code != 200 {
			return
		}
		var resp struct {
			ProjectID         string   `json:"projectId"` // Google returns the project NUMBER here
			AuthorizedDomains []string `json:"authorizedDomains"`
		}
		if json.Unmarshal(body, &resp) != nil {
			return
		}
		if resp.ProjectID != "" {
			d.noteNumber("identitytoolkit-getProjectConfig", resp.ProjectID)
		}
		// Mine authorizedDomains for any obvious slug (foo.firebaseapp.com /
		// foo.web.app) — that IS the project slug, so it can upgrade a
		// number-only finding into a full project ID.
		for _, dom := range resp.AuthorizedDomains {
			if s := strings.TrimSuffix(dom, ".firebaseapp.com"); s != dom && s != "" {
				d.noteID("identitytoolkit-authdomain", s)
				break
			}
			if s := strings.TrimSuffix(dom, ".web.app"); s != dom && s != "" {
				d.noteID("identitytoolkit-authdomain", s)
				break
			}
		}
	}()

	wg.Wait()

	// Post-resolution: project number → project ID. Runs after fan-out so it
	// has a chance to upgrade a numeric finding into an alphanumeric slug.
	// Many APIs accept numbers in place of IDs, but the slug is friendlier in
	// reports and PoC commands.
	d.mu.Lock()
	noIDs := len(d.ids) == 0
	numsCopy := append([]string(nil), d.numbers...)
	d.mu.Unlock()
	if noIDs {
		for _, num := range numsCopy {
			u := "https://cloudresourcemanager.googleapis.com/v1/projects/" + num + "?key=" + escKey
			code, body, err := doGet(u)
			if err != nil || code != 200 {
				continue
			}
			var resp struct {
				ProjectID string `json:"projectId"`
			}
			if json.Unmarshal(body, &resp) == nil && resp.ProjectID != "" {
				d.noteID("rm-number-resolve", resp.ProjectID)
				break
			}
		}
	}

	return d
}
