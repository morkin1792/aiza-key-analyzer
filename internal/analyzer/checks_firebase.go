package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── Firebase checks ─────────────────────────────────────────────────────────

func check4_21() ServiceCheck {
	return ServiceCheck{
		Desc: "Anonymous Firebase Authentication sign-up is enabled, letting anyone mint a valid idToken — the foothold for every auth-gated Firebase resource whose rules only check that the caller is signed in (auth != null).",
		Name: "Firebase Anonymous Sign-up Enabled", Category: "Firebase", NeedsProject: false,
		PoC: `curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}' -H 'Content-Type: application/json' -d '{"returnSecureToken":true}'`,
		Run: func(key, projectID string) CheckResult {
			result, _, _ := runFirebaseSignUp(key)
			return result
		},
	}
}

// check4_22 (Firebase Auth Providers) probes for Email Enumeration Protection.
//
// Firebase added Email Enumeration Protection in 2023 because the default
// createAuthUri behaviour — returning `"registered": true|false` — lets
// anyone with the API key confirm whether arbitrary email addresses are users
// of the project. Google explicitly calls this a misconfiguration when
// protection is off.
//
// We send the endpoint a deliberately bogus email; if the response still
// includes `"registered": false`, protection is OFF (real finding). If the
// endpoint masks the field or errors out, protection is ON.
func check4_22() ServiceCheck {
	return ServiceCheck{
		Desc: "The Identity Toolkit endpoint discloses whether an email is registered, enabling account enumeration for targeted phishing or credential-stuffing.",
		Name: "Firebase Email Enumeration", Category: "Firebase", NeedsProject: false,
		PoC: `# Probe email-enumeration protection status — bogus email should return registered:false if protection is off
curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={KEY}' -H 'Content-Type: application/json' -d '{"identifier":"aiza-poc@no.invalid","continueUri":"http://localhost"}'`,
		Run: func(key, projectID string) CheckResult {
			// Bogus identifier — definitely not a registered user of any project.
			probeEmail := fmt.Sprintf("aiza-poc-%d@no.invalid", time.Now().UnixNano())
			url := "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=" + key
			payload := map[string]interface{}{
				"identifier":  probeEmail,
				"continueUri": "http://localhost",
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Firebase Email Enumeration", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				// Use *bool to distinguish "field present and false" from "field absent".
				var resp struct {
					Registered    *bool    `json:"registered"`
					AllProviders  []string `json:"allProviders"`
					SigninMethods []string `json:"signinMethods"`
				}
				unmarshal(body, &resp)
				if resp.Registered != nil {
					// Endpoint divulged registered-status for our bogus email.
					// Protection is off — anyone can enumerate users of this project.
					return cr("Firebase Email Enumeration", "Firebase", StatusConfirmed,
						"", body)
				}
				// Field absent: protection is on (or the response shape changed
				// in a way that hides registration status).
				return cr("Firebase Email Enumeration", "Firebase", StatusNotVulnerable,
					"createAuthUri reachable; Email Enumeration Protection appears active", body)
			}
			// Some projects with protection on return EMAIL_EXISTS or similar 400.
			bodyStr := string(body)
			if code == 400 && (strings.Contains(bodyStr, "EMAIL_EXISTS") || strings.Contains(bodyStr, "INVALID_EMAIL") || strings.Contains(bodyStr, "EMAIL_ENUMERATION_PROTECTION")) {
				return cr("Firebase Email Enumeration", "Firebase", StatusNotVulnerable,
					"createAuthUri rejects probe email — Email Enumeration Protection active", body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Firebase Email Enumeration", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase Email Enumeration", "Firebase", code, body)
		},
	}
}

// checkEmailPasswordSignup probes whether the project allows random email +
// password signup (separate from anonymous signup). A success means anyone
// with the leaked key can create persistent accounts in the project's user
// database — useful for typosquatting, support-channel abuse, or just
// polluting analytics. We clean up the created account on success.
func checkEmailPasswordSignup() ServiceCheck {
	return ServiceCheck{
		Desc: "Email/password sign-up is open on this project, letting an attacker self-register accounts and obtain authenticated sessions.",
		Name: "Open Email/Password Registration", Category: "Firebase", NeedsProject: false,
		PoC: `# Try to create a random account; if 200 the project allows email/password signup
curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}' -H 'Content-Type: application/json' -d '{"email":"aiza-poc@no.invalid","password":"AizaPoc1!","returnSecureToken":true}'`,
		Run: func(key, projectID string) CheckResult {
			email := fmt.Sprintf("aiza-poc-%d@no.invalid", time.Now().UnixNano())
			u := "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" + key
			payload := map[string]interface{}{
				"email":             email,
				"password":          "AizaPocAbc12345!",
				"returnSecureToken": true,
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Open Email/Password Registration", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					IDToken string `json:"idToken"`
					LocalID string `json:"localId"`
				}
				unmarshal(body, &resp)
				// Cleanup: best-effort delete the account we just created.
				if resp.IDToken != "" {
					_, _, _ = doPost("https://identitytoolkit.googleapis.com/v1/accounts:delete?key="+key,
						map[string]interface{}{"idToken": resp.IDToken})
				}
				return cr("Open Email/Password Registration", "Firebase", StatusConfirmed,
					"Email+password signup is OPEN — created and deleted "+email+" (UID "+resp.LocalID+")", body)
			}
			bodyStr := string(body)
			if code == 400 && (strings.Contains(bodyStr, "OPERATION_NOT_ALLOWED") || strings.Contains(bodyStr, "PASSWORD_LOGIN_DISABLED")) {
				return cr("Open Email/Password Registration", "Firebase", StatusNotVulnerable,
					"Email+password signup explicitly disabled in project — properly restricted", body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Open Email/Password Registration", "Firebase", StatusForbidden, "Key valid, signup rejected", body)
			}
			return httpError("Open Email/Password Registration", "Firebase", code, body)
		},
	}
}

// checkTenantEnumeration lists tenants on a multi-tenant Identity Platform
// project. When accessible, it leaks the tenant structure of the app — names
// like "internal-admins", "partner-orgs", "support-team" are real
// architectural intelligence.
func checkTenantEnumeration() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can enumerate Identity Platform / multi-tenancy tenants, revealing the project's auth tenant structure.",
		Name: "Identity Platform Tenant Enumeration", Category: "Firebase", NeedsProject: true,
		PoC: "curl -s 'https://identitytoolkit.googleapis.com/v2/projects/{PROJECT}/tenants?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://identitytoolkit.googleapis.com/v2/projects/%s/tenants?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Identity Platform Tenant Enumeration", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Tenants []struct {
						Name        string `json:"name"`
						DisplayName string `json:"displayName"`
					} `json:"tenants"`
				}
				unmarshal(body, &resp)
				if len(resp.Tenants) == 0 {
					return cr("Identity Platform Tenant Enumeration", "Firebase", StatusNotVulnerable,
						"Tenants endpoint accessible, project has no tenants configured", body)
				}
				names := make([]string, 0, min(5, len(resp.Tenants)))
				for i := 0; i < min(5, len(resp.Tenants)); i++ {
					names = append(names, resp.Tenants[i].DisplayName)
				}
				return cr("Identity Platform Tenant Enumeration", "Firebase", StatusConfirmed,
					fmt.Sprintf("%d Identity Platform tenants leaked: %s", len(resp.Tenants), strings.Join(names, ", ")), body)
			}
			if code == 401 || code == 403 || code == 404 {
				return cr("Identity Platform Tenant Enumeration", "Firebase", StatusForbidden, "Key valid, tenants endpoint denied or no tenants", body)
			}
			return httpError("Identity Platform Tenant Enumeration", "Firebase", code, body)
		},
	}
}

// rtdbRegions are the Realtime Database regional endpoints we guess as a
// fallback. RTDB instances outside us-central1 are served at
// {db}-default-rtdb.{region}.firebasedatabase.app; us-central1 uses the legacy
// firebaseio.com hosts handled separately. The authoritative host (correct
// region AND any non-default instance name) comes from the init.json databaseURL
// in rtdbHosts; this list only matters when init.json is unavailable.
var rtdbRegions = []string{
	"us-east1", "us-west1",
	"europe-west1", "europe-west3",
	"asia-southeast1", "asia-east1", "asia-northeast1", "asia-south1",
	"southamerica-east1", "australia-southeast1",
}

// rtdbHosts returns the candidate Realtime Database hosts for a project,
// most-authoritative first and de-duplicated. The exact deployed instance is
// taken from the public Hosting init.json's databaseURL when available (this is
// the only signal that captures a non-default region or a named instance);
// everything else is a best-effort fallback guess.
func rtdbHosts(projectID string) []string {
	var hosts []string
	seen := map[string]bool{}
	add := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	// Authoritative: the databaseURL from the public Hosting config.
	if cfg, _, ok := fetchFirebaseInitJSON(projectID); ok && cfg.DatabaseURL != "" {
		if u, err := url.Parse(cfg.DatabaseURL); err == nil {
			add(u.Host)
		}
	}
	// Fallback guesses: default (us-central1) hosts, then known regions.
	add(fmt.Sprintf("%s-default-rtdb.firebaseio.com", projectID))
	add(fmt.Sprintf("%s.firebaseio.com", projectID))
	for _, region := range rtdbRegions {
		add(fmt.Sprintf("%s-default-rtdb.%s.firebasedatabase.app", projectID, region))
	}
	return hosts
}

// rtdbProbe walks the candidate RTDB hosts and reports the most permissive
// outcome. authMode is "anon" or "auth"; for "auth" the supplied idToken is
// passed as the RTDB `auth=` query parameter (RTDB does not accept the API
// key as an auth credential — it expects a Firebase ID token or a legacy
// database secret). The matched host is returned so callers can build a PoC
// against the exact URL that worked (the host varies by region/legacy setup).
func rtdbProbe(projectID, idToken, authMode string) (CheckResult, string) {
	hosts := rtdbHosts(projectID)
	var bestForbidden *CheckResult
	for _, h := range hosts {
		u := "https://" + h + "/.json?shallow=true"
		if idToken != "" {
			u += "&auth=" + url.QueryEscape(idToken)
		}
		code, body, err := doGet(u)
		if err != nil {
			continue
		}
		if code == 200 {
			detail := "Open read access to root node"
			if authMode == "auth" {
				detail = "Read access via anonymous signup idToken (auth-rule bypass)"
			}
			return cr("Firebase RTDB Public Read Access", "Firebase", StatusConfirmed, detail+" — "+h, body), h
		}
		if (code == 401 || code == 403) && bestForbidden == nil {
			r := cr("Firebase RTDB Public Read Access", "Firebase", StatusForbidden, "Key valid, read access denied", body)
			bestForbidden = &r
		}
	}
	if bestForbidden != nil {
		return *bestForbidden, ""
	}
	return cr("Firebase RTDB Public Read Access", "Firebase", StatusForbidden, "No RTDB instance found (tried default, EU, Asia, and bare project name)", nil), ""
}

// scanRTDBData reads a bounded slice (scanRTDBBytes) of an open Realtime
// Database root and returns scanForSecrets labels found in it. One capped read,
// so an enormous database still costs at most scanRTDBBytes.
func scanRTDBData(host, idToken string) []string {
	u := "https://" + host + "/.json"
	if idToken != "" {
		u += "?auth=" + url.QueryEscape(idToken)
	}
	code, body, err := doGetCapped(context.Background(), u, nil, scanRTDBBytes)
	if err != nil || code/100 != 2 {
		return nil
	}
	return scanForSecrets(body)
}

// finalizeRTDBRead applies content secret-scanning to a confirmed RTDB read and
// sets severity: a secret in the data keeps/makes it Confirmed; an otherwise
// public root read (no secret, no auth-bypass) is downgraded to Potential since
// public read can be intentional. authBypass results are already Confirmed and
// only get any secret evidence appended.
func finalizeRTDBRead(result CheckResult, host, idToken string, authBypass bool) CheckResult {
	hits := scanRTDBData(host, idToken)
	if authBypass || len(hits) > 0 {
		return mergeSecretHits(result, hits, "RTDB DATA")
	}
	result.Status = StatusPotential
	result.StatusS = StatusPotential.String()
	result.Detail += " — public RTDB; review nodes for sensitive data"
	return result
}

const rtdbAuthPoCTemplate = `# 1. Sign up anonymously to get an idToken
TOKEN=$(curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}' -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)
# 2. Read RTDB root with the token (use the host from the finding detail)
curl -s "https://{HOST}/.json?auth=${TOKEN}"`

const rtdbAnonPoCTemplate = `curl -s 'https://{HOST}/.json'`

func check4_23() ServiceCheck {
	return ServiceCheck{
		Desc: "The Realtime Database is readable without proper authorization, directly exposing application data stored in RTDB.",
		Name: "Firebase RTDB Public Read Access", Category: "Firebase", NeedsProject: true,
		// Default PoC is a placeholder — the check overrides it with the
		// matched host below so the user doesn't have to guess which of the
		// 4 candidate hosts actually served the response.
		PoC: "curl -s 'https://{PROJECT}-default-rtdb.firebaseio.com/.json'",
		Run: func(key, projectID string) CheckResult {
			result, host := rtdbProbe(projectID, "", "anon")
			if result.Status == StatusConfirmed && host != "" {
				// Scan a bounded sample of the data: a secret in it is a confirmed
				// critical; an otherwise-public read is downgraded to review.
				result = finalizeRTDBRead(result, host, "", false)
				result.PoC = strings.ReplaceAll(rtdbAnonPoCTemplate, "{HOST}", host)
			}
			return result
		},
		RunAuth: func(key, projectID, idToken string) CheckResult {
			anon, anonHost := rtdbProbe(projectID, "", "anon")
			authed, authedHost := rtdbProbe(projectID, idToken, "auth")
			anonOK := anon.Status == StatusConfirmed
			authOK := authed.Status == StatusConfirmed
			// Auth-bypass: anon denied, but anon-signup JWT bypasses → clear misconfig.
			if !anonOK && authOK {
				authed.Detail += " — rules require auth but anonymous-signup JWT bypasses them"
				authed = finalizeRTDBRead(authed, authedHost, idToken, true) // stays Confirmed; appends any secrets
				authed.PoC = fillPoC(strings.ReplaceAll(rtdbAuthPoCTemplate, "{HOST}", authedHost), key, projectID, "")
				return authed
			}
			// Public read works → scan; secret = Confirmed, else review.
			if anonOK {
				anon = finalizeRTDBRead(anon, anonHost, "", false)
				anon.PoC = strings.ReplaceAll(rtdbAnonPoCTemplate, "{HOST}", anonHost)
				return anon
			}
			// Both denied — properly restricted.
			if anon.Status == StatusForbidden {
				return anon
			}
			return authed
		},
	}
}

// firestoreListCollections lists Firestore root-level collections via the
// Firebase SDK surface. With idToken="" the request is anonymous (catches
// `allow read: if true;`); with idToken set it rides through Security Rules
// as an authenticated user (catches `if request.auth != null;`).
func firestoreListCollections(escKey, projectID, idToken string) CheckResult {
	u := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents:listCollectionIds?key=%s", projectID, escKey)
	headers := map[string]string{"Content-Type": "application/json"}
	if idToken != "" {
		headers["Authorization"] = "Bearer " + idToken
	}
	code, respBody, err := doCustomCtx(context.Background(), "POST", u, []byte(`{"pageSize":100}`), headers)
	if err != nil {
		return cr("Firebase Firestore Public Read Access", "Firebase", StatusError, err.Error(), nil)
	}
	if code == 200 {
		var parsed struct {
			CollectionIDs []string `json:"collectionIds"`
		}
		unmarshal(respBody, &parsed)
		n := len(parsed.CollectionIDs)
		mode := "public read"
		if idToken != "" {
			mode = "auth bypass via anonymous signup"
		}
		detail := fmt.Sprintf("%d root collections (%s)", n, mode)
		if n > 0 {
			names := make([]string, 0, min(5, n))
			for i := 0; i < min(5, n); i++ {
				names = append(names, parsed.CollectionIDs[i])
			}
			detail += ": " + strings.Join(names, ", ")
		}
		return cr("Firebase Firestore Public Read Access", "Firebase", StatusConfirmed, detail, respBody)
	}
	if code == 401 || code == 403 {
		return cr("Firebase Firestore Public Read Access", "Firebase", StatusForbidden, "Security rules deny read", respBody)
	}
	if code == 404 {
		return cr("Firebase Firestore Public Read Access", "Firebase", StatusForbidden, "No (default) Firestore database in project", respBody)
	}
	return httpError("Firebase Firestore Public Read Access", "Firebase", code, respBody)
}

const firestoreAuthPoCTemplate = `# 1. Sign up anonymously to get an idToken
TOKEN=$(curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}' -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)
# 2. List Firestore root collections with the token
curl -s -X POST "https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents:listCollectionIds?key={KEY}" -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"pageSize":100}'`

func checkFirebaseFirestore() ServiceCheck {
	return ServiceCheck{
		Desc: "Firestore (Firebase REST API) is readable without proper authorization, directly exposing application documents.",
		Name: "Firebase Firestore Public Read Access", Category: "Firebase", NeedsProject: true,
		PoC: `curl -s -X POST 'https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents:listCollectionIds?key={KEY}' -H 'Content-Type: application/json' -d '{"pageSize":100}'`,
		Run: func(key, projectID string) CheckResult {
			anon := firestoreListCollections(key, projectID, "")
			if anon.Status == StatusConfirmed {
				// Public listing without auth — intentional in some demo apps,
				// usually unintentional. Promote to Potential for manual review.
				anon.Status = StatusPotential
				anon.StatusS = StatusPotential.String()
				anon.Detail += " — public access; review collections for sensitive data"
			}
			return anon
		},
		RunAuth: func(key, projectID, idToken string) CheckResult {
			anon := firestoreListCollections(key, projectID, "")
			authed := firestoreListCollections(key, projectID, idToken)
			anonOK := anon.Status == StatusConfirmed
			authOK := authed.Status == StatusConfirmed
			// Auth-bypass case — rules required auth but anon-signup slipped past.
			if !anonOK && authOK {
				authed.Detail += " — rules require auth but anonymous-signup JWT bypasses them (likely misconfiguration)"
				authed.PoC = fillPoC(firestoreAuthPoCTemplate, key, projectID, "")
				return authed
			}
			// Public listing without auth — intentional in some demo apps.
			if anonOK {
				anon.Status = StatusPotential
				anon.StatusS = StatusPotential.String()
				anon.Detail += " — public access; review collections for sensitive data"
				return anon
			}
			if anon.Status == StatusForbidden {
				return anon
			}
			return authed
		},
	}
}

// ─── Write probes (Tier 5) ──────────────────────────────────────────────────
//
// These confirm WRITE access on Firebase Security Rules surfaces. They each
// write a small probe value, observe the response, and best-effort delete the
// probe on success. Write rules are normally stricter than read rules, so a
// success here is a much bigger finding than a successful read.

// firestoreWriteProbe creates a document at aiza_analyzer_probe/<ts>, then
// deletes it. Probe path is namespaced to avoid colliding with real data.
func firestoreWriteProbe(escKey, projectID, idToken string) CheckResult {
	docPath := fmt.Sprintf("aiza_analyzer_probe/probe-%d", time.Now().UnixNano())
	u := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s?key=%s",
		projectID, docPath, escKey)
	payload := []byte(`{"fields":{"probe":{"stringValue":"aiza-key-analyzer"}}}`)

	ctx, cancel := context.WithTimeout(context.Background(), Client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "PATCH", u, bytes.NewReader(payload))
	if err != nil {
		return cr("Firebase Firestore Unauthorized Write", "Firebase", StatusError, err.Error(), nil)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aiza-key-analyzer/1.0")
	if idToken != "" {
		req.Header.Set("Authorization", "Bearer "+idToken)
	}
	resp, err := Client.Do(req)
	if err != nil {
		return cr("Firebase Firestore Unauthorized Write", "Firebase", StatusError, err.Error(), nil)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 {
		// Best-effort cleanup
		dctx, dcancel := context.WithTimeout(context.Background(), Client.Timeout)
		defer dcancel()
		dreq, _ := http.NewRequestWithContext(dctx, "DELETE", u, nil)
		dreq.Header.Set("User-Agent", "aiza-key-analyzer/1.0")
		if idToken != "" {
			dreq.Header.Set("Authorization", "Bearer "+idToken)
		}
		dresp, derr := Client.Do(dreq)
		if derr == nil {
			dresp.Body.Close()
		}
		return cr("Firebase Firestore Unauthorized Write", "Firebase", StatusConfirmed,
			"Confirmed write access — probe doc created and deleted at "+docPath, respBody)
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return cr("Firebase Firestore Unauthorized Write", "Firebase", StatusForbidden, "Security rules deny write", respBody)
	}
	return httpError("Firebase Firestore Unauthorized Write", "Firebase", resp.StatusCode, respBody)
}

func checkFirebaseFirestoreWrite() ServiceCheck {
	return ServiceCheck{
		Desc: "Firestore Security Rules permit writes from this key/anonymous session, letting an attacker create or tamper with documents.",
		Name: "Firebase Firestore Unauthorized Write", Category: "Firebase", NeedsProject: true, NeedsAuth: true,
		PoC: `# 1. Get an idToken via anonymous signup
TOKEN=$(curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}' -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)
# 2. Create a doc at aiza_analyzer_probe/poc with the token
curl -s -X PATCH "https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/aiza_analyzer_probe/poc?key={KEY}" -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"fields":{"probe":{"stringValue":"poc"}}}'
# 3. Read it back to verify the write succeeded
curl -s "https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/aiza_analyzer_probe/poc?key={KEY}" -H "Authorization: Bearer ${TOKEN}"
# 4. Delete the probe doc to leave no trace
curl -s -X DELETE "https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/aiza_analyzer_probe/poc?key={KEY}" -H "Authorization: Bearer ${TOKEN}"`,
		RunAuth: func(key, projectID, idToken string) CheckResult {
			return firestoreWriteProbe(key, projectID, idToken)
		},
	}
}

// rtdbWriteProbe walks RTDB host candidates and PUTs a probe value, then
// best-effort deletes it. Returns the result and the matched host.
func rtdbWriteProbe(projectID, idToken string) (CheckResult, string) {
	hosts := rtdbHosts(projectID)
	var lastForbidden []byte
	for _, h := range hosts {
		probePath := fmt.Sprintf("aiza_analyzer_probe-%d", time.Now().UnixNano())
		u := fmt.Sprintf("https://%s/%s.json", h, probePath)
		if idToken != "" {
			u += "?auth=" + url.QueryEscape(idToken)
		}
		ctx, cancel := context.WithTimeout(context.Background(), Client.Timeout)
		req, err := http.NewRequestWithContext(ctx, "PUT", u, bytes.NewReader([]byte(`"aiza-key-analyzer"`)))
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "aiza-key-analyzer/1.0")
		resp, err := Client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		if resp.StatusCode == 200 {
			// Cleanup
			dctx, dcancel := context.WithTimeout(context.Background(), Client.Timeout)
			dreq, _ := http.NewRequestWithContext(dctx, "DELETE", u, nil)
			dreq.Header.Set("User-Agent", "aiza-key-analyzer/1.0")
			dresp, derr := Client.Do(dreq)
			dcancel()
			if derr == nil {
				dresp.Body.Close()
			}
			return cr("Firebase RTDB Unauthorized Write", "Firebase", StatusConfirmed,
				fmt.Sprintf("Confirmed write access — probe at %s/%s.json (created and deleted)", h, probePath), body), h
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			lastForbidden = body
		}
	}
	if lastForbidden != nil {
		return cr("Firebase RTDB Unauthorized Write", "Firebase", StatusForbidden, "Security rules deny write", lastForbidden), ""
	}
	return cr("Firebase RTDB Unauthorized Write", "Firebase", StatusForbidden, "No RTDB instance found", nil), ""
}

// checkRTDBRules probes /.settings/rules.json across the candidate RTDB hosts.
// In a hardened project this endpoint requires the legacy database-secret
// admin credential and returns 403 to any other caller. A 200 here means
// the project leaks its Realtime Database security rules to anonymous callers
// — that's a direct disclosure of the rules engine, which routinely reveals:
//   - the path structure of the database (which subtrees exist)
//   - which conditions the project considers "secure" (auth shape, claim
//     names, role checks)
//   - missing access control around specific paths (e.g. ".read": true on
//     a subtree the developer forgot)
//
// Anyone with the rules can target weak paths with surgical precision.
func checkRTDBRules() ServiceCheck {
	return ServiceCheck{
		Desc: "The Realtime Database .settings/rules endpoint is readable, disclosing the database's security rules and any misconfigurations in them.",
		Name: "RTDB Security Rules Disclosure", Category: "Firebase", NeedsProject: true,
		PoC: `# .settings/rules.json should be admin-only — a 200 leaks the project's
# Realtime DB security rules to anonymous callers (rules engine disclosure).
for h in {PROJECT}-default-rtdb.firebaseio.com \
         {PROJECT}-default-rtdb.europe-west1.firebasedatabase.app \
         {PROJECT}-default-rtdb.asia-southeast1.firebasedatabase.app \
         {PROJECT}.firebaseio.com; do
  echo -n "$h -> "
  curl -s -o /dev/null -w "%{http_code}\n" "https://${h}/.settings/rules.json"
done
# A 200 prints the project's RTDB security rules JSON.`,
		Run: func(key, projectID string) CheckResult {
			hosts := rtdbHosts(projectID)
			var disclosed *struct {
				host string
				body []byte
			}
			var sawForbidden bool
			var forbiddenHost string
			for _, h := range hosts {
				u := "https://" + h + "/.settings/rules.json"
				code, body, err := doGet(u)
				if err != nil {
					continue
				}
				if code == 200 {
					disclosed = &struct {
						host string
						body []byte
					}{host: h, body: body}
					break
				}
				if code == 401 || code == 403 {
					sawForbidden = true
					forbiddenHost = h
				}
				// 404 → no DB at this host, move on
			}
			if disclosed != nil {
				summary := strings.TrimSpace(string(disclosed.body))
				// Keep the in-table detail short; full rules go into RawJSON.
				if len(summary) > 220 {
					summary = summary[:220] + "…"
				}
				summary = strings.ReplaceAll(summary, "\n", " ")
				res := cr("RTDB Security Rules Disclosure", "Firebase", StatusConfirmed,
					fmt.Sprintf("RTDB security rules ANONYMOUSLY READABLE at %s — rules engine fully disclosed: %s",
						disclosed.host, summary),
					disclosed.body)
				// Point the PoC at the exact host that served the rules (may be a
				// regional / named-instance endpoint, not the default one).
				res.PoC = "curl -s 'https://" + disclosed.host + "/.settings/rules.json'"
				return res
			}
			if sawForbidden {
				return cr("RTDB Security Rules Disclosure", "Firebase", StatusNotVulnerable,
					"RTDB exists at "+forbiddenHost+" but /.settings/rules.json is properly gated (403)", nil)
			}
			return cr("RTDB Security Rules Disclosure", "Firebase", StatusNotVulnerable,
				"No RTDB instance found at the candidate hosts (rules-disclosure surface absent)", nil)
		},
	}
}

const rtdbWritePoCTemplate = `# 1. Get an idToken via anonymous signup
TOKEN=$(curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}' -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)
# 2. PUT a value at /aiza_analyzer_probe with the token
curl -s -X PUT "https://{HOST}/aiza_analyzer_probe.json?auth=${TOKEN}" -d '"poc"'
# 3. GET the same node back to verify the write
curl -s "https://{HOST}/aiza_analyzer_probe.json?auth=${TOKEN}"
# 4. DELETE the probe node to leave no trace
curl -s -X DELETE "https://{HOST}/aiza_analyzer_probe.json?auth=${TOKEN}"`

func checkFirebaseRTDBWrite() ServiceCheck {
	return ServiceCheck{
		Desc: "RTDB Security Rules permit writes from this key/anonymous session, letting an attacker inject or overwrite data.",
		Name: "Firebase RTDB Unauthorized Write", Category: "Firebase", NeedsProject: true, NeedsAuth: true,
		RunAuth: func(key, projectID, idToken string) CheckResult {
			result, host := rtdbWriteProbe(projectID, idToken)
			// Point the PoC at the exact host that accepted the write (the
			// matched host may be a regional / named-instance endpoint, not the
			// default firebaseio.com one).
			if result.Status == StatusConfirmed && host != "" {
				result.PoC = fillPoC(strings.ReplaceAll(rtdbWritePoCTemplate, "{HOST}", host), key, projectID, "")
			}
			return result
		},
	}
}

// storageWriteProbe uploads a tiny text object to each candidate bucket using
// the firebasestorage upload endpoint, then best-effort deletes on success.
//
// Diagnostics: we track *every* non-200 outcome (transport errors, unexpected
// status codes, denied responses) and surface them in the returned detail.
// This was added after a flaky-finding investigation: a silent `continue` on
// timeouts / unexpected statuses meant the finding appeared/disappeared
// across runs without any explanation. Now every failure mode is reported.
func storageWriteProbe(escKey, projectID, idToken string) CheckResult {
	buckets := []string{
		projectID + ".firebasestorage.app",
		projectID + ".appspot.com",
	}
	var lastForbidden []byte
	var lastForbiddenBucket string
	var transportErrors []string
	var unexpectedStatuses []string
	for _, bucket := range buckets {
		name := fmt.Sprintf("aiza_analyzer_probe-%d.txt", time.Now().UnixNano())
		u := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o?uploadType=media&name=%s&key=%s",
			bucket, url.QueryEscape(name), escKey)
		headers := map[string]string{"Content-Type": "text/plain"}
		if idToken != "" {
			headers["Authorization"] = "Bearer " + idToken
		}
		code, body, err := doCustomCtx(context.Background(), "POST", u, []byte("aiza-key-analyzer"), headers)
		if err != nil {
			transportErrors = append(transportErrors, bucket+": "+err.Error())
			continue
		}
		if code == 200 {
			// Cleanup the probe object — best-effort.
			delURL := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o/%s?key=%s",
				bucket, url.QueryEscape(name), escKey)
			delHeaders := map[string]string{}
			if idToken != "" {
				delHeaders["Authorization"] = "Bearer " + idToken
			}
			_, _, _ = doCustomCtx(context.Background(), "DELETE", delURL, nil, delHeaders)
			return cr("Firebase Storage Unauthorized Write", "Firebase", StatusConfirmed,
				fmt.Sprintf("Confirmed write access — uploaded and deleted %s in %s", name, bucket), body)
		}
		if code == 401 || code == 403 {
			lastForbidden = body
			lastForbiddenBucket = bucket
			continue
		}
		unexpectedStatuses = append(unexpectedStatuses, fmt.Sprintf("%s: HTTP %d", bucket, code))
	}
	// Failure diagnostics, ordered by interest to the operator.
	if lastForbidden != nil {
		return cr("Firebase Storage Unauthorized Write", "Firebase", StatusForbidden,
			"Security rules deny write on "+lastForbiddenBucket, lastForbidden)
	}
	if len(transportErrors) > 0 {
		return cr("Firebase Storage Unauthorized Write", "Firebase", StatusError,
			"Storage write probe failed (transport): "+strings.Join(transportErrors, "; ")+" — retry, increase -timeout, or check proxy", nil)
	}
	if len(unexpectedStatuses) > 0 {
		return cr("Firebase Storage Unauthorized Write", "Firebase", StatusError,
			"Storage write probe returned unexpected statuses: "+strings.Join(unexpectedStatuses, "; ")+" — re-run with -v to inspect bodies", nil)
	}
	return cr("Firebase Storage Unauthorized Write", "Firebase", StatusForbidden, "No Firebase Storage bucket found at the candidate suffixes", nil)
}

func checkFirebaseStorageWrite() ServiceCheck {
	return ServiceCheck{
		Desc: "Firebase Storage Security Rules permit uploads from this key/anonymous session, letting an attacker write objects (defacement, malware hosting, quota abuse).",
		Name: "Firebase Storage Unauthorized Write", Category: "Firebase", NeedsProject: true, NeedsAuth: true,
		PoC: `# 1. Get an idToken via anonymous signup
TOKEN=$(curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}' -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)
# 2. Upload a probe object (bucket name routes to the project; no API key needed for upload/read)
curl -s -X POST "https://firebasestorage.googleapis.com/v0/b/{PROJECT}.appspot.com/o?uploadType=media&name=aiza_poc.txt" -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: text/plain" --data-binary "poc"
# 3. Download the uploaded object back to verify the write
curl -s "https://firebasestorage.googleapis.com/v0/b/{PROJECT}.appspot.com/o/aiza_poc.txt?alt=media" -H "Authorization: Bearer ${TOKEN}"
# 4. Delete the probe object (DELETE requires the API key for routing)
curl -s -X DELETE "https://firebasestorage.googleapis.com/v0/b/{PROJECT}.appspot.com/o/aiza_poc.txt?key={KEY}" -H "Authorization: Bearer ${TOKEN}"`,
		RunAuth: func(key, projectID, idToken string) CheckResult {
			return storageWriteProbe(key, projectID, idToken)
		},
	}
}

// ─── Tier 2 — Firebase product info-disclosure probes ───────────────────────
//
// These follow the standard "list a project's resources via key" pattern.
// Most of them only succeed when the project has the relevant API enabled
// and the key isn't HTTP-referrer-restricted; even forbidden responses are
// useful confirmation that the service is in scope.

func checkFirebaseCrashlytics() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can reach Crashlytics APIs for the project, exposing crash and diagnostic data surfaces.",
		Name: "Firebase Crashlytics Access", Category: "Firebase", NeedsProject: true,
		PoC: "curl -s 'https://firebasecrashlytics.googleapis.com/v1/projects/{PROJECT}/apps?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebasecrashlytics.googleapis.com/v1/projects/%s/apps?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase Crashlytics Access", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Firebase Crashlytics Access", "Firebase", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase Crashlytics Access", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase Crashlytics Access", "Firebase", code, body)
		},
	}
}

func checkFirebaseAppDistribution() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can reach Firebase App Distribution, potentially exposing pre-release app binaries and tester information.",
		Name: "Firebase App Distribution Access", Category: "Firebase", NeedsProject: true,
		PoC: "curl -s 'https://firebaseappdistribution.googleapis.com/v1/projects/{PROJECT}/apps?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebaseappdistribution.googleapis.com/v1/projects/%s/apps?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase App Distribution Access", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Apps []struct {
						AppID string `json:"appId"`
					} `json:"apps"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d App Distribution apps (may leak builds / tester emails)", len(resp.Apps))
				if len(resp.Apps) > 0 {
					ids := make([]string, 0, min(5, len(resp.Apps)))
					for i := 0; i < min(5, len(resp.Apps)); i++ {
						ids = append(ids, resp.Apps[i].AppID)
					}
					detail += ": " + strings.Join(ids, ", ")
				}
				return cr("Firebase App Distribution Access", "Firebase", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase App Distribution Access", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase App Distribution Access", "Firebase", code, body)
		},
	}
}

func checkFirebaseInAppMessaging() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can reach Firebase In-App Messaging APIs, exposing campaign configuration surfaces.",
		Name: "Firebase In-App Messaging Access", Category: "Firebase", NeedsProject: true,
		PoC: "curl -s 'https://firebaseinappmessaging.googleapis.com/v1/projects/{PROJECT}/campaigns?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebaseinappmessaging.googleapis.com/v1/projects/%s/campaigns?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase In-App Messaging Access", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Firebase In-App Messaging Access", "Firebase", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase In-App Messaging Access", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase In-App Messaging Access", "Firebase", code, body)
		},
	}
}

func checkFirebaseABTesting() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can reach Firebase A/B Testing APIs, exposing experiment configuration.",
		Name: "Firebase A/B Testing Access", Category: "Firebase", NeedsProject: true,
		PoC: "curl -s 'https://firebaseabt.googleapis.com/v1/projects/{PROJECT}/experiments?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebaseabt.googleapis.com/v1/projects/%s/experiments?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase A/B Testing Access", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Firebase A/B Testing Access", "Firebase", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase A/B Testing Access", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase A/B Testing Access", "Firebase", code, body)
		},
	}
}

func checkFirebaseML() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Firebase ML custom models, revealing (and potentially allowing download of) deployed model artifacts.",
		Name: "Firebase ML Model Enumeration", Category: "Firebase", NeedsProject: true,
		PoC: "curl -s 'https://firebaseml.googleapis.com/v1beta2/projects/{PROJECT}/models?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebaseml.googleapis.com/v1beta2/projects/%s/models?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase ML Model Enumeration", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Models []struct {
						DisplayName string `json:"displayName"`
					} `json:"models"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d Firebase ML models (may include download URLs)", len(resp.Models))
				if len(resp.Models) > 0 {
					names := make([]string, 0, min(5, len(resp.Models)))
					for i := 0; i < min(5, len(resp.Models)); i++ {
						names = append(names, resp.Models[i].DisplayName)
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Firebase ML Model Enumeration", "Firebase", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase ML Model Enumeration", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase ML Model Enumeration", "Firebase", code, body)
		},
	}
}

func checkFirebaseDataConnect() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can reach Firebase Data Connect APIs, exposing the managed GraphQL/SQL data layer surface.",
		Name: "Firebase Data Connect Access", Category: "Firebase", NeedsProject: true,
		PoC: "curl -s 'https://firebasedataconnect.googleapis.com/v1beta/projects/{PROJECT}/locations/-/services?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebasedataconnect.googleapis.com/v1beta/projects/%s/locations/-/services?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase Data Connect Access", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Firebase Data Connect Access", "Firebase", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase Data Connect Access", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase Data Connect Access", "Firebase", code, body)
		},
	}
}

func checkFirebaseAppHosting() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Firebase App Hosting backends, revealing deployed full-stack web properties.",
		Name: "Firebase App Hosting Enumeration", Category: "Firebase", NeedsProject: true,
		PoC: "curl -s 'https://firebaseapphosting.googleapis.com/v1beta/projects/{PROJECT}/locations/-/backends?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebaseapphosting.googleapis.com/v1beta/projects/%s/locations/-/backends?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase App Hosting Enumeration", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Firebase App Hosting Enumeration", "Firebase", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase App Hosting Enumeration", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase App Hosting Enumeration", "Firebase", code, body)
		},
	}
}

// ─── Common-path guessing on Security-Rules surfaces ────────────────────────
//
// When list endpoints are denied (the usual case for well-configured rules),
// specific paths can still be readable because rules can be path-specific.
// We probe a list of common collection/path names and report any that
// respond with content. Same anonymous-vs-authenticated severity logic as
// the read checks: anonymous hit → Potential (public, intentional?), auth
// bypass → Vulnerable.

var commonFirestoreCollections = []string{
	"users", "Users", "accounts", "customers", "members", "profiles",
	"posts", "messages", "chats", "conversations", "comments",
	"orders", "transactions", "payments", "carts", "invoices",
	"products", "items", "inventory", "catalog",
	"admin", "admins", "config", "configs", "settings", "secrets", "private",
	"notifications", "logs", "events", "audit",
	"sessions", "tokens", "apikeys", "api_keys",
}

func firestoreReadCollection(escKey, projectID, idToken, collection string) (status Status, count int, body []byte) {
	u := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s?key=%s&pageSize=3",
		projectID, url.PathEscape(collection), escKey)
	ctx, cancel := context.WithTimeout(context.Background(), Client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return StatusError, 0, nil
	}
	req.Header.Set("User-Agent", "aiza-key-analyzer/1.0")
	if idToken != "" {
		req.Header.Set("Authorization", "Bearer "+idToken)
	}
	resp, err := Client.Do(req)
	if err != nil {
		return StatusError, 0, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 {
		var parsed struct {
			Documents []json.RawMessage `json:"documents"`
		}
		unmarshal(respBody, &parsed)
		return StatusConfirmed, len(parsed.Documents), respBody
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
		return StatusForbidden, 0, respBody
	}
	return StatusError, 0, respBody
}

func checkFirestoreCommonPaths() ServiceCheck {
	return ServiceCheck{
		Desc: "Probing well-known collection names returns data without proper authorization, confirming Firestore content is publicly readable at common paths.",
		Name: "Firestore Public Collection Access (Common Paths)", Category: "Firebase", NeedsProject: true,
		PoC: `# Read a specific Firestore collection (replace {COLLECTION} with one of the names from the detail above)
curl -s "https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/{COLLECTION}?key={KEY}&pageSize=3"`,
		Run: func(key, projectID string) CheckResult {
			anonHits := []string{}
			var mu sync.Mutex
			parallelProbe(commonFirestoreCollections, 8, func(col string) {
				if s, n, _ := firestoreReadCollection(key, projectID, "", col); s == StatusConfirmed {
					mu.Lock()
					anonHits = append(anonHits, fmt.Sprintf("%s (%d docs)", col, n))
					mu.Unlock()
				}
			})
			if len(anonHits) > 0 {
				return cr("Firestore Public Collection Access (Common Paths)", "Firebase", StatusPotential,
					"Public read on common collections: "+strings.Join(anonHits, ", ")+" — review for sensitive data", nil)
			}
			return cr("Firestore Public Collection Access (Common Paths)", "Firebase", StatusForbidden, "No common collection name is anonymously readable", nil)
		},
		RunAuth: func(key, projectID, idToken string) CheckResult {
			anonReadable := map[string]int{}
			authReadable := map[string]int{}
			var mu sync.Mutex
			parallelProbe(commonFirestoreCollections, 8, func(col string) {
				anonS, anonN, _ := firestoreReadCollection(key, projectID, "", col)
				authS, authN, _ := firestoreReadCollection(key, projectID, idToken, col)
				mu.Lock()
				defer mu.Unlock()
				if anonS == StatusConfirmed {
					anonReadable[col] = anonN
				}
				if authS == StatusConfirmed {
					authReadable[col] = authN
				}
			})
			// auth-only readable = real bypass
			var bypass []string
			for col, n := range authReadable {
				if _, anon := anonReadable[col]; !anon {
					bypass = append(bypass, fmt.Sprintf("%s (%d docs)", col, n))
				}
			}
			if len(bypass) > 0 {
				return cr("Firestore Public Collection Access (Common Paths)", "Firebase", StatusConfirmed,
					"Auth-bypass read on common collections (rules require auth, anon-signup JWT bypasses): "+strings.Join(bypass, ", "), nil)
			}
			if len(anonReadable) > 0 {
				var parts []string
				for col, n := range anonReadable {
					parts = append(parts, fmt.Sprintf("%s (%d docs)", col, n))
				}
				return cr("Firestore Public Collection Access (Common Paths)", "Firebase", StatusPotential,
					"Public read on common collections: "+strings.Join(parts, ", ")+" — review for sensitive data", nil)
			}
			return cr("Firestore Public Collection Access (Common Paths)", "Firebase", StatusForbidden, "No common collection name is readable", nil)
		},
	}
}

var commonRTDBPaths = []string{
	"users", "Users", "accounts", "profiles",
	"posts", "messages", "chats", "conversations",
	"orders", "transactions", "products",
	"admin", "admins", "config", "settings", "secrets", "private", "public", "shared",
	"notifications", "logs", "audit", "sessions",
}

func rtdbReadPath(host, idToken, path string) (status Status, contentLen int) {
	u := "https://" + host + "/" + path + ".json"
	if idToken != "" {
		u += "?auth=" + url.QueryEscape(idToken)
	}
	code, body, err := doGet(u)
	if err != nil {
		return StatusError, 0
	}
	if code == 200 {
		bs := strings.TrimSpace(string(body))
		// "null" body means the key exists but value is empty — RTDB returns
		// "null" for missing nodes too. Treat null as no-content.
		if bs == "null" || bs == "" {
			return StatusForbidden, 0
		}
		return StatusConfirmed, len(body)
	}
	if code == 401 || code == 403 {
		return StatusForbidden, 0
	}
	return StatusError, 0
}

// rtdbRootReadable returns true when GET /.json (root) on any candidate host
// succeeds — meaning the whole database is publicly readable. In that case
// every common-path probe would also succeed, making RTDB Common Paths a
// duplicate of the main Firebase RTDB row.
func rtdbRootReadable(projectID, idToken string) bool {
	result, _ := rtdbProbe(projectID, idToken, "anon")
	return result.Status == StatusConfirmed
}

func checkRTDBCommonPaths() ServiceCheck {
	return ServiceCheck{
		Desc: "Probing well-known node paths returns data without proper authorization, confirming RTDB content is publicly readable at common paths.",
		Name: "RTDB Public Node Access (Common Paths)", Category: "Firebase", NeedsProject: true,
		PoC: `# Read a specific RTDB node (replace {PATH} with one of the names from the detail above)
curl -s 'https://{PROJECT}-default-rtdb.firebaseio.com/{PATH}.json'`,
		Run: func(key, projectID string) CheckResult {
			// Suppress redundancy: if root /.json is publicly readable, every
			// path under it is too — that's already on the "Firebase RTDB Public Read Access" row.
			if rtdbRootReadable(projectID, "") {
				return cr("RTDB Public Node Access (Common Paths)", "Firebase", StatusNotVulnerable,
					"Skipped — RTDB root /.json is publicly readable (covered by Firebase RTDB finding)", nil)
			}
			hosts := rtdbHosts(projectID)
			var hits []string
			for _, h := range hosts {
				var local []string
				var mu sync.Mutex
				parallelProbe(commonRTDBPaths, 8, func(p string) {
					if s, n := rtdbReadPath(h, "", p); s == StatusConfirmed {
						mu.Lock()
						local = append(local, fmt.Sprintf("%s/%s (%d bytes)", h, p, n))
						mu.Unlock()
					}
				})
				if len(local) > 0 {
					hits = local
					break // found a working host
				}
			}
			if len(hits) > 0 {
				return cr("RTDB Public Node Access (Common Paths)", "Firebase", StatusPotential,
					"Public read on specific paths (root denied): "+strings.Join(hits, ", ")+" — path-scoped rules grant access to these nodes; review for sensitive data", nil)
			}
			return cr("RTDB Public Node Access (Common Paths)", "Firebase", StatusForbidden, "No common RTDB path is anonymously readable", nil)
		},
		RunAuth: func(key, projectID, idToken string) CheckResult {
			// Suppress redundancy when root is accessible either anonymously
			// or via the anonymous-signup JWT.
			if rtdbRootReadable(projectID, "") || rtdbRootReadable(projectID, idToken) {
				return cr("RTDB Public Node Access (Common Paths)", "Firebase", StatusNotVulnerable,
					"Skipped — RTDB root /.json is readable (covered by Firebase RTDB finding)", nil)
			}
			hosts := rtdbHosts(projectID)
			var workingHost string
			var anonHits []string
			var authHits []string
			for _, h := range hosts {
				var localAnon, localAuth []string
				var mu sync.Mutex
				parallelProbe(commonRTDBPaths, 8, func(p string) {
					anonS, anonN := rtdbReadPath(h, "", p)
					authS, authN := rtdbReadPath(h, idToken, p)
					mu.Lock()
					defer mu.Unlock()
					if anonS == StatusConfirmed {
						localAnon = append(localAnon, fmt.Sprintf("%s (%d bytes)", p, anonN))
					}
					if authS == StatusConfirmed {
						localAuth = append(localAuth, fmt.Sprintf("%s (%d bytes)", p, authN))
					}
				})
				if len(localAnon) > 0 || len(localAuth) > 0 {
					workingHost = h
					anonHits = localAnon
					authHits = localAuth
					break
				}
			}
			anonSet := map[string]bool{}
			for _, h := range anonHits {
				anonSet[h] = true
			}
			var bypass []string
			for _, h := range authHits {
				if !anonSet[h] {
					bypass = append(bypass, h)
				}
			}
			if len(bypass) > 0 {
				return cr("RTDB Public Node Access (Common Paths)", "Firebase", StatusConfirmed,
					fmt.Sprintf("Auth-bypass read on %s specific paths (root denied): %s — path-scoped rules require auth but anon-signup JWT bypasses", workingHost, strings.Join(bypass, ", ")), nil)
			}
			if len(anonHits) > 0 {
				return cr("RTDB Public Node Access (Common Paths)", "Firebase", StatusPotential,
					fmt.Sprintf("Public read on %s specific paths (root denied): %s — review nodes for sensitive data", workingHost, strings.Join(anonHits, ", ")), nil)
			}
			return cr("RTDB Public Node Access (Common Paths)", "Firebase", StatusForbidden, "No common RTDB path is readable", nil)
		},
	}
}

var commonStoragePrefixes = []string{
	"avatars/", "profile_photos/", "profile_pictures/",
	"user_uploads/", "uploads/", "users/",
	"private/", "admin/", "secrets/", "config/", "configs/",
	"backups/", "backup/",
	"documents/", "files/", "downloads/",
	"public/", "shared/",
	"media/", "images/", "videos/", "audio/",
}

func storageListPrefix(escKey, bucket, prefix, idToken string) (status Status, count int, names []string) {
	u := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o?prefix=%s&maxResults=20", bucket, url.QueryEscape(prefix))
	if escKey != "" {
		u += "&key=" + escKey
	}
	headers := map[string]string{}
	if idToken != "" {
		headers["Authorization"] = "Bearer " + idToken
	}
	code, respBody, err := doCustomCtx(context.Background(), "GET", u, nil, headers)
	if err != nil {
		return StatusError, 0, nil
	}
	if code == 200 {
		var parsed struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		}
		unmarshal(respBody, &parsed)
		if len(parsed.Items) == 0 {
			return StatusForbidden, 0, nil
		}
		ns := make([]string, 0, len(parsed.Items))
		for _, it := range parsed.Items {
			ns = append(ns, it.Name)
		}
		return StatusConfirmed, len(parsed.Items), ns
	}
	if code == 401 || code == 403 {
		return StatusForbidden, 0, nil
	}
	return StatusError, 0, nil
}

// storageObjFetch returns a bounded fetch for "bucket/name" candidates against
// the Firebase Storage download endpoint, for use with scanObjectsForSecrets.
func storageObjFetch(escKey, idToken string) func(string) []byte {
	return func(c string) []byte {
		i := strings.IndexByte(c, '/')
		if i < 0 {
			return nil
		}
		bucket, name := c[:i], c[i+1:]
		u := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o/%s?alt=media&key=%s",
			bucket, url.QueryEscape(name), escKey)
		h := map[string]string{}
		if idToken != "" {
			h["Authorization"] = "Bearer " + idToken
		}
		code, b, err := doGetCapped(context.Background(), u, h, scanRangeBytes)
		if err != nil || code/100 != 2 {
			return nil
		}
		return b
	}
}

// storageRootReadable returns true when listing /o (no prefix) succeeds on
// any of the candidate buckets. When it does, every prefix probe would also
// succeed, making Storage Common Paths a redundant duplicate of Firebase
// Storage. We use this to suppress the Common-Paths row in that case.
func storageRootReadable(escKey, projectID, idToken string) bool {
	status, _, _, _ := firebaseStorageList(escKey, projectID, idToken)
	return status == StatusConfirmed
}

func checkStorageCommonPaths() ServiceCheck {
	return ServiceCheck{
		Desc: "Probing well-known object prefixes returns listings without proper authorization, confirming Storage content is publicly accessible at common paths.",
		Name: "Storage Public Listing (Common Paths)", Category: "Firebase", NeedsProject: true,
		PoC: `# List objects under a specific Storage prefix (replace {PREFIX})
curl -s 'https://firebasestorage.googleapis.com/v0/b/{PROJECT}.appspot.com/o?prefix={PREFIX}'`,
		Run: func(key, projectID string) CheckResult {
			// Suppress redundancy: if /o lists publicly, every prefix probe
			// would too — that case is already on the "Firebase Storage Public Listing" row.
			if storageRootReadable(key, projectID, "") {
				return cr("Storage Public Listing (Common Paths)", "Firebase", StatusNotVulnerable,
					"Skipped — root listing on bucket /o already public (covered by Firebase Storage finding)", nil)
			}
			buckets := []string{projectID + ".appspot.com", projectID + ".firebasestorage.app"}
			var hits, candidates []string
			for _, b := range buckets {
				var local, localCand []string
				var mu sync.Mutex
				parallelProbe(commonStoragePrefixes, 8, func(p string) {
					if s, n, names := storageListPrefix(key, b, p, ""); s == StatusConfirmed {
						mu.Lock()
						local = append(local, fmt.Sprintf("%s/%s (%d items)", b, p, n))
						for _, nm := range names {
							localCand = append(localCand, b+"/"+nm)
						}
						mu.Unlock()
					}
				})
				if len(local) > 0 {
					hits = local
					candidates = localCand
					break
				}
			}
			if len(hits) > 0 {
				res := cr("Storage Public Listing (Common Paths)", "Firebase", StatusPotential,
					"Public-readable prefixes (root denied): "+strings.Join(hits, ", ")+" — path-scoped rules grant access to specific prefixes; review listed objects", nil)
				return mergeSecretHits(res, scanObjectsForSecrets(candidates, storageObjFetch(key, "")), "STORAGE OBJECTS")
			}
			return cr("Storage Public Listing (Common Paths)", "Firebase", StatusForbidden, "No common Storage prefix is anonymously listable", nil)
		},
		RunAuth: func(key, projectID, idToken string) CheckResult {
			// Same suppression: if root is readable (anon or auth), the
			// per-prefix detail isn't new — Firebase Storage already covers it.
			if storageRootReadable(key, projectID, "") || storageRootReadable(key, projectID, idToken) {
				return cr("Storage Public Listing (Common Paths)", "Firebase", StatusNotVulnerable,
					"Skipped — root listing on bucket /o is accessible (covered by Firebase Storage finding)", nil)
			}
			buckets := []string{projectID + ".appspot.com", projectID + ".firebasestorage.app"}
			var workingBucket string
			var anonHits, authHits, anonCand, authCand []string
			for _, b := range buckets {
				var localAnon, localAuth, localAnonCand, localAuthCand []string
				var mu sync.Mutex
				parallelProbe(commonStoragePrefixes, 8, func(p string) {
					anonS, anonN, anonNames := storageListPrefix(key, b, p, "")
					authS, authN, authNames := storageListPrefix(key, b, p, idToken)
					mu.Lock()
					defer mu.Unlock()
					if anonS == StatusConfirmed {
						localAnon = append(localAnon, fmt.Sprintf("%s (%d)", p, anonN))
						for _, nm := range anonNames {
							localAnonCand = append(localAnonCand, b+"/"+nm)
						}
					}
					if authS == StatusConfirmed {
						localAuth = append(localAuth, fmt.Sprintf("%s (%d)", p, authN))
						for _, nm := range authNames {
							localAuthCand = append(localAuthCand, b+"/"+nm)
						}
					}
				})
				if len(localAnon) > 0 || len(localAuth) > 0 {
					workingBucket = b
					anonHits = localAnon
					authHits = localAuth
					anonCand = localAnonCand
					authCand = localAuthCand
					break
				}
			}
			anonSet := map[string]bool{}
			for _, h := range anonHits {
				anonSet[h] = true
			}
			var bypass []string
			for _, h := range authHits {
				if !anonSet[h] {
					bypass = append(bypass, h)
				}
			}
			if len(bypass) > 0 {
				res := cr("Storage Public Listing (Common Paths)", "Firebase", StatusConfirmed,
					fmt.Sprintf("Auth-bypass listings on %s prefixes (root denied): %s — path-scoped rules require auth but anon-signup JWT bypasses", workingBucket, strings.Join(bypass, ", ")), nil)
				return mergeSecretHits(res, scanObjectsForSecrets(authCand, storageObjFetch(key, idToken)), "STORAGE OBJECTS")
			}
			if len(anonHits) > 0 {
				res := cr("Storage Public Listing (Common Paths)", "Firebase", StatusPotential,
					fmt.Sprintf("Public-readable prefixes on %s (root denied): %s — review listed objects", workingBucket, strings.Join(anonHits, ", ")), nil)
				return mergeSecretHits(res, scanObjectsForSecrets(anonCand, storageObjFetch(key, "")), "STORAGE OBJECTS")
			}
			return cr("Storage Public Listing (Common Paths)", "Firebase", StatusForbidden, "No common Storage prefix is readable", nil)
		},
	}
}

// firebaseInitConfig mirrors the fields Firebase Hosting serves at the public
// reserved URL /__/firebase/init.json — the same firebaseConfig object the web
// SDK embeds. It always carries the project's web appId, which is the missing
// ingredient for the Remote Config client fetch below.
type firebaseInitConfig struct {
	APIKey            string `json:"apiKey"`
	AppID             string `json:"appId"`
	AuthDomain        string `json:"authDomain"`
	DatabaseURL       string `json:"databaseURL"`
	LocationID        string `json:"locationId"`
	MeasurementID     string `json:"measurementId"`
	MessagingSenderID string `json:"messagingSenderId"`
	ProjectID         string `json:"projectId"`
	StorageBucket     string `json:"storageBucket"`
	VapidKey          string `json:"vapidKey"`
}

// initJSONCache memoizes init.json fetches per project slug. The Remote Config,
// Web Config and RTDB-host checks all need this same static file, so without a
// cache a single key triggers ~6 fetches of it; with the cache it's at most one
// network round-trip per project per run. Slugs are project-specific, so the
// cache is safe within and across keys (negative results are cached too, so a
// project with no Hosting domain isn't re-probed by every caller).
var initJSONCache sync.Map // slug -> initJSONEntry

type initJSONEntry struct {
	cfg  firebaseInitConfig
	body []byte
	ok   bool
}

// fetchFirebaseInitJSON GETs the public Firebase Hosting reserved-URL config for
// a project slug. Firebase serves /__/firebase/init.json on both the
// .firebaseapp.com auth domain and the .web.app hosting domain (no auth, no key
// needed), so we try both and return on the first 200 that carries an appId.
func fetchFirebaseInitJSON(slug string) (cfg firebaseInitConfig, body []byte, ok bool) {
	if v, hit := initJSONCache.Load(slug); hit {
		e := v.(initJSONEntry)
		return e.cfg, e.body, e.ok
	}
	var entry initJSONEntry
	for _, host := range []string{slug + ".firebaseapp.com", slug + ".web.app"} {
		code, b, err := doGet("https://" + host + "/__/firebase/init.json")
		if err != nil || code != 200 {
			continue
		}
		if json.Unmarshal(b, &entry.cfg) == nil && entry.cfg.AppID != "" {
			entry.body, entry.ok = b, true
			break
		}
	}
	initJSONCache.Store(slug, entry)
	return entry.cfg, entry.body, entry.ok
}

// firebaseInstall registers a Firebase Installation for the given app and
// returns the FIS auth token + installation id (fid). The Remote Config client
// fetch endpoint authenticates the *installation* with this token while the API
// key authorizes project access. Mirrors the installations probe in discovery.go.
func firebaseInstall(projectNumber, appID, key string) (token, fid string, err error) {
	u := "https://firebaseinstallations.googleapis.com/v1/projects/" + projectNumber + "/installations"
	payload, _ := json.Marshal(map[string]interface{}{
		"appId": appID, "authVersion": "FIS_v2", "sdkVersion": "w:0.6.4", "fid": "",
	})
	code, resp, err := doCustomCtx(context.Background(), "POST", u, payload, map[string]string{
		"x-goog-api-key": key,
		"Content-Type":   "application/json",
	})
	if err != nil {
		return "", "", err
	}
	if code != 200 {
		return "", "", fmt.Errorf("installations HTTP %d", code)
	}
	var parsed struct {
		FID       string `json:"fid"`
		AuthToken struct {
			Token string `json:"token"`
		} `json:"authToken"`
	}
	if json.Unmarshal(resp, &parsed) != nil || parsed.AuthToken.Token == "" {
		return "", "", fmt.Errorf("installations: no auth token in response")
	}
	return parsed.AuthToken.Token, parsed.FID, nil
}

// checkFirebaseRemoteConfigFetch probes the CLIENT Remote Config endpoint
// (namespaces/firebase:fetch) — the one the mobile/web SDKs actually use, which
// accepts API-key auth — rather than the management /remoteConfig endpoint,
// which rejects API keys outright (OAuth-only). A 200 returns the real config
// values delivered to every install: feature flags, backend URLs, and any
// secrets operators parked in config. The endpoint needs the project NUMBER plus
// an appId; the appId is auto-discovered from the public Hosting init.json, and
// when it can't be found the check silently skips (no appId fallback).
func checkFirebaseRemoteConfigFetch() ServiceCheck {
	const name = "Firebase Remote Config Possible Secret Leak"
	return ServiceCheck{
		Desc: "The key can fetch the project's client-delivered Remote Config via the SDK fetch endpoint. Remote Config is public by design, so this is surfaced only when the values appear to contain a secret operators wrongly embedded (e.g. a third-party API key or token) — review the flagged values before reporting.",
		Name: name, Category: "Firebase", NeedsProject: true, NeedsProjectNumber: true,
		RunWithNumber: func(key, projectID, projectNumber string) CheckResult {
			// The client fetch needs the project's appId. We auto-discover it
			// from the public Hosting init.json; if that isn't available there's
			// no other source, so silently skip (NotVulnerable is hidden by
			// default and stays out of the findings report).
			cfg, _, ok := fetchFirebaseInitJSON(projectID)
			if !ok || cfg.AppID == "" {
				return cr(name, "Firebase", StatusNotVulnerable,
					"appId not auto-discoverable (no public Hosting init.json) — Remote Config client fetch skipped", nil)
			}
			appID := cfg.AppID

			token, fid, err := firebaseInstall(projectNumber, appID, key)
			if err != nil {
				return cr(name, "Firebase", StatusForbidden,
					"Could not register a Firebase Installation for appId "+appID+" ("+err.Error()+")", nil)
			}

			u := "https://firebaseremoteconfig.googleapis.com/v1/projects/" + projectNumber + "/namespaces/firebase:fetch"
			reqBody, _ := json.Marshal(map[string]interface{}{"appId": appID, "appInstanceId": fid})
			code, resp, err := doCustomCtx(context.Background(), "POST", u, reqBody, map[string]string{
				"X-Goog-Api-Key":                     key,
				"X-Goog-Firebase-Installations-Auth": token,
				"Content-Type":                       "application/json",
			})
			if err != nil {
				return cr(name, "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var parsed struct {
					Entries map[string]string `json:"entries"`
				}
				unmarshal(resp, &parsed)
				keys := make([]string, 0, len(parsed.Entries))
				for k := range parsed.Entries {
					keys = append(keys, k)
				}
				sort.Strings(keys)

				// RC is public-by-design: a successful read is informational on
				// its own. It only becomes a finding when a value looks like a
				// real secret operators misplaced here — detected via the
				// secret-pattern scan over values plus a secret-named-param
				// heuristic (guarded so boolean feature flags don't trip).
				secretHits := scanForSecrets(resp)
				var suspectParams []string
				for _, k := range keys {
					if looksSecretParam(k, parsed.Entries[k]) {
						suspectParams = append(suspectParams, k)
					}
				}

				if len(secretHits) == 0 && len(suspectParams) == 0 {
					// By-design case (incl. empty config) — not a finding. Detail
					// still records the surface for -v / audit.
					detail := "Client fetch endpoint accepts the key (appId " + appID + ") but the project has no Remote Config parameters configured"
					if len(keys) > 0 {
						detail = fmt.Sprintf("%d Remote Config parameters readable via the client fetch endpoint (appId %s) — client-delivered config, public by design, no embedded secrets detected", len(keys), appID)
					}
					return cr(name, "Firebase", StatusNotVulnerable, detail, resp)
				}

				// Something looks sensitive → Potential (needs human review; a
				// real-looking key in RC may still be an intentionally-public
				// client credential).
				detail := fmt.Sprintf("%d Remote Config parameters readable (appId %s) — POSSIBLE EMBEDDED SECRET, review", len(keys), appID)
				if len(secretHits) > 0 {
					detail += "; secret patterns in values: " + strings.Join(secretHits, ", ")
				}
				if len(suspectParams) > 0 {
					shown := suspectParams
					if len(shown) > 8 {
						shown = shown[:8]
					}
					detail += "; secret-named params: " + strings.Join(shown, ", ")
				}
				result := cr(name, "Firebase", StatusPotential, detail, resp)
				result.PoC = fmt.Sprintf(`# 1. Register a Firebase Installation to obtain a FIS auth token (appId from %s.firebaseapp.com/__/firebase/init.json)
INSTALL=$(curl -s -X POST 'https://firebaseinstallations.googleapis.com/v1/projects/%s/installations' -H 'x-goog-api-key: %s' -H 'Content-Type: application/json' -d '{"appId":"%s","authVersion":"FIS_v2","sdkVersion":"w:0.6.4"}')
FID=$(echo "$INSTALL" | jq -r .fid); TOKEN=$(echo "$INSTALL" | jq -r .authToken.token)
# 2. Fetch the client-delivered Remote Config
curl -s -X POST 'https://firebaseremoteconfig.googleapis.com/v1/projects/%s/namespaces/firebase:fetch' -H 'X-Goog-Api-Key: %s' -H "X-Goog-Firebase-Installations-Auth: ${TOKEN}" -H 'Content-Type: application/json' -d '{"appId":"%s","appInstanceId":"'"${FID}"'"}'`,
					projectID, projectNumber, key, appID, projectNumber, key, appID)
				return result
			}
			if code == 400 && isInvalidKeyResponse(resp) {
				return cr(name, "Firebase", StatusForbidden, "Key rejected for Remote Config", resp)
			}
			if code == 401 || code == 403 {
				return cr(name, "Firebase", StatusForbidden, "Key valid, Remote Config client fetch denied", resp)
			}
			return httpError(name, "Firebase", code, resp)
		},
	}
}

// checkFirebaseWebConfig flags the public Hosting init.json only when it carries
// a value BEYOND the standard public web config (apiKey/appId/etc., which are
// public by design). Those expected fields are stripped before scanning, so the
// always-present public apiKey never trips a finding — we only report a real
// embedded secret.
func checkFirebaseWebConfig() ServiceCheck {
	const name = "Firebase Web Config Secret Exposure"
	return ServiceCheck{
		Desc: "The project's public Firebase Hosting config (/__/firebase/init.json) exposes a value beyond the standard public web config, indicating an embedded secret.",
		Name: name, Category: "Firebase", NeedsProject: true,
		PoC: "curl -s 'https://{PROJECT}.firebaseapp.com/__/firebase/init.json'",
		Run: func(key, projectID string) CheckResult {
			_, body, ok := fetchFirebaseInitJSON(projectID)
			if !ok {
				return cr(name, "Firebase", StatusForbidden,
					"No public init.json served (project has no default Hosting/auth domain)", nil)
			}
			var raw map[string]json.RawMessage
			if unmarshal(body, &raw) != nil {
				return cr(name, "Firebase", StatusError, "init.json is not a JSON object", body)
			}
			known := map[string]bool{
				"apiKey": true, "appId": true, "authDomain": true, "databaseURL": true,
				"locationId": true, "measurementId": true, "messagingSenderId": true,
				"projectId": true, "storageBucket": true, "vapidKey": true,
			}
			var extraKeys []string
			var extra strings.Builder
			for k, v := range raw {
				if known[k] {
					continue
				}
				extraKeys = append(extraKeys, k)
				extra.Write(v)
				extra.WriteByte('\n')
			}
			if hits := scanForSecrets([]byte(extra.String())); len(hits) > 0 {
				sort.Strings(extraKeys)
				return cr(name, "Firebase", StatusPotential,
					"init.json exposes non-standard field(s) "+strings.Join(extraKeys, ", ")+" containing: "+strings.Join(hits, ", ")+" — review (publicly readable)", body)
			}
			return cr(name, "Firebase", StatusNotVulnerable,
				"init.json contains only the standard public web config (no embedded secrets)", body)
		},
	}
}

func check4_25() ServiceCheck {
	return ServiceCheck{
		Desc: "The key is accepted by the FCM send API (validated via dry-run), letting an attacker send push notifications to the app's users (spam/phishing).",
		Name: "Firebase Cloud Messaging Send Abuse", Category: "Firebase", NeedsProject: true,
		PoC: `curl -s -X POST 'https://fcm.googleapis.com/v1/projects/{PROJECT}/messages:send?key={KEY}' -H 'Content-Type: application/json' -d '{"validate_only":true,"message":{"topic":"test","notification":{"title":"PoC"}}}'`,
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send?key=%s", projectID, key)
			payload := map[string]interface{}{
				"validate_only": true,
				"message": map[string]interface{}{
					"topic": "test",
					"notification": map[string]interface{}{
						"title": "PoC",
					},
				},
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Firebase Cloud Messaging Send Abuse", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Firebase Cloud Messaging Send Abuse", "Firebase", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase Cloud Messaging Send Abuse", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase Cloud Messaging Send Abuse", "Firebase", code, body)
		},
	}
}
