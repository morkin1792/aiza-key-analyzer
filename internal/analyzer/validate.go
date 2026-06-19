package analyzer

import (
	"net/url"
	"strings"
	"sync"
	"time"
)

// anonSignupPayload / emailSignupPayload are the curl `-d` bodies for the two
// signup flavors. They appear (byte-identical) in every auth-bypass PoC, so a
// single swap converts an anonymous-signup PoC into an email/password one.
const (
	anonSignupPayload  = `-d '{"returnSecureToken":true}'`
	emailSignupPayload = `-d '{"email":"aiza-poc@no.invalid","password":"AizaPoc1!","returnSecureToken":true}'`
)

// rewriteSignupPoCForPassword swaps the anonymous-signup line embedded in an
// auth-bypass PoC for the email/password equivalent so the PoC reproduces a
// finding confirmed with a registered session. No-op when the PoC has no
// anonymous-signup line.
func rewriteSignupPoCForPassword(poc string) string {
	return strings.ReplaceAll(poc, anonSignupPayload, emailSignupPayload)
}

// ValidateKey runs the full pipeline against one API key: gateway check,
// project-ID discovery (when needed), session bootstrap, fan-out of every
// registered ServiceCheck, and cleanup of the anonymous Firebase user.
func ValidateKey(key, fallbackProject string, checks []ServiceCheck) KeyResult {
	kr := KeyResult{
		Key:       key,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// URL-encode the key for safe use in query parameters
	escKey := url.QueryEscape(key)

	gw := gatewayCheck(key, fallbackProject)
	switch gw.status {
	case "invalid":
		if Silent == 0 {
			printMu.Lock()
			colorInv.Printf("[INVALID]    ---                               | Key rejected by Google (HTTP 400)\n")
			printMu.Unlock()
		}
		kr.Results = append(kr.Results, CheckResult{
			Service: "Gateway", Category: "---", Status: StatusInvalid, StatusS: "invalid",
			Detail: "Key rejected by Google (HTTP 400)",
		})
		return kr
	case "error":
		errDetail := "Gateway check failed: " + gw.errMsg
		if Silent == 0 {
			printMu.Lock()
			colorErr.Printf("[ERROR]      ---                               | %s\n", errDetail)
			printMu.Unlock()
		}
		kr.Results = append(kr.Results, CheckResult{
			Service: "Gateway", Category: "---", Status: StatusError, StatusS: "error",
			Detail: errDetail,
		})
		return kr
	}

	kr.ProjectID = gw.projectID

	// Inject the Resource Manager result from the gateway check
	if gw.rmResult != nil {
		printResult(*gw.rmResult)
		kr.Results = append(kr.Results, *gw.rmResult)
	}

	// Fallback project ID discovery: if Resource Manager didn't yield a project
	// ID and the user didn't pass -p, fan out across multiple side-channel
	// methods in parallel (Firebase Auth, securetoken exchange, recaptchaConfig,
	// Firebase Management, Dynamic Links / Maps Static error leaks, generic
	// 403 scraping, project-number resolution). The first hit wins. Service
	// checks that doubled as discovery probes are cached so the main scan
	// doesn't re-run them.
	var cachedChecks map[string]CheckResult
	var session firebaseSession
	if kr.ProjectID == "" {
		d := discoverProjectID(key, escKey)
		cachedChecks = d.cachedChecks
		session = d.session
		if pid := d.pickProjectID(); pid != "" {
			kr.ProjectID = pid
		}
		if pn := d.pickProjectNumber(); pn != "" {
			kr.ProjectNumber = pn
		}
		// Discovery is a pre-phase, not a vulnerability — render it as a
		// distinct banner above the API checks instead of mixing it in with
		// the per-service findings. The full method-hit list still gets
		// recorded in KeyResult.ProjectIDDiscovery for JSONL/audit.
		if len(d.methodHits) > 0 {
			// Record the discovery-method hits for the per-key summary
			// ("project_id source:") and JSONL/audit. The live "──→ PROJECT_ID"
			// banner was removed — the same information now appears in the
			// summary block, so the inline progress noise is redundant.
			kr.ProjectIDDiscovery = append([]string(nil), d.methodHits...)
		}
	}

	// Session selection for the auth-aware checks. A registered email/password
	// user is a strict superset of an anonymous one for security-rule evaluation
	// (it also satisfies rules that exclude anonymous), so prefer it; fall back
	// to any anonymous session discovery captured, then to a fresh anonymous
	// signup. Track every account we create so all are deleted at end of scan —
	// the discovery anonymous account would otherwise leak once the session is
	// upgraded to email/password.
	var createdTokens []string
	if session.idToken != "" {
		createdTokens = append(createdTokens, session.idToken) // discovery's anonymous account
	}
	emailResult, emailSess := runFirebaseEmailSignUp(escKey)
	// Preserve the registered-signup finding's PoC, then serve it from cache so
	// checkEmailPasswordSignup doesn't run again and create a second account.
	if emailResult.Status == StatusConfirmed {
		emailResult.PoC = "curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" + key +
			`' -H 'Content-Type: application/json' -d '{"email":"aiza-poc@no.invalid","password":"AizaPoc1!","returnSecureToken":true}'`
	}
	if cachedChecks == nil {
		cachedChecks = map[string]CheckResult{}
	}
	cachedChecks["Open Email/Password Registration"] = emailResult
	if emailSess.idToken != "" {
		session = emailSess
		createdTokens = append(createdTokens, emailSess.idToken)
	} else if session.idToken == "" {
		// No registered session and discovery captured none — try anonymous now
		// (e.g. Resource Manager gave us the project ID so discovery never ran).
		_, _, anon := runFirebaseSignUp(escKey)
		session = anon
		if anon.idToken != "" {
			createdTokens = append(createdTokens, anon.idToken)
		}
	}

	// Progress tracker: live "N/Total checks complete" line on stderr so the
	// operator sees the scan moving instead of staring at a blank terminal.
	prog := newProgressTracker(len(checks))
	prog.Start()

	var wg sync.WaitGroup
	results := make([]CheckResult, len(checks))

	for i, chk := range checks {
		if cached, ok := cachedChecks[chk.Name]; ok {
			// Already executed during project ID discovery — reuse the result
			// in its natural slot so output ordering follows buildChecks (which
			// groups by category) rather than discovery timing.
			cached.Description = chk.Desc
			results[i] = cached
			prog.Tick()
			continue
		}
		if chk.NeedsProject && kr.ProjectID == "" {
			results[i] = CheckResult{
				Service: chk.Name, Category: chk.Category, Status: StatusError, StatusS: "error",
				Detail: "Skipped — no project ID found (use -project-id flag)",
			}
			prog.Tick()
			continue
		}
		if chk.NeedsProjectNumber && kr.ProjectNumber == "" {
			results[i] = CheckResult{
				Service: chk.Name, Category: chk.Category, Status: StatusError, StatusS: "error",
				Detail: "Skipped — no project number discovered (resource name embeds it)",
			}
			prog.Tick()
			continue
		}
		if chk.NeedsAuth && session.idToken == "" {
			results[i] = CheckResult{
				Service: chk.Name, Category: chk.Category, Status: StatusForbidden, StatusS: "forbidden",
				Detail: "Skipped — no anonymous idToken (signup disabled or failed)",
			}
			prog.Tick()
			continue
		}
		wg.Add(1)
		go func(idx int, c ServiceCheck) {
			defer wg.Done()
			defer prog.Tick()
			switch {
			case c.RunAuth != nil && session.idToken != "":
				results[idx] = c.RunAuth(escKey, kr.ProjectID, session.idToken)
			case c.RunWithNumber != nil:
				results[idx] = c.RunWithNumber(escKey, kr.ProjectID, kr.ProjectNumber)
			default:
				results[idx] = c.Run(escKey, kr.ProjectID)
			}
			// Attach the check's static finding explanation. The Run funcs
			// only set the dynamic Detail (evidence); the consistent "what
			// this finding is" text lives on the check definition.
			results[idx].Description = c.Desc
			// Default PoC: substitute placeholders in c.PoC, but only if the
			// check didn't already set its own PoC (auth-bypass paths typically
			// need a different multi-step PoC than the template).
			if (results[idx].Status == StatusConfirmed || results[idx].Status == StatusPotential) && results[idx].PoC == "" && c.PoC != "" {
				results[idx].PoC = fillPoC(c.PoC, key, kr.ProjectID, kr.ProjectNumber)
			}
		}(i, chk)
	}
	wg.Wait()
	prog.Stop()

	// If the session is a registered (email/password) user, rewrite the
	// anonymous-signup line embedded in auth-bypass PoCs so each PoC actually
	// reproduces the finding (the signup payload is the only difference, and it
	// is byte-identical across every auth-bypass template).
	if session.provider == "password" {
		for i := range results {
			results[i].PoC = rewriteSignupPoCForPassword(results[i].PoC)
		}
	}

	for _, r := range results {
		printResult(r)
		kr.Results = append(kr.Results, r)
	}

	// Cleanup: delete every Firebase user we created this scan (anonymous from
	// discovery, the email/password session, and/or a fresh anonymous fallback).
	// Best-effort, Silent on failure — keeps the scan non-destructive.
	seenTokens := map[string]bool{}
	for _, tok := range createdTokens {
		if tok == "" || seenTokens[tok] {
			continue
		}
		seenTokens[tok] = true
		deleteFirebaseUser(escKey, tok)
	}

	return kr
}
