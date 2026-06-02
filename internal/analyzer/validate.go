package analyzer

import (
	"net/url"
	"sync"
	"time"
)

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

	// Ensure we have an anonymous Firebase session before the auth-aware checks
	// fan out. Discovery would have created one already; this fills the gap
	// when Resource Manager already gave us the project ID (so discovery never
	// ran). Failure is Silent — auth-aware checks degrade gracefully and the
	// signup result itself is intentionally not surfaced as a finding.
	if session.idToken == "" {
		_, _, sess := runFirebaseSignUp(escKey)
		session = sess
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

	for _, r := range results {
		printResult(r)
		kr.Results = append(kr.Results, r)
	}

	// Cleanup: delete the anonymous Firebase user we created. Best-effort,
	// Silent on failure. This keeps the scan non-destructive — no leftover
	// users in the target project's Auth user database.
	deleteAnonymousUser(escKey, session.idToken)

	return kr
}
