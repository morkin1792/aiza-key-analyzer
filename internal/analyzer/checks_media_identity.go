package analyzer

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// ─── Media & Content checks ─────────────────────────────────────────────────

func check4_47() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key can issue YouTube Data API search queries (100 quota units each), letting an attacker exhaust the project's daily quota.",
		Name: "YouTube Search Quota Abuse (Unrestricted Key)", Category: "Media", NeedsProject: false,
		PoC: "curl -s 'https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&type=video&maxResults=5&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&type=video&maxResults=1&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("YouTube Search Quota Abuse (Unrestricted Key)", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("YouTube Search Quota Abuse (Unrestricted Key)", "Media", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("YouTube Search Quota Abuse (Unrestricted Key)", "Media", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("YouTube Search Quota Abuse (Unrestricted Key)", "Media", code, body)
		},
	}
}

func check4_48() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key can query the YouTube Data API channels endpoint on the project's quota (quota/cost abuse).",
		Name: "YouTube Channels API Abuse (Unrestricted Key)", Category: "Media", NeedsProject: false,
		PoC: "curl -s 'https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("YouTube Channels API Abuse (Unrestricted Key)", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("YouTube Channels API Abuse (Unrestricted Key)", "Media", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("YouTube Channels API Abuse (Unrestricted Key)", "Media", StatusForbidden, "Key valid, requires OAuth", body)
			}
			return httpError("YouTube Channels API Abuse (Unrestricted Key)", "Media", code, body)
		},
	}
}

func check4_49() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can reach YouTube Analytics endpoints for the project, exposing analytics data surfaces.",
		Name: "YouTube Analytics Access", Category: "Media", NeedsProject: false,
		PoC: "curl -s 'https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==MINE&metrics=views&startDate=2024-01-01&endDate=2024-01-02&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==MINE&metrics=views&startDate=2024-01-01&endDate=2024-01-02&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("YouTube Analytics Access", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("YouTube Analytics Access", "Media", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("YouTube Analytics Access", "Media", StatusForbidden, "Key valid, requires OAuth", body)
			}
			return httpError("YouTube Analytics Access", "Media", code, body)
		},
	}
}

func check4_50() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key can call the Google Books API on the project's account, consuming quota (cost abuse).",
		Name: "Google Books API Abuse (Unrestricted Key)", Category: "Media", NeedsProject: false,
		PoC: "curl -s 'https://www.googleapis.com/books/v1/volumes?q=golang&maxResults=5&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://www.googleapis.com/books/v1/volumes?q=golang&maxResults=1&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Google Books API Abuse (Unrestricted Key)", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Google Books API Abuse (Unrestricted Key)", "Media", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Google Books API Abuse (Unrestricted Key)", "Media", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Google Books API Abuse (Unrestricted Key)", "Media", code, body)
		},
	}
}

func check4_51() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key can call the Google Fonts Developer API on the project's account, consuming quota (cost abuse).",
		Name: "Google Fonts API Abuse (Unrestricted Key)", Category: "Media", NeedsProject: false,
		PoC: "curl -s 'https://www.googleapis.com/webfonts/v1/webfonts?key={KEY}&sort=popularity'",
		Run: func(key, projectID string) CheckResult {
			url := "https://www.googleapis.com/webfonts/v1/webfonts?key=" + key + "&sort=popularity"
			code, body, err := doGet(url)
			if err != nil {
				return cr("Google Fonts API Abuse (Unrestricted Key)", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Google Fonts API Abuse (Unrestricted Key)", "Media", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Google Fonts API Abuse (Unrestricted Key)", "Media", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Google Fonts API Abuse (Unrestricted Key)", "Media", code, body)
		},
	}
}

func check4_52() ServiceCheck {
	return ServiceCheck{
		Desc: "The key is accepted by the Calendar API; depending on calendar sharing this can expose user data and consumes the project's quota.",
		Name: "Google Calendar API Access", Category: "Media", NeedsProject: false,
		PoC: "curl -s 'https://www.googleapis.com/calendar/v3/users/me/calendarList?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://www.googleapis.com/calendar/v3/users/me/calendarList?key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Google Calendar API Access", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Google Calendar API Access", "Media", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Google Calendar API Access", "Media", StatusForbidden, "Key valid, requires OAuth", body)
			}
			return httpError("Google Calendar API Access", "Media", code, body)
		},
	}
}

func check4_53() ServiceCheck {
	return ServiceCheck{
		Desc: "The key is accepted by the Drive API; depending on file sharing this can expose user data and consumes the project's quota.",
		Name: "Google Drive API Access", Category: "Media", NeedsProject: false,
		PoC: "curl -s 'https://www.googleapis.com/drive/v3/files?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://www.googleapis.com/drive/v3/files?key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Google Drive API Access", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Google Drive API Access", "Media", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Google Drive API Access", "Media", StatusForbidden, "Key valid, requires OAuth", body)
			}
			return httpError("Google Drive API Access", "Media", code, body)
		},
	}
}

func check4_54() ServiceCheck {
	return ServiceCheck{
		Desc: "The key is accepted by the Sheets API; depending on spreadsheet sharing this can expose user data and consumes the project's quota.",
		Name: "Google Sheets API Access", Category: "Media", NeedsProject: false,
		PoC: "curl -s 'https://sheets.googleapis.com/v4/spreadsheets?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://sheets.googleapis.com/v4/spreadsheets?key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Google Sheets API Access", "Media", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Google Sheets API Access", "Media", StatusConfirmed, "", body)
			}
			// 400 here is normal: the /v4/spreadsheets path is not a listing
			// endpoint, so even a working key gets back "spreadsheetId required".
			// That confirms the API is reachable, just unusable without OAuth/an ID.
			if code == 400 || code == 401 || code == 403 || code == 404 {
				return cr("Google Sheets API Access", "Media", StatusForbidden, "Key valid, requires OAuth", body)
			}
			return httpError("Google Sheets API Access", "Media", code, body)
		},
	}
}

// ─── Identity & Security checks ──────────────────────────────────────────────

func check4_55() ServiceCheck {
	return ServiceCheck{
		Desc: "The key is accepted by the People API directory endpoint; if a Workspace domain directory is exposed this leaks names, emails, and phone numbers.",
		Name: "People API Access", Category: "Identity", NeedsProject: false,
		PoC: "curl -s 'https://people.googleapis.com/v1/people:listDirectoryPeople?sources=DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE&readMask=names,emailAddresses,phoneNumbers&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://people.googleapis.com/v1/people:listDirectoryPeople?sources=DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE&readMask=names&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("People API Access", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("People API Access", "Identity", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("People API Access", "Identity", StatusForbidden, "Key valid, requires OAuth", body)
			}
			return httpError("People API Access", "Identity", code, body)
		},
	}
}

func check4_56() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list reCAPTCHA Enterprise site keys on the project, disclosing the configured keys and enabling assessment/token-farming cost abuse.",
		Name: "reCAPTCHA Enterprise Abuse (Unrestricted Key)", Category: "Identity", NeedsProject: true,
		PoC: "curl -s 'https://recaptchaenterprise.googleapis.com/v1/projects/{PROJECT}/keys?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://recaptchaenterprise.googleapis.com/v1/projects/%s/keys?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("reCAPTCHA Enterprise Abuse (Unrestricted Key)", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Keys []struct {
						Name string `json:"name"`
					} `json:"keys"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d reCAPTCHA site keys", len(resp.Keys))
				return cr("reCAPTCHA Enterprise Abuse (Unrestricted Key)", "Identity", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("reCAPTCHA Enterprise Abuse (Unrestricted Key)", "Identity", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("reCAPTCHA Enterprise Abuse (Unrestricted Key)", "Identity", code, body)
		},
	}
}

func check4_57() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can enumerate Identity-Aware Proxy resources/settings, revealing access-controlled applications behind IAP.",
		Name: "Identity-Aware Proxy Enumeration", Category: "Identity", NeedsProject: true,
		PoC: "curl -s 'https://iap.googleapis.com/v1/projects/{PROJECT}/iap_web?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://iap.googleapis.com/v1/projects/%s/iap_web?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Identity-Aware Proxy Enumeration", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Identity-Aware Proxy Enumeration", "Identity", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Identity-Aware Proxy Enumeration", "Identity", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Identity-Aware Proxy Enumeration", "Identity", code, body)
		},
	}
}

func check4_58() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list which Google APIs are enabled on the project, mapping the full attack surface.",
		Name: "Enabled API Disclosure (Service Usage)", Category: "Identity", NeedsProject: true,
		PoC: "curl -s 'https://serviceusage.googleapis.com/v1/projects/{PROJECT}/services?filter=state:ENABLED&key={KEY}&pageSize=200'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://serviceusage.googleapis.com/v1/projects/%s/services?filter=state:ENABLED&key=%s&pageSize=20", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Enabled API Disclosure (Service Usage)", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Services []struct {
						Config struct {
							Name string `json:"name"`
						} `json:"config"`
					} `json:"services"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, s := range resp.Services {
					names = append(names, s.Config.Name)
				}
				detail := fmt.Sprintf("%d enabled APIs", len(resp.Services))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Enabled API Disclosure (Service Usage)", "Identity", StatusPotential, detail+" — recon only, follow up with the relevant per-service rows", body)
			}
			if code == 401 || code == 403 {
				return cr("Enabled API Disclosure (Service Usage)", "Identity", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Enabled API Disclosure (Service Usage)", "Identity", code, body)
		},
	}
}

func check4_59() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list the project's IAM service accounts, disclosing principal emails that are prime targets for privilege escalation.",
		Name: "IAM Service Account Enumeration", Category: "Identity", NeedsProject: true,
		PoC: "curl -s 'https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://iam.googleapis.com/v1/projects/%s/serviceAccounts?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("IAM Service Account Enumeration", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Accounts []struct {
						Email string `json:"email"`
					} `json:"accounts"`
				}
				unmarshal(body, &resp)
				var emails []string
				for _, a := range resp.Accounts {
					emails = append(emails, a.Email)
				}
				detail := fmt.Sprintf("%d service accounts", len(resp.Accounts))
				if len(emails) > 0 {
					detail += ": " + strings.Join(emails, ", ")
				}
				return cr("IAM Service Account Enumeration", "Identity", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("IAM Service Account Enumeration", "Identity", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("IAM Service Account Enumeration", "Identity", code, body)
		},
	}
}

// ─── New Identity checks ────────────────────────────────────────────────────

// checkPhoneSMSAbuse confirms whether the key can trigger Firebase phone-auth
// SMS without a reCAPTCHA token. A success here is a direct billing-cost
// finding (Google charges per SMS) plus a spam vector. Only registered when
// the operator supplies -test-phone with a number they control.
func checkPhoneSMSAbuse(phone string) ServiceCheck {
	pocBody := fmt.Sprintf(`{"phoneNumber":"%s"}`, phone)
	return ServiceCheck{
		Desc: "The key can trigger Identity Platform phone-auth SMS to attacker-supplied numbers without reCAPTCHA, enabling SMS pumping / toll fraud billed to the project.",
		Name: "Phone Auth SMS Toll Fraud", Category: "Identity", NeedsProject: false,
		PoC: fmt.Sprintf(`# WARNING: this sends a real SMS to %s
curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:sendVerificationCode?key={KEY}' -H 'Content-Type: application/json' -d '%s'`, phone, pocBody),
		Run: func(key, projectID string) CheckResult {
			u := "https://identitytoolkit.googleapis.com/v1/accounts:sendVerificationCode?key=" + key
			code, body, err := doPost(u, map[string]interface{}{"phoneNumber": phone})
			if err != nil {
				return cr("Phone Auth SMS Toll Fraud", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Phone Auth SMS Toll Fraud", "Identity", StatusConfirmed,
					fmt.Sprintf("SMS dispatched to %s without reCAPTCHA — confirmed billing-cost + spam vector", phone), body)
			}
			bodyStr := string(body)
			if strings.Contains(bodyStr, "MISSING_RECAPTCHA_TOKEN") || strings.Contains(bodyStr, "INVALID_RECAPTCHA_TOKEN") ||
				strings.Contains(bodyStr, "CAPTCHA_CHECK_FAILED") || strings.Contains(bodyStr, "MISSING_APP_TOKEN") {
				return cr("Phone Auth SMS Toll Fraud", "Identity", StatusNotVulnerable,
					"sendVerificationCode requires reCAPTCHA / app attestation token — properly protected", body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Phone Auth SMS Toll Fraud", "Identity", StatusForbidden, "Key valid, phone auth not enabled or other restriction", body)
			}
			return httpError("Phone Auth SMS Toll Fraud", "Identity", code, body)
		},
	}
}

// checkEmailOOBAbuse confirms whether the key can trigger Firebase to send a
// real password-reset email to an attacker-supplied address. Success is a
// spam/phishing vector (and a low-but-real cost on some Firebase plans). Only
// registered when the operator supplies -test-email with an inbox they own.
func checkEmailOOBAbuse(email string) ServiceCheck {
	return ServiceCheck{
		Desc: "The key can trigger Identity Platform out-of-band emails (verification/reset) to arbitrary addresses, usable as a spam/phishing vector from a trusted Google sender.",
		Name: "Auth Email Sending Abuse", Category: "Identity", NeedsProject: false,
		PoC: fmt.Sprintf(`# WARNING: this sends a real password-reset email to %s
curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={KEY}' -H 'Content-Type: application/json' -d '{"requestType":"PASSWORD_RESET","email":"%s"}'`, email, email),
		Run: func(key, projectID string) CheckResult {
			u := "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=" + key
			code, body, err := doPost(u, map[string]interface{}{
				"requestType": "PASSWORD_RESET",
				"email":       email,
			})
			if err != nil {
				return cr("Auth Email Sending Abuse", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Auth Email Sending Abuse", "Identity", StatusConfirmed,
					fmt.Sprintf("Password-reset email dispatched to %s — confirmed phishing/spam vector usable from the leaked key", email), body)
			}
			bodyStr := string(body)
			if strings.Contains(bodyStr, "EMAIL_NOT_FOUND") {
				// The endpoint divulged that the email isn't a registered user.
				// Email Enumeration Protection rendering already covers this
				// case via the Firebase Auth Providers check; here we don't
				// re-flag it — just record that no email was sent.
				return cr("Auth Email Sending Abuse", "Identity", StatusNotVulnerable,
					fmt.Sprintf("%s is not a registered user — no email sent", email), body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Auth Email Sending Abuse", "Identity", StatusForbidden, "Key valid, password-reset endpoint denied", body)
			}
			return httpError("Auth Email Sending Abuse", "Identity", code, body)
		},
	}
}

func checkFirebaseAppCheck() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list the apps registered for Firebase App Check, disclosing the project's app inventory.",
		Name: "Firebase App Check App Enumeration", Category: "Identity", NeedsProject: true,
		PoC: "curl -s 'https://firebaseappcheck.googleapis.com/v1/projects/{PROJECT}/apps?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebaseappcheck.googleapis.com/v1/projects/%s/apps?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase App Check App Enumeration", "Identity", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Apps []struct {
						Name string `json:"name"`
					} `json:"apps"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d registered apps", len(resp.Apps))
				return cr("Firebase App Check App Enumeration", "Identity", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase App Check App Enumeration", "Identity", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase App Check App Enumeration", "Identity", code, body)
		},
	}
}

func checkSourceRepos() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud Source Repositories, potentially exposing source-code repository names and access surfaces.",
		Name: "Cloud Source Repositories Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://sourcerepo.googleapis.com/v1/projects/{PROJECT}/repos?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://sourcerepo.googleapis.com/v1/projects/%s/repos?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Source Repositories Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Repos []struct {
						Name string `json:"name"`
					} `json:"repos"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d repositories", len(resp.Repos))
				return cr("Cloud Source Repositories Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Source Repositories Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Source Repositories Enumeration", "GCP", code, body)
		},
	}
}

func checkCloudKMS() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud KMS key rings/keys, disclosing the project's cryptographic key inventory.",
		Name: "Cloud KMS Key Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://cloudkms.googleapis.com/v1/projects/{PROJECT}/locations/-/keyRings?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://cloudkms.googleapis.com/v1/projects/%s/locations/-/keyRings?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud KMS Key Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					KeyRings []struct {
						Name string `json:"name"`
					} `json:"keyRings"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d key rings", len(resp.KeyRings))
				return cr("Cloud KMS Key Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud KMS Key Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud KMS Key Enumeration", "GCP", code, body)
		},
	}
}

func checkDataflow() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Dataflow jobs, exposing data-pipeline activity.",
		Name: "Cloud Dataflow Job Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://dataflow.googleapis.com/v1b3/projects/{PROJECT}/jobs?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://dataflow.googleapis.com/v1b3/projects/%s/jobs?key=%s", projectID, key)
			code, body, err := doMapsGet(u)
			if err != nil {
				return cr("Cloud Dataflow Job Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Jobs []struct {
						Name string `json:"name"`
					} `json:"jobs"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d jobs", len(resp.Jobs))
				return cr("Cloud Dataflow Job Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Dataflow Job Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Dataflow Job Enumeration", "GCP", code, body)
		},
	}
}

func checkFindPlace() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Find Place API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Find Place API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum+of+Contemporary+Art+Australia&inputtype=textquery&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum+of+Contemporary+Art+Australia&inputtype=textquery&key=" + key
			code, body, err := doMapsGet(u)
			if err != nil {
				return cr("Find Place API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status     string `json:"status"`
					Candidates []struct {
						PlaceID string `json:"place_id"`
					} `json:"candidates"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" {
					// Fixed probe query, so the candidate count is not useful
					// evidence — the finding is that the key works.
					return cr("Find Place API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Find Place API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Find Place API Abuse (Unrestricted Key)", "Maps", StatusError, "status: "+resp.Status, body)
			}
			if code == 401 || code == 403 {
				return cr("Find Place API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Find Place API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func checkGeminiEmbeddings() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key can run billable Gemini embedding requests on the project's account (cost abuse).",
		Name: "Gemini Embeddings Abuse (Unrestricted Key)", Category: "AI", NeedsProject: false,
		PoC: `curl -s -X POST 'https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent?key={KEY}' -H 'Content-Type: application/json' -d '{"content":{"parts":[{"text":"Hello"}]}}'`,
		Run: func(key, projectID string) CheckResult {
			u := "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent?key=" + key
			payload := map[string]interface{}{
				"content": map[string]interface{}{
					"parts": []map[string]interface{}{
						{"text": "Hello"},
					},
				},
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Gemini Embeddings Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				// The embedding dimension is constant for a given model, so it
				// carries no run-specific evidence — the finding is that the
				// billable embedding call succeeded.
				return cr("Gemini Embeddings Abuse (Unrestricted Key)", "AI", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Gemini Embeddings Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Gemini Embeddings Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

func checkCloudComposer() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud Composer (managed Airflow) environments, exposing orchestration infrastructure.",
		Name: "Cloud Composer Environment Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://composer.googleapis.com/v1/projects/{PROJECT}/locations/-/environments?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://composer.googleapis.com/v1/projects/%s/locations/-/environments?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Composer Environment Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Environments []struct {
						Name string `json:"name"`
					} `json:"environments"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d Composer environments", len(resp.Environments))
				if len(resp.Environments) > 0 {
					var names []string
					for _, e := range resp.Environments {
						names = append(names, shortName(e.Name))
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Composer Environment Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Composer Environment Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Composer Environment Enumeration", "GCP", code, body)
		},
	}
}

func checkAlloyDB() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list AlloyDB clusters, revealing PostgreSQL-compatible database infrastructure.",
		Name: "AlloyDB Cluster Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://alloydb.googleapis.com/v1/projects/{PROJECT}/locations/-/clusters?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://alloydb.googleapis.com/v1/projects/%s/locations/-/clusters?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("AlloyDB Cluster Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Clusters []struct {
						Name string `json:"name"`
					} `json:"clusters"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d AlloyDB clusters", len(resp.Clusters))
				if len(resp.Clusters) > 0 {
					var names []string
					for _, c := range resp.Clusters {
						names = append(names, shortName(c.Name))
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("AlloyDB Cluster Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("AlloyDB Cluster Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("AlloyDB Cluster Enumeration", "GCP", code, body)
		},
	}
}

func checkBatchAPI() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud Batch jobs, exposing batch-compute activity.",
		Name: "Cloud Batch Job Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://batch.googleapis.com/v1/projects/{PROJECT}/locations/-/jobs?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://batch.googleapis.com/v1/projects/%s/locations/-/jobs?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Batch Job Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Jobs []struct {
						Name string `json:"name"`
					} `json:"jobs"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d batch jobs", len(resp.Jobs))
				return cr("Cloud Batch Job Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Batch Job Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Batch Job Enumeration", "GCP", code, body)
		},
	}
}

func checkBillingAccounts() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can read the billing account(s) linked to the project, disclosing billing identifiers and confirming an active, billable target.",
		Name: "Cloud Billing Account Disclosure", Category: "GCP", NeedsProject: false,
		PoC: "curl -s 'https://cloudbilling.googleapis.com/v1/billingAccounts?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := "https://cloudbilling.googleapis.com/v1/billingAccounts?key=" + key
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Billing Account Disclosure", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					BillingAccounts []struct {
						Name        string `json:"name"`
						DisplayName string `json:"displayName"`
						Open        bool   `json:"open"`
					} `json:"billingAccounts"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d billing accounts", len(resp.BillingAccounts))
				if len(resp.BillingAccounts) > 0 {
					var parts []string
					for _, ba := range resp.BillingAccounts {
						s := ba.Name + " " + ba.DisplayName
						if ba.Open {
							s += " (active)"
						}
						parts = append(parts, s)
					}
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud Billing Account Disclosure", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Billing Account Disclosure", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Billing Account Disclosure", "GCP", code, body)
		},
	}
}

// checkComputeProjectMetadata reads compute/v1/projects/{p} which returns the
// project-wide `commonInstanceMetadata.items[]` array. That array is the
// single richest leak in GCP when accessible by an API key: it commonly
// contains the project-wide SSH keys (granting login to every VM), and dev
// teams routinely stash environment variables, startup scripts, and even
// credentials there. A 200 here is one of the highest-impact findings the
// tool can produce.
func checkComputeProjectMetadata() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can read project-wide Compute metadata, which often contains SSH keys, startup scripts, and embedded secrets.",
		Name: "Compute Project Metadata Disclosure", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://compute.googleapis.com/compute/v1/projects/{PROJECT}?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Compute Project Metadata Disclosure", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					CommonInstanceMetadata struct {
						Items []struct {
							Key   string `json:"key"`
							Value string `json:"value"`
						} `json:"items"`
					} `json:"commonInstanceMetadata"`
					DefaultServiceAccount string `json:"defaultServiceAccount"`
				}
				unmarshal(body, &resp)
				keys := make([]string, 0, len(resp.CommonInstanceMetadata.Items))
				sshKeysFound := false
				for _, it := range resp.CommonInstanceMetadata.Items {
					keys = append(keys, it.Key)
					if it.Key == "ssh-keys" || it.Key == "sshKeys" {
						sshKeysFound = true
					}
				}
				detail := fmt.Sprintf("Project-wide metadata accessible: %d entries", len(keys))
				if len(keys) > 0 {
					detail += " (" + strings.Join(keys, ", ") + ")"
				}
				if sshKeysFound {
					detail += " — INCLUDES PROJECT-WIDE SSH KEYS (login to every VM in this project)"
				}
				if resp.DefaultServiceAccount != "" {
					detail += " — default SA: " + resp.DefaultServiceAccount
				}
				return cr("Compute Project Metadata Disclosure", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Compute Project Metadata Disclosure", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Compute Project Metadata Disclosure", "GCP", code, body)
		},
	}
}

// checkAppEngineApp reads appengine.googleapis.com/v1/apps/{appsId} which is
// usually the project ID. Response may contain hostnames, custom domains,
// runtime configs, default service account, and bucket names — useful recon
// + occasionally exposes the app's default service account email which is a
// pivot target.
func checkAppEngineApp() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can read the App Engine application resource, disclosing the app's hosting configuration, default hostname, buckets, and service account.",
		Name: "App Engine Application Disclosure", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://appengine.googleapis.com/v1/apps/{PROJECT}?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://appengine.googleapis.com/v1/apps/%s?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("App Engine Application Disclosure", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Name            string `json:"name"`
					DefaultHostname string `json:"defaultHostname"`
					DefaultBucket   string `json:"defaultBucket"`
					CodeBucket      string `json:"codeBucket"`
					ServiceAccount  string `json:"serviceAccount"`
					DatabaseType    string `json:"databaseType"`
				}
				unmarshal(body, &resp)
				parts := []string{}
				if resp.DefaultHostname != "" {
					parts = append(parts, "host="+resp.DefaultHostname)
				}
				if resp.ServiceAccount != "" {
					parts = append(parts, "SA="+resp.ServiceAccount)
				}
				if resp.DefaultBucket != "" {
					parts = append(parts, "default-bucket="+resp.DefaultBucket)
				}
				if resp.CodeBucket != "" {
					parts = append(parts, "code-bucket="+resp.CodeBucket)
				}
				detail := "App Engine app metadata accessible"
				if len(parts) > 0 {
					detail += " — " + strings.Join(parts, ", ")
				}
				return cr("App Engine Application Disclosure", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 || code == 404 {
				return cr("App Engine Application Disclosure", "GCP", StatusForbidden, "Key valid, App Engine not enabled or app not deployed", body)
			}
			return httpError("App Engine Application Disclosure", "GCP", code, body)
		},
	}
}

// checkCloudAssetInventory probes Cloud Asset Inventory — a comprehensive
// "list everything" API. Usually requires elevated IAM roles, so a successful
// hit from an API key is a major finding (full project resource inventory).
func checkCloudAssetInventory() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can query Cloud Asset Inventory, enumerating resources across the project in bulk.",
		Name: "Cloud Asset Inventory Disclosure", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://cloudasset.googleapis.com/v1/projects/{PROJECT}/assets?key={KEY}&pageSize=10'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://cloudasset.googleapis.com/v1/projects/%s/assets?key=%s&pageSize=10", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Asset Inventory Disclosure", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				// Defensive: some Google APIs return 200 with an error envelope
				// (or a proxy/intercept can rewrite the status), and the bare
				// "0 assets" reading would otherwise be a false positive.
				var resp struct {
					Assets []struct {
						Name      string `json:"name"`
						AssetType string `json:"assetType"`
					} `json:"assets"`
					Error *struct {
						Code    int    `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				}
				unmarshal(body, &resp)
				if resp.Error != nil {
					return cr("Cloud Asset Inventory Disclosure", "GCP", StatusForbidden,
						fmt.Sprintf("Key valid, API not callable with API key (HTTP 200 + error %d: %s)", resp.Error.Code, resp.Error.Message),
						body)
				}
				if len(resp.Assets) == 0 {
					// The endpoint accepted the key but listed no assets. Could
					// mean an empty project or a silent permission denial that
					// doesn't surface as an error object — don't claim CONFIRMED.
					return cr("Cloud Asset Inventory Disclosure", "GCP", StatusNotVulnerable,
						"API responded 200 but listed no assets — inconclusive (likely empty project or permission-shaped no-op)", body)
				}
				sample := make([]string, 0, min(3, len(resp.Assets)))
				for i := 0; i < min(3, len(resp.Assets)); i++ {
					sample = append(sample, resp.Assets[i].AssetType)
				}
				detail := fmt.Sprintf("Asset Inventory accessible: %d assets in sample (full inventory enumerable) — types: %s, ...",
					len(resp.Assets), strings.Join(sample, ", "))
				return cr("Cloud Asset Inventory Disclosure", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Asset Inventory Disclosure", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Asset Inventory Disclosure", "GCP", code, body)
		},
	}
}

// checkGCSCommonBuckets enumerates well-known bucket names for the project.
// GCS buckets are globally unique, so an attacker who can guess the name can
// probe each one anonymously. We try the most common suffix patterns; a 200
// listing on any of them is a finding.
func checkGCSCommonBuckets() ServiceCheck {
	return ServiceCheck{
		Desc: "Well-known bucket-name patterns for this project are listable, exposing storage that commonly holds backups or source.",
		Name: "GCS Common Bucket Exposure", Category: "GCP", NeedsProject: true,
		PoC: "for s in '' -staging -prod -dev -uploads -backup -public -private -data -media -assets; do curl -s -o /dev/null -w '%{http_code} {PROJECT}'$s'\\n' \"https://storage.googleapis.com/storage/v1/b/{PROJECT}$s/o?key={KEY}&maxResults=1\"; done",
		Run: func(key, projectID string) CheckResult {
			suffixes := []string{"", "-staging", "-prod", "-dev", "-uploads", "-backup", "-public", "-private", "-data", "-media", "-assets", "-files"}
			type bucketHit struct {
				bucket   string
				count    int
				sample   []string
				allNames []string
			}
			var hits []bucketHit
			var mu sync.Mutex
			parallelProbe(suffixes, 8, func(sfx string) {
				bucket := projectID + sfx
				u := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o?key=%s&maxResults=200", bucket, key)
				code, body, err := doGet(u)
				if err != nil || code != 200 {
					return
				}
				var resp struct {
					Items []struct {
						Name string `json:"name"`
					} `json:"items"`
				}
				unmarshal(body, &resp)
				names := make([]string, 0, min(3, len(resp.Items)))
				all := make([]string, 0, len(resp.Items))
				for i, it := range resp.Items {
					if i < 3 {
						names = append(names, it.Name)
					}
					all = append(all, it.Name)
				}
				mu.Lock()
				hits = append(hits, bucketHit{bucket: bucket, count: len(resp.Items), sample: names, allNames: all})
				mu.Unlock()
			})
			if len(hits) == 0 {
				return cr("GCS Common Bucket Exposure", "GCP", StatusForbidden, "No common-named buckets are publicly listable", nil)
			}
			parts := make([]string, 0, len(hits))
			// Build one global candidate list across all listable buckets, encoded
			// as "bucket/object", so a single bounded scan covers every bucket.
			var candidates []string
			for _, h := range hits {
				p := fmt.Sprintf("%s (%d objects)", h.bucket, h.count)
				if len(h.sample) > 0 {
					p += ": " + strings.Join(h.sample, ", ")
				}
				parts = append(parts, p)
				for _, name := range h.allNames {
					candidates = append(candidates, h.bucket+"/"+name)
				}
			}
			secretHits := scanObjectsForSecrets(candidates, func(c string) []byte {
				i := strings.IndexByte(c, '/')
				if i < 0 {
					return nil
				}
				bucket, name := c[:i], c[i+1:]
				fu := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o/%s?alt=media&key=%s",
					bucket, url.QueryEscape(name), key)
				code, b, err := doGetCapped(context.Background(), fu, nil, scanRangeBytes)
				if err != nil || code/100 != 2 {
					return nil
				}
				return b
			})
			res := cr("GCS Common Bucket Exposure", "GCP", StatusConfirmed,
				"Anonymously-listable GCS bucket(s) found by common-name enumeration: "+strings.Join(parts, " | "), nil)
			return mergeSecretHits(res, secretHits, "GCS OBJECTS")
		},
	}
}

// commonCloudFunctionNames is the brute-force dictionary used when the
// Cloud Functions management API is denied. We probe the public Gen-1 URL
// pattern (`https://{region}-{project}.cloudfunctions.net/{name}`) directly.
// A function deployed with `allUsers` invoker (or no IAM at all on Gen 1)
// shows up as HTTP 200 — that's anonymously callable from the internet.
var commonCloudFunctionNames = []string{
	// Hello-world / starters
	"hello", "helloWorld", "helloworld", "helloHttp", "helloHTTP",
	// API surfaces
	"api", "graphql", "webhook", "callback", "trigger",
	// Auth
	"auth", "login", "register", "signup", "signin", "logout",
	// User CRUD
	"createUser", "getUser", "getUsers", "listUsers", "updateUser", "deleteUser", "getProfile",
	// Admin
	"admin", "dashboard", "status", "health", "ping", "version",
	"test", "debug", "internal",
	// Messaging
	"sendEmail", "sendMessage", "sendNotification", "notify", "mail",
	// Payments
	"processPayment", "payment", "charge", "refund", "checkout", "stripe", "paypal",
	// Files
	"upload", "download", "getDownloadUrl", "presign",
	// Search / data
	"search", "query", "getData", "import", "export",
}

func checkFunctionsEnum() ServiceCheck {
	return ServiceCheck{
		Desc: "Function names can be confirmed by probing the public Cloud Functions URL pattern, mapping serverless endpoints even when the listing API is blocked.",
		Name: "Cloud Functions Name Enumeration", Category: "GCP", NeedsProject: true,
		PoC: `# Replace FUNC_NAME with one of the hits in the detail; try other regions if us-central1 isn't yours.
curl -s 'https://us-central1-{PROJECT}.cloudfunctions.net/FUNC_NAME'`,
		Run: func(key, projectID string) CheckResult {
			// Probe a junk name first — if the host doesn't resolve, this project
			// has no Gen-1 functions in us-central1 and we can bail early.
			junkURL := fmt.Sprintf("https://us-central1-%s.cloudfunctions.net/aiza-no-such-function", projectID)
			junkCode, _, junkErr := doGet(junkURL)
			if junkErr != nil {
				return cr("Cloud Functions Name Enumeration", "GCP", StatusForbidden,
					"No Gen-1 Cloud Functions deployment in us-central1 (host DNS does not resolve)", nil)
			}
			// If even the junk name returns 200, the deployment has a wildcard
			// catch-all that responds to anything — treat as VULN.
			if junkCode == 200 {
				return cr("Cloud Functions Name Enumeration", "GCP", StatusConfirmed,
					"us-central1 deployment responds 200 to arbitrary function names — wildcard catch-all or open invoker on all functions", nil)
			}
			var vulnHits []string  // anonymously-callable (200)
			var existHits []string // function exists but auth-required (401/403/405)
			var mu sync.Mutex
			parallelProbe(commonCloudFunctionNames, 8, func(name string) {
				u := fmt.Sprintf("https://us-central1-%s.cloudfunctions.net/%s", projectID, name)
				code, _, err := doGet(u)
				if err != nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				switch code {
				case 200:
					vulnHits = append(vulnHits, fmt.Sprintf("%s (HTTP 200, anonymously callable)", name))
				case 401, 403:
					existHits = append(existHits, fmt.Sprintf("%s (HTTP %d, auth required)", name, code))
				case 405:
					existHits = append(existHits, fmt.Sprintf("%s (HTTP 405, exists, expects different method)", name))
				}
			})
			if len(vulnHits) > 0 {
				detail := "Anonymously-callable Cloud Functions in us-central1: " + strings.Join(vulnHits, ", ")
				if len(existHits) > 0 {
					detail += " | Also present (auth-required): " + strings.Join(existHits, ", ")
				}
				return cr("Cloud Functions Name Enumeration", "GCP", StatusConfirmed, detail, nil)
			}
			if len(existHits) > 0 {
				return cr("Cloud Functions Name Enumeration", "GCP", StatusPotential,
					"Cloud Functions present in us-central1 but require auth: "+strings.Join(existHits, ", ")+" — try with anonymous-signup idToken or known credentials", nil)
			}
			return cr("Cloud Functions Name Enumeration", "GCP", StatusForbidden,
				"us-central1 has Gen-1 functions but none of the common names matched (try other regions or a custom wordlist)", nil)
		},
	}
}

func checkCloudRetail() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud Retail catalogs, exposing the project's retail/recommendation data surfaces.",
		Name: "Cloud Retail Catalog Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://retail.googleapis.com/v2/projects/{PROJECT}/locations/global/catalogs?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://retail.googleapis.com/v2/projects/%s/locations/global/catalogs?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Retail Catalog Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Catalogs []struct {
						Name string `json:"name"`
					} `json:"catalogs"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d catalogs", len(resp.Catalogs))
				return cr("Cloud Retail Catalog Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Retail Catalog Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Retail Catalog Enumeration", "GCP", code, body)
		},
	}
}

// Helpers (cr, shortName, isInvalidKeyResponse, fillPoC, httpError) live in helpers.go.

// Output (printResult, PrintSummary, showResult) lives in output.go.
