package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
)

// ─── Google Maps & Geo checks ────────────────────────────────────────────────

// checkMapsKeyRestriction sends a Maps Static request with an attacker-
// controlled Referer header. The outcome answers the most important question
// for any Maps finding: is this key restricted, or is anyone-from-anywhere
// allowed to abuse it?
//
//   - 200 with junk referer → key is NOT referer-restricted (unrestricted, or
//     IP-restricted with our scanner IP allowed which is very unlikely).
//     Treat every Maps "200" elsewhere as a confirmed abuse vector.
//   - 403 API_KEY_HTTP_REFERRER_BLOCKED → key IS referer-restricted, our
//     referer is not on the allow list. Maps abuse is contained to legitimate
//     domains.
//
// mapsRestrictionProbe sends a Geocoding request with the supplied
// restriction-signal headers and returns (body, restrictionKind). The
// returned restriction kind is one of "none" (200 OK / ZERO_RESULTS),
// "referer", "ip", "android", "ios", or "denied-other".
func mapsRestrictionProbe(key string, headers map[string]string) (body []byte, kind string, err error) {
	u := "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=" + key
	ctx, cancel := context.WithTimeout(context.Background(), Client.Timeout)
	defer cancel()
	req, rerr := http.NewRequestWithContext(ctx, "GET", u, nil)
	if rerr != nil {
		return nil, "", rerr
	}
	req.Header.Set("User-Agent", "aiza-key-scanner/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, rerr := Client.Do(req)
	if rerr != nil {
		return nil, "", rerr
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(resp.Body)
	bodyStr := string(body)
	if strings.Contains(bodyStr, `"status" : "OK"`) || strings.Contains(bodyStr, `"status" : "ZERO_RESULTS"`) {
		return body, "none", nil
	}
	if strings.Contains(bodyStr, "REQUEST_DENIED") {
		switch {
		case strings.Contains(bodyStr, "HTTP referrer") || strings.Contains(bodyStr, "referer") || strings.Contains(bodyStr, "Referer"):
			return body, "referer", nil
		case strings.Contains(bodyStr, "Android application"):
			return body, "android", nil
		case strings.Contains(bodyStr, "iOS application"):
			return body, "ios", nil
		case strings.Contains(bodyStr, "IP address"):
			return body, "ip", nil
		default:
			return body, "denied-other", nil
		}
	}
	return body, "denied-other", nil
}

func checkMapsKeyRestriction() ServiceCheck {
	return ServiceCheck{
		Desc: "The API key accepts requests with arbitrary or missing HTTP-referrer, Android, and iOS restrictions, so it can be lifted from client code and reused by anyone — the root cause of the Maps and billing-abuse findings below.",
		Name: "Unrestricted Maps API Key (No Application Restrictions)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			// Probe 1: attacker referer (no app headers)
			refererBody, refererKind, err := mapsRestrictionProbe(key, map[string]string{
				"Referer": "https://aiza-poc.example.com",
			})
			if err != nil {
				return cr("Unrestricted Maps API Key (No Application Restrictions)", "Maps", StatusError, err.Error(), nil)
			}
			if refererKind == "none" {
				return cr("Unrestricted Maps API Key (No Application Restrictions)", "Maps", StatusConfirmed,
					"Key accepts requests from arbitrary referer on Geocoding — broad billing-abuse posture. Each Maps row below is now also independently verified with the same attacker Referer.", refererBody)
			}
			// Probe 2: junk Android-app headers — if this passes but referer
			// probe failed, the key has an Android restriction.
			_, androidKind, _ := mapsRestrictionProbe(key, map[string]string{
				"X-Android-Package": "com.aiza.poc",
				"X-Android-Cert":    "0000000000000000000000000000000000000000",
			})
			// Probe 3: junk iOS-bundle header
			_, iosKind, _ := mapsRestrictionProbe(key, map[string]string{
				"X-Ios-Bundle-Identifier": "com.aiza.poc",
			})
			// Build a restriction-posture summary
			parts := []string{}
			labelMap := map[string]string{
				"referer":      "HTTP-Referer-restricted (junk referer rejected)",
				"android":      "Android-app restriction observed",
				"ios":          "iOS-bundle restriction observed",
				"ip":           "IP-restricted",
				"denied-other": "denied without specific reason",
			}
			parts = append(parts, "referer-probe: "+labelMap[refererKind])
			if androidKind != refererKind {
				parts = append(parts, "android-probe: "+labelMap[androidKind])
			}
			if iosKind != refererKind && iosKind != androidKind {
				parts = append(parts, "ios-probe: "+labelMap[iosKind])
			}
			// If any probe passed (none), the key is unrestricted for that
			// surface — still a real billing-abuse posture for Android/iOS
			// attackers spoofing the matching app headers.
			if androidKind == "none" || iosKind == "none" {
				return cr("Unrestricted Maps API Key (No Application Restrictions)", "Maps", StatusConfirmed,
					"Key accepts requests when Android-Package or iOS-Bundle headers are present (any value). An attacker can spoof these from a mobile app context. Posture: "+strings.Join(parts, "; "), refererBody)
			}
			// All probes denied — properly restricted
			return cr("Unrestricted Maps API Key (No Application Restrictions)", "Maps", StatusNotVulnerable,
				"Maps key is restricted in every probed dimension. Posture: "+strings.Join(parts, "; "), refererBody)
		},
	}
}

func check4_26() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Maps JavaScript API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Maps JavaScript API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		// PoC loads the JS in a browser; server-side `curl` always returns 200
		// because the key is validated Client-side by the SDK.
		PoC: "# Open in a browser, console will show 'Google Maps JavaScript API error: InvalidKeyMapError' if invalid\nopen 'https://maps.googleapis.com/maps/api/js?key={KEY}&callback=console.log'",
		Run: func(key, projectID string) CheckResult {
			// The /maps/api/js endpoint returns HTTP 200 for ANY key value
			// (validation happens in-browser), so it cannot be probed directly.
			// Instead, hit the Maps Platform Static API which shares the same
			// Maps Platform billing umbrella and DOES validate keys server-side.
			// A 200 here strongly implies the Maps JS API is also usable.
			url := "https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key=" + key
			code, body, err := doMapsGet(url)
			if err != nil {
				return cr("Maps JavaScript API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				// Static Maps proxy probe — the JS API itself only validates
				// in-browser, so we can't directly confirm Maps JS works.
				// Treat as Potential: load the PoC URL in a browser to confirm.
				return cr("Maps JavaScript API Abuse (Unrestricted Key)", "Maps", StatusPotential, "Maps Platform key accepted on Static probe — confirm Maps JS by loading PoC in a browser", nil)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Maps JavaScript API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key rejected by Maps Platform", body)
			}
			return httpError("Maps JavaScript API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func check4_27() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Geocoding API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Geocoding API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway&key=" + key
			code, body, err := doMapsGet(url)
			if err != nil {
				return cr("Geocoding API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status  string `json:"status"`
					Results []struct {
						Geometry struct {
							Location struct {
								Lat float64 `json:"lat"`
								Lng float64 `json:"lng"`
							} `json:"location"`
						} `json:"geometry"`
					} `json:"results"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" && len(resp.Results) > 0 {
					return cr("Geocoding API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Geocoding API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Geocoding API Abuse (Unrestricted Key)", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return httpError("Geocoding API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func check4_28() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Places API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Places API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&key=" + key
			code, body, err := doMapsGet(url)
			if err != nil {
				return cr("Places API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status string `json:"status"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" || resp.Status == "ZERO_RESULTS" {
					return cr("Places API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Places API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Places API Abuse (Unrestricted Key)", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return httpError("Places API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func check4_29() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Directions API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Directions API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://maps.googleapis.com/maps/api/directions/json?origin=Toronto&destination=Montreal&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/directions/json?origin=Toronto&destination=Montreal&key=" + key
			code, body, err := doMapsGet(url)
			if err != nil {
				return cr("Directions API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status string `json:"status"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" {
					return cr("Directions API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Directions API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Directions API Abuse (Unrestricted Key)", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return httpError("Directions API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func check4_30() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Distance Matrix API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Distance Matrix API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://maps.googleapis.com/maps/api/distancematrix/json?origins=Toronto&destinations=Montreal&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/distancematrix/json?origins=Toronto&destinations=Montreal&key=" + key
			code, body, err := doMapsGet(url)
			if err != nil {
				return cr("Distance Matrix API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status string `json:"status"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" {
					return cr("Distance Matrix API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Distance Matrix API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Distance Matrix API Abuse (Unrestricted Key)", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return httpError("Distance Matrix API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func check4_31() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Elevation API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Elevation API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=" + key
			code, body, err := doMapsGet(url)
			if err != nil {
				return cr("Elevation API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status string `json:"status"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" {
					return cr("Elevation API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Elevation API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Elevation API Abuse (Unrestricted Key)", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return httpError("Elevation API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func check4_32() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Static Maps API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Static Maps API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -o map.png -w '%{http_code}\\n' 'https://maps.googleapis.com/maps/api/staticmap?center=Brooklyn+Bridge&zoom=13&size=600x300&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/staticmap?center=Brooklyn+Bridge&zoom=13&size=10x10&key=" + key
			code, _, err := doMapsGet(url)
			if err != nil {
				return cr("Static Maps API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				// Response is binary image data, not JSON
				return cr("Static Maps API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", nil)
			}
			if code == 401 || code == 403 {
				return cr("Static Maps API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", nil)
			}
			return httpError("Static Maps API Abuse (Unrestricted Key)", "Maps", code, nil)
		},
	}
}

func check4_33() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Street View Static API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Street View API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -o sv.jpg -w '%{http_code}\\n' 'https://maps.googleapis.com/maps/api/streetview?size=600x300&location=40.720032,-73.988354&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/streetview?size=10x10&location=40.720032,-73.988354&key=" + key
			code, _, err := doMapsGet(url)
			if err != nil {
				return cr("Street View API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				// Response is binary image data, not JSON
				return cr("Street View API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", nil)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Street View API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", nil)
			}
			return httpError("Street View API Abuse (Unrestricted Key)", "Maps", code, nil)
		},
	}
}

func check4_34() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Time Zone API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Time Zone API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=" + key
			code, body, err := doMapsGet(url)
			if err != nil {
				return cr("Time Zone API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status string `json:"status"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" {
					return cr("Time Zone API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Time Zone API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Time Zone API Abuse (Unrestricted Key)", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return httpError("Time Zone API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func check4_35() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Roads API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Roads API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958&key=" + key
			code, body, err := doMapsGet(url)
			if err != nil {
				return cr("Roads API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Roads API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Roads API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Roads API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func check4_36() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key has the Custom Search JSON API enabled, so an attacker can run billable search queries on the project's account (quota exhaustion and cost inflation).",
		Name: "Custom Search API Abuse (Unrestricted Key)", Category: "Search", NeedsProject: false,
		PoC: "curl -s 'https://www.googleapis.com/customsearch/v1?q=test&cx=017576662512468239146:omuauf_lfve&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			// Uses a public example search engine (cx). A 200 confirms the key has
			// Custom Search API + billing enabled, but does NOT mean the key controls
			// any custom search engine — only that it can make billable queries.
			url := "https://www.googleapis.com/customsearch/v1?q=test&cx=017576662512468239146:omuauf_lfve&key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Custom Search API Abuse (Unrestricted Key)", "Search", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Custom Search API Abuse (Unrestricted Key)", "Search", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Custom Search API Abuse (Unrestricted Key)", "Search", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Custom Search API Abuse (Unrestricted Key)", "Search", code, body)
		},
	}
}

// ─── Extra Maps & Geo checks ─────────────────────────────────────────────────

func checkPlacesAutocomplete() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Places Autocomplete API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation). Billed at roughly $2.83 per 1,000 requests.",
		Name: "Places Autocomplete Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Googleplex&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Googleplex&key=" + key
			code, body, err := doMapsGet(url)
			if err != nil {
				return cr("Places Autocomplete Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status string `json:"status"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" || resp.Status == "ZERO_RESULTS" {
					return cr("Places Autocomplete Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Places Autocomplete Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Places Autocomplete Abuse (Unrestricted Key)", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return httpError("Places Autocomplete Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func checkPlacesDetails() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Places Details API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation). Billed at roughly $17 per 1,000 requests.",
		Name: "Places Details Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,formatted_address,geometry&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name&key=" + key
			code, body, err := doMapsGet(url)
			if err != nil {
				return cr("Places Details Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Status string `json:"status"`
				}
				unmarshal(body, &resp)
				if resp.Status == "OK" {
					return cr("Places Details Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
				}
				if resp.Status == "REQUEST_DENIED" {
					return cr("Places Details Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
				}
				return cr("Places Details Abuse (Unrestricted Key)", "Maps", StatusError, "Status: "+resp.Status, body)
			}
			return httpError("Places Details Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func checkMapsTile() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Map Tiles API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Map Tiles API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: `curl -s -X POST 'https://tile.googleapis.com/v1/createSession?key={KEY}' -H 'Content-Type: application/json' -d '{"mapType":"roadmap","language":"en-US","region":"US"}'`,
		Run: func(key, projectID string) CheckResult {
			url := "https://tile.googleapis.com/v1/createSession?key=" + key
			payload := map[string]interface{}{
				"mapType":  "roadmap",
				"language": "en-US",
				"region":   "US",
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Map Tiles API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Map Tiles API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Map Tiles API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Map Tiles API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func checkEmbedAPI() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Maps Embed API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Maps Embed API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://www.google.com/maps/embed/v1/place?q=NYC&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://www.google.com/maps/embed/v1/place?q=NYC&key=" + key
			code, body, err := doMapsGet(url)
			if err != nil {
				return cr("Maps Embed API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Maps Embed API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Maps Embed API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Maps Embed API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func checkSolarAPI() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Solar API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation). Billed at roughly $15–$25 per 1,000 requests.",
		Name: "Solar API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://solar.googleapis.com/v1/buildingInsights:findClosest?location.latitude=37.4219999&location.longitude=-122.0840575&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://solar.googleapis.com/v1/buildingInsights:findClosest?location.latitude=37.4219999&location.longitude=-122.0840575&key=" + key
			code, body, err := doMapsGet(url)
			if err != nil {
				return cr("Solar API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Solar API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Solar API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Solar API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func checkAirQuality() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Air Quality API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation). Billed at roughly $5 per 1,000 requests.",
		Name: "Air Quality API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: `curl -s -X POST 'https://airquality.googleapis.com/v1/currentConditions:lookup?key={KEY}' -H 'Content-Type: application/json' -d '{"location":{"latitude":37.419734,"longitude":-122.0827784}}'`,
		Run: func(key, projectID string) CheckResult {
			url := "https://airquality.googleapis.com/v1/currentConditions:lookup?key=" + key
			payload := map[string]interface{}{
				"location": map[string]interface{}{
					"latitude":  37.419734,
					"longitude": -122.0827784,
				},
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Air Quality API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Air Quality API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
			}
			if code == 400 || code == 401 || code == 403 {
				return cr("Air Quality API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Air Quality API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

// ─── New Maps & Geo checks ──────────────────────────────────────────────────

func checkAddressValidation() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Address Validation API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation). Billed at roughly $0.005 per call.",
		Name: "Address Validation API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: `curl -s -X POST 'https://addressvalidation.googleapis.com/v1:validateAddress?key={KEY}' -H 'Content-Type: application/json' -d '{"address":{"addressLines":["1600 Amphitheatre Parkway, Mountain View, CA"]}}'`,
		Run: func(key, projectID string) CheckResult {
			u := "https://addressvalidation.googleapis.com/v1:validateAddress?key=" + key
			payload := map[string]interface{}{
				"address": map[string]interface{}{
					"addressLines": []string{"1600 Amphitheatre Parkway, Mountain View, CA"},
				},
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Address Validation API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Address Validation API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Address Validation API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Address Validation API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func checkRoutesAPI() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Routes API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Routes API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: `curl -s -X POST 'https://routes.googleapis.com/directions/v2:computeRoutes?key={KEY}' -H 'Content-Type: application/json' -H 'X-Goog-FieldMask: routes.duration,routes.distanceMeters' -d '{"origin":{"location":{"latLng":{"latitude":37.4191,"longitude":-122.0574}}},"destination":{"location":{"latLng":{"latitude":37.418,"longitude":-122.079}}}}'`,
		Run: func(key, projectID string) CheckResult {
			u := "https://routes.googleapis.com/directions/v2:computeRoutes?key=" + key
			payload := map[string]interface{}{
				"origin":      map[string]interface{}{"location": map[string]interface{}{"latLng": map[string]interface{}{"latitude": 37.4191, "longitude": -122.0574}}},
				"destination": map[string]interface{}{"location": map[string]interface{}{"latLng": map[string]interface{}{"latitude": 37.418, "longitude": -122.079}}},
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Routes API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Routes API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Routes API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Routes API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func checkRouteMatrix() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Route Matrix API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Route Matrix API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: `curl -s -X POST 'https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key={KEY}' -H 'Content-Type: application/json' -H 'X-Goog-FieldMask: duration,distanceMeters' -d '{"origins":[{"waypoint":{"location":{"latLng":{"latitude":37.4191,"longitude":-122.0574}}}}],"destinations":[{"waypoint":{"location":{"latLng":{"latitude":37.418,"longitude":-122.079}}}}]}'`,
		Run: func(key, projectID string) CheckResult {
			u := "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key=" + key
			payload := map[string]interface{}{
				"origins":      []map[string]interface{}{{"waypoint": map[string]interface{}{"location": map[string]interface{}{"latLng": map[string]interface{}{"latitude": 37.4191, "longitude": -122.0574}}}}},
				"destinations": []map[string]interface{}{{"waypoint": map[string]interface{}{"location": map[string]interface{}{"latLng": map[string]interface{}{"latitude": 37.418, "longitude": -122.079}}}}},
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Route Matrix API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Route Matrix API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Route Matrix API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Route Matrix API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func checkAerialView() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Aerial View API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Aerial View API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://aerialview.googleapis.com/v1/videos:lookupVideo?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := "https://aerialview.googleapis.com/v1/videos:lookupVideo?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key=" + key
			code, body, err := doMapsGet(u)
			if err != nil {
				return cr("Aerial View API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Aerial View API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
			}
			// 404 means API is enabled but no aerial video exists for this address
			if code == 404 {
				return cr("Aerial View API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Aerial View API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Aerial View API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func checkPlacesNew() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Places API (New), so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Places API (New) Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: `curl -s -X POST 'https://places.googleapis.com/v1/places:searchNearby?key={KEY}' -H 'Content-Type: application/json' -H 'X-Goog-FieldMask: places.displayName,places.formattedAddress' -d '{"locationRestriction":{"circle":{"center":{"latitude":37.4191,"longitude":-122.0574},"radius":100.0}}}'`,
		Run: func(key, projectID string) CheckResult {
			u := "https://places.googleapis.com/v1/places:searchNearby?key=" + key
			payload := map[string]interface{}{
				"locationRestriction": map[string]interface{}{
					"circle": map[string]interface{}{
						"center": map[string]interface{}{"latitude": 37.4191, "longitude": -122.0574},
						"radius": 100.0,
					},
				},
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Places API (New) Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				// The probe uses a fixed location, so the result count carries no
				// useful evidence — the finding is simply that the key works.
				return cr("Places API (New) Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Places API (New) Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Places API (New) Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}

func checkPollenAPI() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Pollen API, so an attacker can call it freely on the project's billing account (quota exhaustion and cost inflation).",
		Name: "Pollen API Abuse (Unrestricted Key)", Category: "Maps", NeedsProject: false,
		PoC: "curl -s -H 'Referer: https://aiza-poc.example.com' 'https://pollen.googleapis.com/v1/forecast:lookup?location.latitude=37.4&location.longitude=-122.0&days=1&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := "https://pollen.googleapis.com/v1/forecast:lookup?location.latitude=37.4&location.longitude=-122.0&days=1&key=" + key
			code, body, err := doGet(u)
			if err != nil {
				return cr("Pollen API Abuse (Unrestricted Key)", "Maps", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Pollen API Abuse (Unrestricted Key)", "Maps", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Pollen API Abuse (Unrestricted Key)", "Maps", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Pollen API Abuse (Unrestricted Key)", "Maps", code, body)
		},
	}
}
