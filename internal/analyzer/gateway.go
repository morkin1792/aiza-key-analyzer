package analyzer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// gatewayCheck is the entry-point of every scan: it hits Cloud Resource Manager
// to (a) confirm the key isn't outright invalid, and (b) try to discover the
// project ID. The result feeds into the discovery pipeline (discovery.go) and
// then the full check fan-out (validate.go).
func gatewayCheck(key, fallbackProject string) gatewayResult {
	escKey := url.QueryEscape(key)
	u := "https://cloudresourcemanager.googleapis.com/v1/projects?key=" + escKey
	code, body, err := doGet(u)
	if err != nil {
		return gatewayResult{status: "error", errMsg: err.Error()}
	}
	switch {
	case code == 200:
		var resp struct {
			Projects []struct {
				ProjectID string `json:"projectId"`
			} `json:"projects"`
		}
		var rmDetail string
		if json.Unmarshal(body, &resp) == nil {
			n := len(resp.Projects)
			rmDetail = fmt.Sprintf("%d projects", n)
			if n > 0 {
				names := make([]string, 0, min(5, n))
				for i := 0; i < min(5, n); i++ {
					names = append(names, resp.Projects[i].ProjectID)
				}
				rmDetail += ": " + strings.Join(names, ", ")
			}
		} else {
			rmDetail = "API accessible (parse error)"
		}
		rmCR := cr("Cloud Resource Manager", "GCP", StatusConfirmed, rmDetail, body)
		rmCR.Description = "The API key can call Cloud Resource Manager and list the GCP projects it is authorized against, exposing project IDs that bootstrap every other enumeration in this report."
		rmCR.PoC = fillPoC("curl -s 'https://cloudresourcemanager.googleapis.com/v1/projects?key={KEY}'", key, "", "")
		gr := gatewayResult{status: "ok", rmResult: &rmCR}
		if len(resp.Projects) > 0 {
			gr.projectID = resp.Projects[0].ProjectID
		} else if fallbackProject != "" {
			gr.projectID = fallbackProject
		}
		return gr
	case code == 401 || code == 403:
		rmCR := cr("Cloud Resource Manager", "GCP", StatusForbidden, "Key valid, API not enabled", body)
		return gatewayResult{status: "forbidden", projectID: fallbackProject, rmResult: &rmCR}
	case code == 400:
		return gatewayResult{status: "invalid"}
	default:
		return gatewayResult{status: "error", errMsg: fmt.Sprintf("HTTP %d", code)}
	}
}
