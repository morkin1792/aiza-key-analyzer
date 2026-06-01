package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// ─── GCP Infrastructure checks ──────────────────────────────────────────────

func check4_2() ServiceCheck {
	return ServiceCheck{
		Desc: "The API key is accepted by the Cloud Storage JSON API and can list the project's storage buckets, exposing infrastructure layout and candidate targets for object access.",
		Name: "Cloud Storage Bucket Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://storage.googleapis.com/storage/v1/b?project={PROJECT}&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s&key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Storage Bucket Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Items []struct {
						Name string `json:"name"`
					} `json:"items"`
				}
				unmarshal(body, &resp)
				n := len(resp.Items)
				detail := fmt.Sprintf("%d buckets", n)
				if n > 0 {
					names := make([]string, 0, min(5, n))
					for i := 0; i < min(5, n); i++ {
						names = append(names, resp.Items[i].Name)
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Storage Bucket Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Storage Bucket Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Storage Bucket Enumeration", "GCP", code, body)
		},
	}
}

func check4_3() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can call the Compute Engine API and enumerate VM instances (names and zones), exposing the project's compute footprint.",
		Name: "Compute Engine Instance Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://www.googleapis.com/compute/v1/projects/{PROJECT}/aggregated/instances?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/aggregated/instances?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Compute Engine Instance Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Items map[string]struct {
						Instances []struct {
							Name string `json:"name"`
							Zone string `json:"zone"`
						} `json:"instances"`
					} `json:"items"`
				}
				unmarshal(body, &resp)
				total := 0
				var instances []string
				for _, zone := range resp.Items {
					for _, inst := range zone.Instances {
						total++
						if len(instances) < 3 {
							instances = append(instances, inst.Name)
						}
					}
				}
				detail := fmt.Sprintf("%d instances", total)
				if len(instances) > 0 {
					detail += ": " + strings.Join(instances, ", ")
				}
				return cr("Compute Engine Instance Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Compute Engine Instance Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Compute Engine Instance Enumeration", "GCP", code, body)
		},
	}
}

func check4_4() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud SQL instances and their database engine/version, revealing managed databases that may be reachable or attackable.",
		Name: "Cloud SQL Instance Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://www.googleapis.com/sql/v1beta4/projects/{PROJECT}/instances?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://www.googleapis.com/sql/v1beta4/projects/%s/instances?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud SQL Instance Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Items []struct {
						Name            string `json:"name"`
						DatabaseVersion string `json:"databaseVersion"`
					} `json:"items"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, item := range resp.Items {
					parts = append(parts, item.Name+"("+item.DatabaseVersion+")")
				}
				detail := fmt.Sprintf("%d instances", len(resp.Items))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud SQL Instance Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud SQL Instance Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud SQL Instance Enumeration", "GCP", code, body)
		},
	}
}

func check4_5() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud DNS managed zones and their DNS names, mapping the project's internal and external domains.",
		Name: "Cloud DNS Zone Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://dns.googleapis.com/dns/v1/projects/{PROJECT}/managedZones?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://dns.googleapis.com/dns/v1/projects/%s/managedZones?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud DNS Zone Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					ManagedZones []struct {
						Name    string `json:"name"`
						DNSName string `json:"dnsName"`
					} `json:"managedZones"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, z := range resp.ManagedZones {
					parts = append(parts, z.Name+"("+z.DNSName+")")
				}
				detail := fmt.Sprintf("%d zones", len(resp.ManagedZones))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud DNS Zone Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud DNS Zone Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud DNS Zone Enumeration", "GCP", code, body)
		},
	}
}

func check4_6() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list deployed Cloud Functions (Gen1 and Gen2) and their HTTPS trigger URLs, exposing serverless endpoints for further probing.",
		Name: "Cloud Functions Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://cloudfunctions.googleapis.com/v2/projects/{PROJECT}/locations/-/functions?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			// Query both v1 (Gen 1) and v2 (Gen 2) endpoints sequentially.
			// This makes two HTTP calls in one goroutine — worst case 2× timeout.
			type cfn struct {
				Name string
				URL  string
			}
			var allFns []cfn
			var lastBody []byte
			var sawForbidden bool
			var errs []string

			// Gen 1
			u1 := fmt.Sprintf("https://cloudfunctions.googleapis.com/v1/projects/%s/locations/-/functions?key=%s", projectID, key)
			code1, body1, err1 := doGet(u1)
			if err1 == nil {
				if code1 == 200 {
					var resp struct {
						Functions []struct {
							Name         string `json:"name"`
							HTTPSTrigger struct {
								URL string `json:"url"`
							} `json:"httpsTrigger"`
						} `json:"functions"`
					}
					unmarshal(body1, &resp)
					for _, f := range resp.Functions {
						allFns = append(allFns, cfn{Name: shortName(f.Name), URL: f.HTTPSTrigger.URL})
					}
					lastBody = body1
				} else if code1 == 401 || code1 == 403 {
					sawForbidden = true
					lastBody = body1
				} else {
					errs = append(errs, fmt.Sprintf("v1: HTTP %d", code1))
				}
			} else {
				errs = append(errs, "v1: "+err1.Error())
			}

			// Gen 2
			u2 := fmt.Sprintf("https://cloudfunctions.googleapis.com/v2/projects/%s/locations/-/functions?key=%s", projectID, key)
			code2, body2, err2 := doGet(u2)
			if err2 == nil {
				if code2 == 200 {
					var resp struct {
						Functions []struct {
							Name          string `json:"name"`
							ServiceConfig struct {
								URI string `json:"uri"`
							} `json:"serviceConfig"`
						} `json:"functions"`
					}
					unmarshal(body2, &resp)
					for _, f := range resp.Functions {
						allFns = append(allFns, cfn{Name: shortName(f.Name), URL: f.ServiceConfig.URI})
					}
					lastBody = body2
				} else if code2 == 401 || code2 == 403 {
					sawForbidden = true
					if lastBody == nil {
						lastBody = body2
					}
				} else {
					errs = append(errs, fmt.Sprintf("v2: HTTP %d", code2))
				}
			} else {
				errs = append(errs, "v2: "+err2.Error())
			}

			if len(allFns) > 0 {
				var parts []string
				for _, f := range allFns {
					s := f.Name
					if f.URL != "" {
						s += " → " + f.URL
					}
					parts = append(parts, s)
				}
				detail := fmt.Sprintf("%d functions (v1+v2)", len(allFns))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud Functions Enumeration", "GCP", StatusConfirmed, detail, lastBody)
			}
			if sawForbidden {
				return cr("Cloud Functions Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", lastBody)
			}
			if len(errs) > 0 {
				return cr("Cloud Functions Enumeration", "GCP", StatusError, strings.Join(errs, "; "), lastBody)
			}
			return cr("Cloud Functions Enumeration", "GCP", StatusError, "no response from v1 or v2", nil)
		},
	}
}

func check4_7() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud Run services and their public URLs, revealing deployed containerized endpoints.",
		Name: "Cloud Run Service Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://run.googleapis.com/v2/projects/{PROJECT}/locations/-/services?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://run.googleapis.com/v2/projects/%s/locations/-/services?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Run Service Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Services []struct {
						Name string `json:"name"`
						URI  string `json:"uri"`
					} `json:"services"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, s := range resp.Services {
					p := shortName(s.Name)
					if s.URI != "" {
						p += " → " + s.URI
					}
					parts = append(parts, p)
				}
				detail := fmt.Sprintf("%d services", len(resp.Services))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud Run Service Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Run Service Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Run Service Enumeration", "GCP", code, body)
		},
	}
}

func check4_8() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list GKE clusters with location and node version, exposing Kubernetes infrastructure and potentially out-of-date nodes.",
		Name: "GKE Cluster Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://container.googleapis.com/v1/projects/{PROJECT}/locations/-/clusters?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/-/clusters?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("GKE Cluster Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Clusters []struct {
						Name               string `json:"name"`
						Location           string `json:"location"`
						CurrentNodeVersion string `json:"currentNodeVersion"`
					} `json:"clusters"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, c := range resp.Clusters {
					parts = append(parts, fmt.Sprintf("%s (%s, v%s)", c.Name, c.Location, c.CurrentNodeVersion))
				}
				detail := fmt.Sprintf("%d clusters", len(resp.Clusters))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("GKE Cluster Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("GKE Cluster Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("GKE Cluster Enumeration", "GCP", code, body)
		},
	}
}

func check4_9() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Pub/Sub topics, revealing the project's messaging and event-driven topology.",
		Name: "Cloud Pub/Sub Topic Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://pubsub.googleapis.com/v1/projects/{PROJECT}/topics?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://pubsub.googleapis.com/v1/projects/%s/topics?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Pub/Sub Topic Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Topics []struct {
						Name string `json:"name"`
					} `json:"topics"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, t := range resp.Topics {
					names = append(names, shortName(t.Name))
				}
				detail := fmt.Sprintf("%d topics", len(resp.Topics))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Pub/Sub Topic Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Pub/Sub Topic Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Pub/Sub Topic Enumeration", "GCP", code, body)
		},
	}
}

func check4_10() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud Spanner instances, exposing the presence and naming of globally-distributed databases.",
		Name: "Cloud Spanner Instance Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://spanner.googleapis.com/v1/projects/{PROJECT}/instances?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://spanner.googleapis.com/v1/projects/%s/instances?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Spanner Instance Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Instances []struct {
						Name   string `json:"name"`
						Config string `json:"config"`
					} `json:"instances"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, i := range resp.Instances {
					parts = append(parts, shortName(i.Name))
				}
				detail := fmt.Sprintf("%d instances", len(resp.Instances))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud Spanner Instance Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Spanner Instance Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Spanner Instance Enumeration", "GCP", code, body)
		},
	}
}

func check4_11() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Bigtable instances, revealing wide-column NoSQL database infrastructure.",
		Name: "Cloud Bigtable Instance Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://bigtableadmin.googleapis.com/v2/projects/{PROJECT}/instances?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://bigtableadmin.googleapis.com/v2/projects/%s/instances?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Bigtable Instance Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Instances []struct {
						Name string `json:"name"`
					} `json:"instances"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, i := range resp.Instances {
					names = append(names, shortName(i.Name))
				}
				detail := fmt.Sprintf("%d instances", len(resp.Instances))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Bigtable Instance Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Bigtable Instance Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Bigtable Instance Enumeration", "GCP", code, body)
		},
	}
}

func check4_12() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Secret Manager secret names (not values), leaking the catalog of credentials the project stores and inviting targeted access attempts.",
		Name: "Secret Manager Secret Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://secretmanager.googleapis.com/v1/projects/{PROJECT}/secrets?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Secret Manager Secret Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Secrets []struct {
						Name string `json:"name"`
					} `json:"secrets"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, s := range resp.Secrets {
					names = append(names, shortName(s.Name))
				}
				detail := fmt.Sprintf("%d secrets", len(resp.Secrets))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Secret Manager Secret Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Secret Manager Secret Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Secret Manager Secret Enumeration", "GCP", code, body)
		},
	}
}

func check4_13() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can read project log entries via the Logging API — logs frequently contain tokens, internal hostnames, and PII, so this is direct data exposure.",
		Name: "Cloud Logging Log Read Access", Category: "GCP", NeedsProject: true,
		PoC: `curl -s -X POST 'https://logging.googleapis.com/v2/entries:list?key={KEY}' -H 'Content-Type: application/json' -d '{"resourceNames":["projects/{PROJECT}"],"pageSize":5}'`,
		Run: func(key, projectID string) CheckResult {
			url := "https://logging.googleapis.com/v2/entries:list?key=" + key
			payload := map[string]interface{}{
				"resourceNames": []string{"projects/" + projectID},
				"pageSize":      5,
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Cloud Logging Log Read Access", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Entries []struct {
						Timestamp string `json:"timestamp"`
					} `json:"entries"`
				}
				unmarshal(body, &resp)
				detail := "Log read access confirmed"
				if len(resp.Entries) > 0 {
					detail += ", most recent: " + resp.Entries[0].Timestamp
				}
				if hits := scanForSecrets(body); len(hits) > 0 {
					detail += " — SECRETS DETECTED IN LOGS: " + strings.Join(hits, ", ") + " (manually review the full log stream)"
				}
				return cr("Cloud Logging Log Read Access", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Logging Log Read Access", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Logging Log Read Access", "GCP", code, body)
		},
	}
}

func check4_14() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can query Cloud Monitoring metric descriptors, exposing operational telemetry and the set of services in use.",
		Name: "Cloud Monitoring Metric Access", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://monitoring.googleapis.com/v3/projects/{PROJECT}/metricDescriptors?key={KEY}&pageSize=3'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://monitoring.googleapis.com/v3/projects/%s/metricDescriptors?key=%s&pageSize=3", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Monitoring Metric Access", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Cloud Monitoring Metric Access", "GCP", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Monitoring Metric Access", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Monitoring Metric Access", "GCP", code, body)
		},
	}
}

func check4_15() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud Tasks queues, revealing asynchronous-processing infrastructure.",
		Name: "Cloud Tasks Queue Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://cloudtasks.googleapis.com/v2/projects/{PROJECT}/locations/-/queues?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://cloudtasks.googleapis.com/v2/projects/%s/locations/-/queues?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Tasks Queue Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Queues []struct {
						Name string `json:"name"`
					} `json:"queues"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, q := range resp.Queues {
					names = append(names, shortName(q.Name))
				}
				detail := fmt.Sprintf("%d queues", len(resp.Queues))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Tasks Queue Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Tasks Queue Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Tasks Queue Enumeration", "GCP", code, body)
		},
	}
}

func check4_16() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud Scheduler jobs and their cron schedules, exposing automated workflows and their timing.",
		Name: "Cloud Scheduler Job Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://cloudscheduler.googleapis.com/v1/projects/{PROJECT}/locations/-/jobs?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://cloudscheduler.googleapis.com/v1/projects/%s/locations/-/jobs?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Scheduler Job Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Jobs []struct {
						Name     string `json:"name"`
						Schedule string `json:"schedule"`
					} `json:"jobs"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, j := range resp.Jobs {
					parts = append(parts, shortName(j.Name)+"("+j.Schedule+")")
				}
				detail := fmt.Sprintf("%d jobs", len(resp.Jobs))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud Scheduler Job Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Scheduler Job Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Scheduler Job Enumeration", "GCP", code, body)
		},
	}
}

func check4_17() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can read recent Cloud Build records and statuses, exposing CI/CD activity and build identifiers.",
		Name: "Cloud Build History Disclosure", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://cloudbuild.googleapis.com/v1/projects/{PROJECT}/builds?key={KEY}&pageSize=3'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://cloudbuild.googleapis.com/v1/projects/%s/builds?key=%s&pageSize=3", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Build History Disclosure", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Builds []struct {
						ID     string `json:"id"`
						Status string `json:"status"`
					} `json:"builds"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, b := range resp.Builds {
					parts = append(parts, b.ID[:min(8, len(b.ID))]+"("+b.Status+")")
				}
				detail := fmt.Sprintf("%d recent builds", len(resp.Builds))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Cloud Build History Disclosure", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Build History Disclosure", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Build History Disclosure", "GCP", code, body)
		},
	}
}

func check4_18() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Artifact Registry repositories and formats, revealing where the project stores container images and packages.",
		Name: "Artifact Registry Repository Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://artifactregistry.googleapis.com/v1/projects/{PROJECT}/locations/-/repositories?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://artifactregistry.googleapis.com/v1/projects/%s/locations/-/repositories?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Artifact Registry Repository Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Repositories []struct {
						Name   string `json:"name"`
						Format string `json:"format"`
					} `json:"repositories"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, r := range resp.Repositories {
					parts = append(parts, shortName(r.Name)+"("+r.Format+")")
				}
				detail := fmt.Sprintf("%d repositories", len(resp.Repositories))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("Artifact Registry Repository Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Artifact Registry Repository Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Artifact Registry Repository Enumeration", "GCP", code, body)
		},
	}
}

func check4_19() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can read top-level documents from the project's Firestore (native GCP API), directly exposing application data.",
		Name: "Cloud Firestore Document Read Access", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents?key={KEY}&pageSize=3'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents?key=%s&pageSize=3", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Cloud Firestore Document Read Access", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Documents []struct {
						Name string `json:"name"`
					} `json:"documents"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, d := range resp.Documents {
					names = append(names, shortName(d.Name))
				}
				detail := fmt.Sprintf("%d top-level documents", len(resp.Documents))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Firestore Document Read Access", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Firestore Document Read Access", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Firestore Document Read Access", "GCP", code, body)
		},
	}
}

func check4_20() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list BigQuery datasets and their locations, mapping the project's analytical data stores.",
		Name: "BigQuery Dataset Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}/datasets?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://bigquery.googleapis.com/bigquery/v2/projects/%s/datasets?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("BigQuery Dataset Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Datasets []struct {
						DatasetReference struct {
							DatasetID string `json:"datasetId"`
						} `json:"datasetReference"`
						Location string `json:"location"`
					} `json:"datasets"`
				}
				unmarshal(body, &resp)
				var parts []string
				for _, d := range resp.Datasets {
					parts = append(parts, d.DatasetReference.DatasetID+"("+d.Location+")")
				}
				detail := fmt.Sprintf("%d datasets", len(resp.Datasets))
				if len(parts) > 0 {
					detail += ": " + strings.Join(parts, ", ")
				}
				return cr("BigQuery Dataset Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("BigQuery Dataset Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("BigQuery Dataset Enumeration", "GCP", code, body)
		},
	}
}

// ─── New GCP Infrastructure checks ──────────────────────────────────────────

func checkMemorystore() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Memorystore (Redis) instances, exposing in-memory datastore infrastructure.",
		Name: "Cloud Memorystore Instance Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://redis.googleapis.com/v1/projects/{PROJECT}/locations/-/instances?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://redis.googleapis.com/v1/projects/%s/locations/-/instances?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Memorystore Instance Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Instances []struct {
						Name string `json:"name"`
					} `json:"instances"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d Redis instances", len(resp.Instances))
				if len(resp.Instances) > 0 {
					var names []string
					for _, inst := range resp.Instances {
						names = append(names, shortName(inst.Name))
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Memorystore Instance Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Memorystore Instance Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Memorystore Instance Enumeration", "GCP", code, body)
		},
	}
}

func checkFilestore() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Filestore (managed NFS) instances, revealing shared-file infrastructure.",
		Name: "Cloud Filestore Instance Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://file.googleapis.com/v1/projects/{PROJECT}/locations/-/instances?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://file.googleapis.com/v1/projects/%s/locations/-/instances?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Filestore Instance Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Instances []struct {
						Name string `json:"name"`
					} `json:"instances"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d Filestore instances", len(resp.Instances))
				if len(resp.Instances) > 0 {
					var names []string
					for _, inst := range resp.Instances {
						names = append(names, shortName(inst.Name))
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Filestore Instance Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Filestore Instance Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Filestore Instance Enumeration", "GCP", code, body)
		},
	}
}

func checkVPCNetworks() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list the project's VPC networks, exposing network topology.",
		Name: "VPC Network Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://www.googleapis.com/compute/v1/projects/{PROJECT}/global/networks?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/networks?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("VPC Network Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Items []struct {
						Name string `json:"name"`
					} `json:"items"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d VPC networks", len(resp.Items))
				if len(resp.Items) > 0 {
					var names []string
					for _, n := range resp.Items {
						names = append(names, n.Name)
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("VPC Network Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("VPC Network Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("VPC Network Enumeration", "GCP", code, body)
		},
	}
}

func checkCloudEndpoints() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud Endpoints managed services, revealing API gateways fronting the project.",
		Name: "Cloud Endpoints Service Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://servicemanagement.googleapis.com/v1/services?producerProjectId={PROJECT}&key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://servicemanagement.googleapis.com/v1/services?producerProjectId=%s&key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Endpoints Service Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Services []struct {
						ServiceName string `json:"serviceName"`
					} `json:"services"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d managed services", len(resp.Services))
				if len(resp.Services) > 0 {
					var names []string
					for _, s := range resp.Services {
						names = append(names, s.ServiceName)
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Endpoints Service Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Endpoints Service Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Endpoints Service Enumeration", "GCP", code, body)
		},
	}
}

func checkFirebaseExtensions() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list installed Firebase Extensions, revealing third-party integrations and their configuration surface.",
		Name: "Firebase Extensions Enumeration", Category: "Firebase", NeedsProject: true,
		PoC: "curl -s 'https://firebaseextensions.googleapis.com/v1beta/projects/{PROJECT}/instances?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebaseextensions.googleapis.com/v1beta/projects/%s/instances?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase Extensions Enumeration", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Instances []struct {
						Name string `json:"name"`
					} `json:"instances"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d extension instances", len(resp.Instances))
				return cr("Firebase Extensions Enumeration", "Firebase", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase Extensions Enumeration", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase Extensions Enumeration", "Firebase", code, body)
		},
	}
}

// checkFirebaseStorage probes Firebase Storage, which is a distinct service
// from GCS Cloud Storage: same bytes underneath, but exposed via
// firebasestorage.googleapis.com and gated by Firebase Storage Security Rules
// rather than IAM. API keys can read/write here whenever the rules allow it.
// We try anonymous first (catches `allow read: if true;`), and if that's
// denied we sign up anonymously and retry with a Bearer idToken (catches the
// very common `if request.auth != null;` rule, which is trivially bypassable).
// firebaseStorageList probes Firebase Storage object listing for both candidate
// bucket suffixes and returns the MOST PERMISSIVE result. The earlier version
// returned on first 200, which meant an empty .firebasestorage.app bucket
// would mask a populated .appspot.com one. We now walk every bucket and pick
// the one with the highest item count (so "56 objects" beats "0 objects").
func firebaseStorageList(escKey, projectID, idToken string) (status Status, detail string, body []byte) {
	buckets := []string{
		projectID + ".firebasestorage.app",
		projectID + ".appspot.com",
	}
	summarize := func(b []byte, bucket, mode string, n int, sampleNames []string) string {
		d := fmt.Sprintf("%d objects in %s (%s)", n, bucket, mode)
		if len(sampleNames) > 0 {
			d += ": " + strings.Join(sampleNames, ", ")
		}
		return d
	}
	type hit struct {
		bucket string
		body   []byte
		count  int
		names  []string
	}
	var hits []hit
	var lastForbidden []byte
	for _, bucket := range buckets {
		u := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o?key=%s", bucket, escKey)
		headers := map[string]string{}
		if idToken != "" {
			headers["Authorization"] = "Bearer " + idToken
		}
		code, respBody, err := doCustomCtx(context.Background(), "GET", u, nil, headers)
		if err != nil {
			continue
		}
		if code == 200 {
			var parsed struct {
				Items []struct {
					Name string `json:"name"`
				} `json:"items"`
			}
			unmarshal(respBody, &parsed)
			n := len(parsed.Items)
			names := make([]string, 0, min(5, n))
			for i := 0; i < min(5, n); i++ {
				names = append(names, parsed.Items[i].Name)
			}
			hits = append(hits, hit{bucket: bucket, body: respBody, count: n, names: names})
			continue
		}
		if code == 401 || code == 403 {
			lastForbidden = respBody
		}
	}
	if len(hits) > 0 {
		best := hits[0]
		for _, h := range hits[1:] {
			if h.count > best.count {
				best = h
			}
		}
		mode := "public read"
		if idToken != "" {
			mode = "auth bypass via anonymous signup"
		}
		return StatusConfirmed, summarize(best.body, best.bucket, mode, best.count, best.names), best.body
	}
	if lastForbidden != nil {
		return StatusForbidden, "Security rules deny read", lastForbidden
	}
	return StatusForbidden, "No Firebase Storage bucket found (tried .firebasestorage.app and .appspot.com)", nil
}

const storageAuthPoCTemplate = `# 1. Sign up anonymously to get an idToken
TOKEN=$(curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}' -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)
# 2. List Firebase Storage objects with the token (bucket name routes to the project; no API key needed)
curl -s "https://firebasestorage.googleapis.com/v0/b/{PROJECT}.appspot.com/o" -H "Authorization: Bearer ${TOKEN}"`

func checkFirebaseStorage() ServiceCheck {
	return ServiceCheck{
		Desc: "Firebase Storage objects are listable without proper authorization (a public rule or an anonymous-token bypass of an auth-only rule), exposing user-uploaded files; review listed objects for accidentally-public sensitive data.",
		Name: "Firebase Storage Public Access", Category: "Firebase", NeedsProject: true,
		// Firebase Storage public listing routes via the bucket name; the API
		// key adds no value here and is omitted so the PoC proves the leak
		// without involving the leaked credential.
		PoC: "curl -s 'https://firebasestorage.googleapis.com/v0/b/{PROJECT}.appspot.com/o'",
		Run: func(key, projectID string) CheckResult {
			status, detail, body := firebaseStorageList(key, projectID, "")
			if status == StatusConfirmed {
				// Public read without auth — almost always intentional (banner
				// images, public assets). Promote to Potential so the operator
				// reviews contents for accidentally-public sensitive data.
				return cr("Firebase Storage Public Access", "Firebase", StatusPotential,
					detail+" — public bucket; review listed objects for accidentally-exposed sensitive data", body)
			}
			return cr("Firebase Storage Public Access", "Firebase", status, detail, body)
		},
		RunAuth: func(key, projectID, idToken string) CheckResult {
			anonStatus, anonDetail, anonBody := firebaseStorageList(key, projectID, "")
			authStatus, authDetail, authBody := firebaseStorageList(key, projectID, idToken)
			anonOK := anonStatus == StatusConfirmed
			authOK := authStatus == StatusConfirmed
			// Auth-bypass: rules required auth, but anonymous-signup token slipped past.
			// This is a near-certain misconfiguration → Vulnerable.
			if !anonOK && authOK {
				result := cr("Firebase Storage Public Access", "Firebase", StatusConfirmed,
					authDetail+" — rules require auth but anonymous-signup JWT bypasses them (likely misconfiguration)", authBody)
				result.PoC = fillPoC(storageAuthPoCTemplate, key, projectID, "")
				return result
			}
			// Public read works → likely intentional, may still contain
			// accidentally-public sensitive data → Potential.
			if anonOK {
				return cr("Firebase Storage Public Access", "Firebase", StatusPotential,
					anonDetail+" — public bucket; review listed objects for accidentally-exposed sensitive data", anonBody)
			}
			// Neither anon nor auth — properly restricted.
			if anonStatus == StatusForbidden {
				return cr("Firebase Storage Public Access", "Firebase", anonStatus, anonDetail, anonBody)
			}
			return cr("Firebase Storage Public Access", "Firebase", authStatus, authDetail, authBody)
		},
	}
}

func checkFirebaseTestLab() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can reach the Firebase Test Lab device catalog. This catalog is public by design, so it is informational rather than a vulnerability.",
		Name: "Firebase Test Lab Catalog Access", Category: "Firebase", NeedsProject: false,
		PoC: "curl -s 'https://testing.googleapis.com/v1/testEnvironmentCatalog/ANDROID?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := "https://testing.googleapis.com/v1/testEnvironmentCatalog/ANDROID?key=" + key
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase Test Lab Catalog Access", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Models []struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"models"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("Public test-device catalog reachable (%d Android models) — accessible by design", len(resp.Models))
				return cr("Firebase Test Lab Catalog Access", "Firebase", StatusNotVulnerable, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase Test Lab Catalog Access", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase Test Lab Catalog Access", "Firebase", code, body)
		},
	}
}

func checkFirebaseHosting() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Firebase Hosting sites and their default URLs, revealing deployed web properties.",
		Name: "Firebase Hosting Site Enumeration", Category: "Firebase", NeedsProject: true,
		PoC: "curl -s 'https://firebasehosting.googleapis.com/v1beta1/projects/{PROJECT}/sites?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://firebasehosting.googleapis.com/v1beta1/projects/%s/sites?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Firebase Hosting Site Enumeration", "Firebase", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Sites []struct {
						Name       string `json:"name"`
						DefaultURL string `json:"defaultUrl"`
					} `json:"sites"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d hosting sites", len(resp.Sites))
				if len(resp.Sites) > 0 {
					var urls []string
					for _, s := range resp.Sites {
						if s.DefaultURL != "" {
							urls = append(urls, s.DefaultURL)
						} else {
							urls = append(urls, shortName(s.Name))
						}
					}
					detail += ": " + strings.Join(urls, ", ")
				}
				return cr("Firebase Hosting Site Enumeration", "Firebase", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Firebase Hosting Site Enumeration", "Firebase", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Firebase Hosting Site Enumeration", "Firebase", code, body)
		},
	}
}

func checkCloudWorkflows() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Cloud Workflows definitions, exposing orchestration logic names.",
		Name: "Cloud Workflows Enumeration", Category: "GCP", NeedsProject: true,
		PoC: "curl -s 'https://workflows.googleapis.com/v1/projects/{PROJECT}/locations/-/workflows?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://workflows.googleapis.com/v1/projects/%s/locations/-/workflows?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Cloud Workflows Enumeration", "GCP", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Workflows []struct {
						Name string `json:"name"`
					} `json:"workflows"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d workflows", len(resp.Workflows))
				if len(resp.Workflows) > 0 {
					var names []string
					for _, w := range resp.Workflows {
						names = append(names, shortName(w.Name))
					}
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Cloud Workflows Enumeration", "GCP", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Workflows Enumeration", "GCP", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Workflows Enumeration", "GCP", code, body)
		},
	}
}

// ─── GCS bucket existence side-channel ──────────────────────────────────────
//
// The XML/anonymous Storage API distinguishes 403 (bucket EXISTS but anonymous
// listing is denied) from 404 (bucket does not exist). This is a stable
// side-channel that doesn't require an API key — GCS storage.objects.list is
// blocked at the gateway for API-key auth anyway. Existence alone is high-
// signal because the well-known bucket-name patterns are tied to specific
// deployment fingerprints (Cloud Functions, App Engine, Container Registry).
//
// Returns one of: "exists-private" (403), "exists-public" (200), "missing"
// (404), or "" (unknown / error / unexpected status).
func gcsBucketState(bucket string) string {
	u := "https://storage.googleapis.com/" + bucket + "/?maxResults=1"
	code, _, err := doGet(u)
	if err != nil {
		return ""
	}
	switch code {
	case 200:
		return "exists-public"
	case 403:
		return "exists-private"
	case 404:
		return "missing"
	}
	return ""
}

// cloudFunctionRegions is the short list we probe for Cloud Functions source
// buckets. Limited to regions where deployments are common — probing all 30+
// would be wasteful.
var cloudFunctionRegions = []string{
	"us-central1", "us-east1", "us-east4", "us-west1", "us-west2",
	"europe-west1", "europe-west2", "europe-west3", "europe-west4",
	"asia-east1", "asia-northeast1", "asia-south1", "southamerica-east1",
}

// checkCloudFunctionsSourceBuckets enumerates Cloud Functions source-code
// buckets (Gen1 + Gen2 + Gen2 uploads) across common regions. The buckets are
// named after the project NUMBER, so this check needs the project number
// (NeedsProjectNumber). Anonymous public listing (200 from the XML API) is the
// finding — it means deployable source archives are downloadable by anyone
// (CONFIRMED). Private existence (403) is the secure default and not a
// vulnerability, so it's reported NOT VULNERABLE rather than flagged. The
// gcf-v2-uploads-* prefix in particular has historically been publicly
// listable on misconfigured projects (CVE-style disclosures of source
// archives).
func checkCloudFunctionsSourceBuckets() ServiceCheck {
	return ServiceCheck{
		Desc:               "A Cloud Functions source/upload bucket for this project (named after the project number) is anonymously listable, leaking deployable function source archives to anyone on the internet.",
		Name:               "Cloud Functions Source Bucket Public Read Access",
		Category:           "GCP",
		NeedsProjectNumber: true,
		PoC: `# Source-code buckets are named after the project NUMBER. Confirm existence:
for region in us-central1 us-east1 europe-west1 asia-east1; do
  for prefix in gcf-sources gcf-v2-sources gcf-v2-uploads; do
    bucket="${prefix}-{PROJECT_NUMBER}-${region}"
    echo -n "$bucket -> "
    curl -s -o /dev/null -w "%{http_code}\n" "https://storage.googleapis.com/${bucket}/?maxResults=1"
  done
done
# 403 = exists (private), 200 = listable (jackpot), 404 = doesn't exist.
# On 200, list with: curl -s 'https://storage.googleapis.com/<bucket>/?maxResults=100'`,
		RunWithNumber: func(key, projectID, projectNumber string) CheckResult {
			type bucketHit struct {
				name  string
				state string // exists-private | exists-public
			}
			prefixes := []string{"gcf-sources", "gcf-v2-sources", "gcf-v2-uploads"}
			targets := make([]string, 0, len(cloudFunctionRegions)*len(prefixes))
			for _, region := range cloudFunctionRegions {
				for _, prefix := range prefixes {
					targets = append(targets, fmt.Sprintf("%s-%s-%s", prefix, projectNumber, region))
				}
			}
			var hits []bucketHit
			var mu sync.Mutex
			parallelProbe(targets, 8, func(bucket string) {
				st := gcsBucketState(bucket)
				if st == "exists-private" || st == "exists-public" {
					mu.Lock()
					hits = append(hits, bucketHit{name: bucket, state: st})
					mu.Unlock()
				}
			})
			if len(hits) == 0 {
				return cr("Cloud Functions Source Bucket Public Read Access", "GCP", StatusNotVulnerable,
					"No source/upload buckets found in the probed regions (no Gen-1/Gen-2 functions deployed there, or buckets in non-standard regions)", nil)
			}
			publicHits := make([]string, 0)
			privateHits := make([]string, 0)
			for _, h := range hits {
				if h.state == "exists-public" {
					publicHits = append(publicHits, h.name)
				} else {
					privateHits = append(privateHits, h.name)
				}
			}
			// Public = source code archive listable anonymously → critical.
			if len(publicHits) > 0 {
				parts := publicHits
				if len(privateHits) > 0 {
					parts = append(parts, fmt.Sprintf("(+%d private)", len(privateHits)))
				}
				return cr("Cloud Functions Source Bucket Public Read Access", "GCP", StatusConfirmed,
					"Cloud Functions source bucket(s) ANONYMOUSLY LISTABLE — source code archives downloadable: "+strings.Join(parts, ", "), nil)
			}
			// Buckets exist but anonymous listing is denied (HTTP 403) — the
			// default, secure configuration. Nothing is exposed; the only signal
			// is a per-region deployment fingerprint, which isn't actionable.
			// Mark NOT VULNERABLE so it stays out of the findings report.
			return cr("Cloud Functions Source Bucket Public Read Access", "GCP", StatusNotVulnerable,
				fmt.Sprintf("%d Cloud Functions source bucket(s) exist but anonymous listing is denied (private — secure default): %s",
					len(privateHits), strings.Join(privateHits, ", ")), nil)
		},
	}
}

// checkAppEngineGCRBuckets probes the well-known buckets that App Engine and
// Container Registry create at deploy time. Bucket names embed the project
// SLUG (not the number), so this check uses the regular Run signature.
//
//   - staging.{project}.appspot.com  — App Engine deploy staging archives
//     (source code historically present)
//   - {us,eu,asia}.artifacts.{project}.appspot.com — Container Registry
//     storage backing gcr.io / eu.gcr.io / asia.gcr.io
//   - artifacts.{project}.appspot.com — legacy / multi-region GCR
//
// As with Cloud Functions buckets, the anonymous XML API distinguishes
// 403 (exists, private) from 404 (missing). Public listing on any of these
// is the actual finding (full source / image layer leak → CONFIRMED).
// Private existence (403) is the secure default and not a vulnerability, so
// it's reported NOT VULNERABLE rather than flagged as a finding.
func checkAppEngineGCRBuckets() ServiceCheck {
	return ServiceCheck{
		Desc:         "An App Engine staging or Container Registry bucket for this project is anonymously listable, leaking deployment source archives and container image layers (which often contain baked-in secrets) to anyone on the internet.",
		Name:         "App Engine / GCR Bucket Public Read Access",
		Category:     "GCP",
		NeedsProject: true,
		PoC: `# App Engine + Container Registry buckets are named after the project SLUG.
for bucket in staging.{PROJECT}.appspot.com us.artifacts.{PROJECT}.appspot.com \
              eu.artifacts.{PROJECT}.appspot.com asia.artifacts.{PROJECT}.appspot.com \
              artifacts.{PROJECT}.appspot.com; do
  echo -n "$bucket -> "
  curl -s -o /dev/null -w "%{http_code}\n" "https://storage.googleapis.com/${bucket}/?maxResults=1"
done
# 403 = exists private, 200 = listable, 404 = missing.
# On 200, list with: curl -s 'https://storage.googleapis.com/<bucket>/?maxResults=100'`,
		Run: func(key, projectID string) CheckResult {
			candidates := []string{
				"staging." + projectID + ".appspot.com",
				"us.artifacts." + projectID + ".appspot.com",
				"eu.artifacts." + projectID + ".appspot.com",
				"asia.artifacts." + projectID + ".appspot.com",
				"artifacts." + projectID + ".appspot.com",
			}
			type bucketHit struct {
				name  string
				state string
			}
			var hits []bucketHit
			var mu sync.Mutex
			parallelProbe(candidates, 5, func(bucket string) {
				st := gcsBucketState(bucket)
				if st == "exists-private" || st == "exists-public" {
					mu.Lock()
					hits = append(hits, bucketHit{name: bucket, state: st})
					mu.Unlock()
				}
			})
			if len(hits) == 0 {
				return cr("App Engine / GCR Bucket Public Read Access", "GCP", StatusNotVulnerable,
					"No App Engine / GCR buckets found (project likely has no App Engine app or GCR images)", nil)
			}
			publicHits := make([]string, 0)
			privateHits := make([]string, 0)
			for _, h := range hits {
				if h.state == "exists-public" {
					publicHits = append(publicHits, h.name)
				} else {
					privateHits = append(privateHits, h.name)
				}
			}
			if len(publicHits) > 0 {
				parts := publicHits
				if len(privateHits) > 0 {
					parts = append(parts, fmt.Sprintf("(+%d private)", len(privateHits)))
				}
				return cr("App Engine / GCR Bucket Public Read Access", "GCP", StatusConfirmed,
					"App Engine / GCR bucket(s) ANONYMOUSLY LISTABLE — source/image layers downloadable: "+strings.Join(parts, ", "), nil)
			}
			// Buckets exist but anonymous listing is denied (HTTP 403) — this is
			// the default, secure configuration. Nothing is exposed; the only
			// signal is a deployment fingerprint, which isn't actionable. Mark
			// NOT VULNERABLE so it stays out of the findings report.
			return cr("App Engine / GCR Bucket Public Read Access", "GCP", StatusNotVulnerable,
				fmt.Sprintf("%d App Engine / GCR bucket(s) exist but anonymous listing is denied (private — secure default): %s",
					len(privateHits), strings.Join(privateHits, ", ")), nil)
		},
	}
}
