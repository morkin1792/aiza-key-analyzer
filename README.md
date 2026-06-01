# 🔍 aiza-key-analyzer
![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)

Check leaked Google API keys (`AIzaSy...`) and determine which Google APIs they can access. Collects non-destructive proof-of-concept data to demonstrate impact during bug bounty engagements.

Findings are reported as **CONFIRMED** (confirmed-vulnerable) or **POTENTIAL** (needs manual review), each with a static description and a ready-to-run PoC. Write/abuse probes are non-destructive: anything created (Firestore/RTDB/Storage probe objects, accounts) is deleted on the way out.

## ✨ Checks

125 service checks across 7 categories (plus 2 opt-in, side-effect checks gated behind `-test-phone` / `-test-email`).

| Category | Services |
|----------|----------|
| **GCP** | Resource Manager, Storage (bucket enum + common/App-Engine/GCR/Functions-source bucket exposure), Compute (instance enum, project-metadata disclosure **+ SSH-key-injection write**), Cloud SQL, DNS, Functions (enum, name brute-force, **callable invocation**), Run, GKE, Pub/Sub, Spanner, Bigtable, Secret Manager, Logging, Monitoring, Tasks, Scheduler, Build, Artifact Registry, Firestore, **BigQuery (dataset enum + arbitrary query execution)**, Memorystore, Filestore, VPC Networks, Endpoints, Workflows, Source Repositories, KMS, Dataflow, Retail, Composer, AlloyDB, Batch, Billing, App Engine, Asset Inventory |
| **Firebase** | Email Enumeration, Realtime DB (read / write / rules disclosure), Firestore (read / write), Storage (read / write), Remote Config, Cloud Messaging, Hosting, Extensions, Crashlytics, App Distribution, A/B Testing, ML Models, Data Connect, App Hosting, common-path probes, Open Email/Password Registration, Identity Platform Tenant enum, **anonymous-signup auth-bypass** (Firestore user-docs / Storage user-folders / password-auth bypass) |
| **Maps & Geo** | Unrestricted-key check, Geocoding, Places, Places (New), Find Place, Autocomplete, Details, Directions, Distance Matrix, Elevation, Static Maps, Street View, Time Zone, Roads, Map Tiles, Embed, Solar, Air Quality, Address Validation, Routes v2, Route Matrix, Aerial View, Pollen |
| **AI & ML** | Gemini (generate / model enum / tuned models / files / embeddings), Translation, Language Detection, Vision, Natural Language, Speech-to-Text, Text-to-Speech, Vertex AI (predict / datasets), AutoML, Video Intelligence, Document AI |
| **Media** | YouTube Search / Channels / Analytics, Books, Fonts, Calendar, Drive, Sheets |
| **Search** | Custom Search |
| **Identity** | People API, reCAPTCHA Enterprise, IAP, Service Usage (enabled-API disclosure), IAM service accounts, Firebase App Check — *opt-in:* Phone-Auth SMS toll fraud, Auth email-sending abuse |

## 📦 Installation

```
go install github.com/morkin1792/aiza-key-analyzer@latest
```

Or:

```
git clone https://github.com/morkin1792/aiza-key-analyzer && cd aiza-key-analyzer && go build -o aiza-key-analyzer .
```

## 🛠️ Usage

```bash
# Pipe keys via stdin, save findings to a file
cat keys.txt | aiza-key-analyzer -o findings.md

# Single key, verbose (full raw JSON + every check result)
aiza-key-analyzer -k AIzaSy... -v

# Full engagement: file input, fallback project, side-effect opt-ins, proxy
aiza-key-analyzer -f keys.txt -project-id my-project-prod \
    -test-phone +15551234567 -test-email me@mybox.example \
    -o findings.md -proxy http://127.0.0.1:8080
```

Keys are read from `-k`, `-f`, or stdin. Multi-key runs scan in parallel (`-w`) and show a live `N/Total keys` progress line on stderr; the findings report prints to stdout at the end.

### 🚩 Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-k` | | Single API key |
| `-f` | | File of newline-separated keys |
| `-project-id` | | Fallback GCP project ID — used when discovery can't find the slug (some Firebase Storage/RTDB probes need a slug, not a number) |
| `-o` | | Save the human-readable findings summary to a file (appends) |
| `-j` | | Append every key's full per-check result as JSONL (automation) |
| `-categories` | | Comma-separated category allow-list (e.g. `Maps,AI`) |
| `-v` | `false` | Verbose: full raw JSON responses + every check's result |
| `-w` | `5` | Worker pool size — keys scanned in parallel |
| `-timeout` | `30` | Per-request HTTP timeout in seconds |
| `-dual-stack` | `false` | Allow IPv6 dialing. Default is IPv4-only, which avoids `connect: network is unreachable` on hosts with broken/black-holed IPv6 |
| `-proxy` | | Route every request through an HTTP proxy (Burp/mitmproxy). Disables TLS verification while set |
| `-test-phone` | | E.164 number you control — opts into the SMS-abuse check. **Sends a real SMS** if the project allows it |
| `-test-email` | | Email you control — opts into the password-reset-spam check. **Sends a real email** if the project allows it |

## 📝 Output

The summary is Markdown — the same content goes to stdout (with ANSI color) and to the `-o` file (plain). Each key gets a summary table followed by detailed findings; only **CONFIRMED** and **POTENTIAL** results are shown.

````markdown
# Findings

## AIzaSy...H4cK
- project_id: my-project-prod
- project_id source: identitytoolkit-getProjectConfig; firebase-signup-jwt
- Found findings: 3

### Summary Table
| Finding | Status |
| --- | --- |
| [Firebase] Firebase Email Enumeration | Confirmed |
| [Identity] IAM Service Account Enumeration | Confirmed |

### Findings

#### [Firebase] Firebase Email Enumeration
- Status: CONFIRMED ✅
- Description: The Identity Toolkit endpoint discloses whether an email is registered, enabling account enumeration for targeted phishing or credential-stuffing.
- PoC:
```
curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=AIza...' \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"probe@no.invalid","continueUri":"http://localhost"}'
```

#### [Identity] IAM Service Account Enumeration
- Status: CONFIRMED ✅
- Description: The key can list the project's IAM service accounts, disclosing principal emails that are prime targets for privilege escalation.
- Evidence: 3 service accounts: app@my-project-prod.iam.gserviceaccount.com, ...
- PoC:
```
curl -s 'https://iam.googleapis.com/v1/projects/my-project-prod/serviceAccounts?key=AIza...'
```
````
