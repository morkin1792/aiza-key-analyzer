# 🔍 aiza-key-analyzer
![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)
![Release](https://img.shields.io/badge/release-v1.2.2-blue.svg?style=flat-square)

Check leaked Google API keys (`AIzaSy...`) and determine which Google APIs they can access. Collects non-destructive proof-of-concept data to demonstrate impact during bug bounty engagements.

Findings are reported as **CONFIRMED** (confirmed-vulnerable) or **POTENTIAL** (needs manual review), each with a static description and a ready-to-run PoC. Write/abuse probes are non-destructive: anything created (Firestore/RTDB/Storage probe objects, accounts) is deleted on the way out.

## ✨ Checks

124 service checks across 7 categories (plus 2 opt-in, side-effect checks gated behind `-test-phone` / `-test-email`).

| Category | Services |
|----------|----------|
| **GCP** | Resource Manager, Storage (bucket enum + common/App-Engine/GCR/Functions-source bucket exposure), Compute (instance enum, project-metadata disclosure **+ SSH-key-injection write**), Cloud SQL, DNS, Functions (enum, name brute-force, **callable invocation**), Run, GKE, Pub/Sub, Spanner, Bigtable, Secret Manager, Logging, Monitoring, Tasks, Scheduler, Build, Artifact Registry, Firestore, **BigQuery (dataset enum + arbitrary query execution)**, Memorystore, Filestore, VPC Networks, Endpoints, Workflows, Source Repositories, KMS, Dataflow, Retail, Composer, AlloyDB, Batch, Billing, App Engine, Asset Inventory |
| **Firebase** | Email Enumeration, Realtime DB (read / write / rules disclosure), Firestore (read / write), Storage (read / write), Remote Config (client-fetch secret leak), Web Config secret exposure, Cloud Messaging, Hosting, Extensions, Crashlytics, App Distribution, A/B Testing, ML Models, Data Connect, App Hosting, common-path probes, Open Email/Password Registration, Identity Platform Tenant enum, **anonymous-signup auth-bypass** (Firestore user-docs / Storage user-folders / password-auth bypass) |
| **Maps & Geo** | Unrestricted-key check, Geocoding, Places, Places (New), Find Place, Autocomplete, Details, Directions, Distance Matrix, Elevation, Static Maps, Street View, Time Zone, Roads, Map Tiles, Embed, Solar, Air Quality, Address Validation, Routes v2, Route Matrix, Aerial View, Pollen |
| **AI & ML** | Gemini (generate / model enum / tuned models / files / embeddings), Translation, Language Detection, Vision, Natural Language, Speech-to-Text, Text-to-Speech, Vertex AI (predict / datasets), Video Intelligence, Document AI |
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
# simple
cat keys.txt | aiza-key-analyzer -o findings.md

# skip a whole category (e.g. don't run any Maps checks)
cat keys.txt | aiza-key-analyzer -exclude-categories Maps

# or more complete
aiza-key-analyzer -f keys.txt -project-id my-project-prod \
    -test-phone +15551234567 -test-email me@mybox.example \
    -o findings.md -proxy http://127.0.0.1:8080
```

`-categories` / `-exclude-categories` take a comma-separated list (`GCP, Firebase, Maps, Search, AI, Media, Identity`); the exclude filter is applied after the include filter.

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
