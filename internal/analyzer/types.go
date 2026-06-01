package analyzer

import (
	"context"
	"sync"
)

// ─── Status ──────────────────────────────────────────────────────────────────

type Status int

const (
	StatusConfirmed     Status = iota // confirmed impact (data read/write, billing abuse confirmed, auth bypass)
	StatusPotential                   // capability accessible but exploit needs manual follow-up
	StatusForbidden                   // key denied by API / Security Rules
	StatusNotVulnerable               // accessible by design (catalog APIs, public search)
	StatusInvalid                     // key rejected as malformed/non-existent by Google
	StatusError                       // technical failure
)

func (s Status) String() string {
	switch s {
	case StatusConfirmed:
		return "confirmed"
	case StatusPotential:
		return "potential"
	case StatusForbidden:
		return "forbidden"
	case StatusNotVulnerable:
		return "not_vulnerable"
	case StatusInvalid:
		return "invalid"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// ─── ServiceCheck / CheckResult / KeyResult ──────────────────────────────────

type ServiceCheck struct {
	Name string
	// Desc is a static, one-or-two-sentence explanation of what the finding
	// IS — the security meaning of a positive result — independent of the
	// runtime evidence. Rendered as the "Description" line; the dynamic
	// per-run data (counts, sample names, response values) is rendered
	// separately as "Evidence". Keep it consistent across checks: state the
	// condition and the impact.
	Desc         string
	Category     string
	NeedsProject bool
	// NeedsAuth signals that the check needs an anonymous Firebase Auth idToken.
	// If true and a session was successfully created, ValidateKey calls RunAuth
	// instead of Run. If true but no idToken is available, the check is skipped.
	NeedsAuth bool
	// NeedsProjectNumber signals that the check uses the project NUMBER (digits),
	// not the project slug. Used for resources whose canonical name embeds the
	// project number (e.g. gcf-sources-{projectNumber}-{region}). When true and
	// RunWithNumber is set, ValidateKey calls RunWithNumber instead of Run.
	NeedsProjectNumber bool
	// PoC is a shell command template the user can copy to verify or exploit
	// this finding. {KEY}, {PROJECT}, {PROJECT_NUMBER} placeholders are
	// substituted with the real values at output time. Populated only on
	// vulnerable findings.
	PoC string
	// Run receives the URL-encoded key (already passed through url.QueryEscape).
	// Do NOT call url.QueryEscape again inside check functions.
	Run func(key, projectID string) CheckResult
	// RunAuth is the auth-aware variant for checks that ride Firebase Security
	// Rules instead of IAM (Firestore, RTDB, Storage). Receives the same
	// URL-encoded key plus the anonymous-signup idToken. Only one of Run /
	// RunAuth needs to be set.
	RunAuth func(key, projectID, idToken string) CheckResult
	// RunWithNumber is the project-number variant. Receives the URL-encoded
	// key, the project slug (if known), and the project number. Used by
	// resource-bucket checks whose names embed the project number.
	RunWithNumber func(key, projectID, projectNumber string) CheckResult
}

type CheckResult struct {
	Service     string `json:"service"`
	Category    string `json:"category"`
	Status      Status `json:"-"`
	StatusS     string `json:"status"`
	Description string `json:"description,omitempty"`
	Detail      string `json:"detail"`
	PoC         string `json:"poc,omitempty"`
	RawJSON     string `json:"raw_json,omitempty"`
}

type KeyResult struct {
	Key                string        `json:"key"`
	ProjectID          string        `json:"project_id"`
	ProjectNumber      string        `json:"project_number,omitempty"`
	ProjectIDDiscovery []string      `json:"project_id_discovery,omitempty"`
	Timestamp          string        `json:"timestamp"`
	Results            []CheckResult `json:"results"`
}

// ─── Gateway + discovery infrastructure ─────────────────────────────────────

type gatewayResult struct {
	status    string // "ok", "forbidden", "invalid", "error"
	projectID string
	errMsg    string
	// Resource Manager result (populated on 200/403 so check4_1 is not needed)
	rmResult *CheckResult
}

// firebaseSession captures the credentials produced by an anonymous Firebase
// Auth signup. The localID is needed to delete the user during cleanup.
type firebaseSession struct {
	idToken      string
	refreshToken string
	localID      string
}

type discoveryAccum struct {
	ctx          context.Context    // cancelled as soon as any method finds an ID
	cancel       context.CancelFunc // signal to abort remaining discovery probes
	mu           sync.Mutex
	ids          []string // alphanumeric project IDs, in arrival order
	numbers      []string // numeric project numbers, in arrival order
	methodHits   []string // human-readable "method=value" entries for the audit trail
	cachedChecks map[string]CheckResult
	session      firebaseSession // anonymous session captured during signup (if successful)
}
