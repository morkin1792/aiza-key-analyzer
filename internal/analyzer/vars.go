package analyzer

import (
	"net/http"
	"regexp"
	"sync"

	"github.com/fatih/color"
)

// ─── Package-level globals ──────────────────────────────────────────────────
//
// Per-check local constants (PoC templates, common-name wordlists, etc.)
// live next to the check they belong to, not here.

var (
	Client         *http.Client
	Verbose        bool
	Silent         int // 0=normal, 1=summary-only, 2=no output
	printMu        sync.Mutex
	KeyPattern     = regexp.MustCompile(`^AIza[0-9A-Za-z_-]{35}$`)
	colorConfirmed = color.New(color.FgGreen, color.Bold)
	colorPot       = color.New(color.FgHiYellow, color.Bold)
	colorForb      = color.New(color.FgYellow)
	colorNV        = color.New(color.FgBlue)
	colorInv       = color.New(color.FgMagenta)
	colorErr       = color.New(color.FgCyan)
	// Structural colors for the terminal findings render (file output stays
	// plain Markdown). colorHeading greens the "# Findings" header;
	// colorKeyHeading is bold bright-blue for each "## <key>" header (more
	// legible than green against the green finding rows); colorBullet greens
	// the leading "-" of each topic line; colorLabelBold bolds the
	// "Evidence:" label on the terminal only.
	colorHeading    = color.New(color.FgGreen, color.Bold)
	colorKeyHeading = color.New(color.FgGreen, color.Bold)
	colorBullet     = color.New(color.FgGreen)
	colorLabelBold  = color.New(color.Bold)
)
