package analyzer

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
)

// ─── Output ──────────────────────────────────────────────────────────────────
//
// The summary is rendered as Markdown — same content for the terminal and
// the -o file. Terminal output gets ANSI colors on the H3 finding headings
// so CONFIRMED vs POTENTIAL is visible at a glance; the -o file gets plain
// Markdown so it can be pasted into a report, GitHub issue, Notion page,
// etc. without scrubbing escape codes.

// showResult returns true when a per-check row should be printed to the
// console as the scan runs. CONFIRMED/POTENTIAL rows are intentionally not
// shown live — they'd just repeat the FINDINGS section that prints at the
// end. ERROR is kept visible because it signals operator problems (timeouts,
// malformed config) the user usually wants to see while the scan is still
// happening. `-v` (Verbose) shows everything.
func showResult(s Status) bool {
	if Verbose {
		return true
	}
	switch s {
	case StatusError, StatusInvalid:
		return true
	default:
		return false
	}
}

func printResult(r CheckResult) {
	if Silent > 0 || !showResult(r.Status) {
		return
	}
	printMu.Lock()
	defer printMu.Unlock()

	var tag string
	switch r.Status {
	case StatusConfirmed:
		tag = colorConfirmed.Sprintf("[CONFIRMED]    ")
	case StatusPotential:
		tag = colorPot.Sprintf("[POTENTIAL]     ")
	case StatusForbidden:
		tag = colorForb.Sprintf("[FORBIDDEN]     ")
	case StatusNotVulnerable:
		tag = colorNV.Sprintf("[NOT VULNERABLE]")
	case StatusInvalid:
		tag = colorInv.Sprintf("[INVALID]       ")
	case StatusError:
		tag = colorErr.Sprintf("[ERROR]         ")
	}

	cat := r.Category
	if cat == "" {
		cat = "---"
	}
	fmt.Printf("%-16s %-8s / %-25s | %s\n", tag, cat, r.Service, r.Detail)

	if Verbose && r.RawJSON != "" {
		fmt.Println("  RAW:", r.RawJSON)
	}
}

// MarkdownFindingsHeader is the top-level "# Findings" heading printed once
// before any per-key block. The -o file consumes this plain constant; the
// terminal uses PrintFindingsHeader for the greened version.
const MarkdownFindingsHeader = "# Findings\n"

// PrintFindingsHeader writes the top-level "# Findings" heading to stdout,
// greened for the terminal. The -o file uses the plain MarkdownFindingsHeader
// constant instead so the report stays clean Markdown.
func PrintFindingsHeader() {
	fmt.Print(colorHeading.Sprint("# Findings") + "\n")
}

// WriteKeyMarkdown emits one key's findings as Markdown to w. Used for the
// -o file (no colors). For stdout we use the colored variant on the H3
// headings via writeKeyMarkdownColored.
func WriteKeyMarkdown(w io.Writer, kr KeyResult) {
	fmt.Fprint(w, renderKeyMarkdown(kr, false))
}

// PrintSummary prints one key's Markdown findings block to stdout, with
// ANSI color on the H3 headings.
func PrintSummary(kr KeyResult) {
	if Silent > 1 {
		return
	}
	printMu.Lock()
	defer printMu.Unlock()

	// Gateway-level early-exit cases: invalid / error keys don't get the
	// full findings block — show a single-line status instead.
	for _, c := range kr.Results {
		if c.Service == "Gateway" && (c.Status == StatusInvalid || c.Status == StatusError) {
			fmt.Printf("\n%s\n%s Status: ", colorKeyHeading.Sprint("## "+kr.Key), colorBullet.Sprint("-"))
			if c.Status == StatusInvalid {
				colorInv.Print("INVALID")
			} else {
				colorErr.Print("ERROR")
			}
			fmt.Printf(" — %s\n\n", c.Detail)
			return
		}
	}

	fmt.Print(renderKeyMarkdown(kr, true))
}

// renderKeyMarkdown builds the Markdown for one key: the "## <key>" header and
// project metadata, a "### Summary Table" listing every finding with its
// status, then "### Findings" with one "#### [Category] Service" block each.
// If colored (terminal output), the "## <key>" header is blue, section
// headings are greened, finding headings + table statuses are greened/yellowed
// by status, each topic's leading "-" is greened, and the "Evidence:" label is
// bolded. If not colored (the -o file), everything is plain Markdown.
func renderKeyMarkdown(kr KeyResult, colored bool) string {
	var b strings.Builder

	// Leading "-" for topic lines: greened on the terminal, plain in the file.
	dash := "-"
	if colored {
		dash = colorBullet.Sprint("-")
	}

	keyHeading := fmt.Sprintf("## %s", kr.Key)
	if colored {
		keyHeading = colorKeyHeading.Sprint(keyHeading)
	}
	b.WriteString("\n" + keyHeading + "\n")

	if kr.ProjectID != "" {
		idLabel := "project_id"
		if isProjectNumber(kr.ProjectID) {
			idLabel = "project_number"
		}
		b.WriteString(fmt.Sprintf("%s %s: %s\n", dash, idLabel, kr.ProjectID))
		if len(kr.ProjectIDDiscovery) > 0 {
			b.WriteString(fmt.Sprintf("%s project_id source: %s\n", dash, strings.Join(kr.ProjectIDDiscovery, "; ")))
		}
		if isProjectNumber(kr.ProjectID) {
			b.WriteString(fmt.Sprintf("%s note: slug not discovered; some Firebase tests (RTDB/Storage) need the slug and were skipped — pass it via -project-id if you know it.\n", dash))
		}
	}

	// Collect the renderable findings (CONFIRMED/POTENTIAL) once, in
	// buildChecks() order — that order groups by Category so a reader sees one
	// product surface at a time. The same slice feeds the count lines, the
	// summary table, and the detailed findings section.
	var findings []CheckResult
	for _, c := range kr.Results {
		switch c.Status {
		case StatusConfirmed, StatusPotential:
			findings = append(findings, c)
		}
	}
	if len(findings) > 0 {
		b.WriteString(fmt.Sprintf("%s Found findings: %d\n", dash, len(findings)))
	}
	b.WriteString("\n")

	if len(findings) == 0 {
		b.WriteString("_No findings — the key looks well-restricted for every probe._\n\n")
		return b.String()
	}

	// ── Summary table: one row per finding, for an at-a-glance overview
	// before the detailed section. ───────────────────────────────────────────
	summaryHeading := "### Summary Table"
	if colored {
		summaryHeading = colorHeading.Sprint(summaryHeading)
	}
	b.WriteString(summaryHeading + "\n")
	b.WriteString("| Finding | Status |\n")
	b.WriteString("| --- | --- |\n")
	for _, c := range findings {
		status := statusWord(c.Status)
		if colored {
			status = colorForStatus(c.Status).Sprint(status)
		}
		b.WriteString(fmt.Sprintf("| [%s] %s | %s |\n", c.Category, c.Service, status))
	}
	b.WriteString("\n")

	// ── Detailed findings ─────────────────────────────────────────────────────
	findingsHeading := "### Findings"
	if colored {
		findingsHeading = colorHeading.Sprint(findingsHeading)
	}
	b.WriteString(findingsHeading + "\n\n")

	for _, c := range findings {
		heading := fmt.Sprintf("#### [%s] %s", c.Category, c.Service)
		if colored {
			heading = colorForStatus(c.Status).Sprint(heading)
		}
		b.WriteString(heading + "\n")

		statusLine := "CONFIRMED ✅"
		if c.Status == StatusPotential {
			statusLine = "POTENTIAL ⚠️"
		}
		b.WriteString(fmt.Sprintf("%s Status: %s\n", dash, statusLine))
		// Description = static explanation of the finding; Evidence = the
		// dynamic per-run proof (counts, sample data, response values). When
		// a check predates the Desc field, fall back to showing Detail as the
		// Description so nothing renders blank.
		if c.Description != "" {
			b.WriteString(fmt.Sprintf("%s Description: %s\n", dash, c.Description))
			// Evidence is optional: it renders only when the check supplied a
			// dynamic, run-specific Detail (counts, names, paths, sample data).
			// Checks whose Detail was just a static restatement of the finding
			// leave Detail empty, so no Evidence line appears here. The label is
			// bolded on the terminal only; the file keeps it plain.
			if c.Detail != "" {
				label := "Evidence:"
				if colored {
					label = colorLabelBold.Sprint(label)
				}
				b.WriteString(fmt.Sprintf("%s %s %s\n", dash, label, c.Detail))
			}
		} else {
			b.WriteString(fmt.Sprintf("%s Description: %s\n", dash, c.Detail))
		}

		if c.PoC != "" {
			b.WriteString(fmt.Sprintf("%s PoC:\n", dash))
			b.WriteString("```\n")
			b.WriteString(c.PoC)
			if !strings.HasSuffix(c.PoC, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("```\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}

// statusWord is the title-case status label used in the summary table.
func statusWord(s Status) string {
	if s == StatusPotential {
		return "Potential"
	}
	return "Confirmed"
}

// colorForStatus maps a finding status to its terminal color (green for
// CONFIRMED, yellow for POTENTIAL). Callers gate this on `colored`.
func colorForStatus(s Status) *color.Color {
	if s == StatusPotential {
		return colorPot
	}
	return colorConfirmed
}
