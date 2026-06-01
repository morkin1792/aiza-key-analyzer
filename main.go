// aiza-key-analyzer — Google API Key Analyzer
//
// Validates leaked Google AIza API Keys (AIzaSy...), determines which Google APIs
// a key can access, collecting non-destructive PoC data to demonstrate impact.
//
// This file is the binary entry point. The scan engine, every check, the
// output renderer and the discovery pipeline all live in internal/analyzer.
// Keep this file focused on flag parsing and orchestration only.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/morkin1792/aiza-key-analyzer/internal/analyzer"
)

func main() {
	flagKey := flag.String("k", "", "Single API key")
	flagFile := flag.String("f", "", "Input file containing keys to test. One per line.")
	flagProject := flag.String("project-id", "", "Fallback GCP Project ID — used when discovery can't find the slug (e.g. Firebase Storage/RTDB probes need a slug, not a number)")
	flagVerbose := flag.Bool("v", false, "Verbose: print full raw JSON responses + every check's result (default hides FORBIDDEN / NOT_CONFIRMED rows)")
	flagWorkers := flag.Int("w", 5, "Worker pool size — number of keys scanned in parallel")
	flagJsonl := flag.String("j", "", "Append every key's full result (every check) to this file as JSONL — useful for automation")
	flagOutput := flag.String("o", "", "Save a human-readable summary of findings to this file (appends to existing content).")
	flagCategories := flag.String("categories", "", "Comma-separated category allow-list (GCP, Firebase, Maps, Search, AI, Media, Identity) — only checks whose Category matches will run")
	flagTimeout := flag.Int("timeout", 30, "Per-request HTTP timeout in seconds")
	flagDualStack := flag.Bool("dual-stack", false, "Allow IPv6 (dual-stack) dialing. By default the analyzer dials IPv4 only, which avoids 'connect: network is unreachable' errors on hosts whose IPv6 route is present but black-holed. Set this only if you actually need IPv6 (e.g. an IPv6-only network).")
	flagProxy := flag.String("proxy", "", "Route every HTTP request through this proxy (e.g. http://127.0.0.1:8080). Useful for inspecting traffic in Burp/mitmproxy. TLS verification is disabled while -proxy is set.")
	flagTestPhone := flag.String("test-phone", "", "E.164 phone number you control (e.g. +15551234567); opts into the SMS-abuse check. Will SEND a real SMS to this number if the project allows it.")
	flagTestEmail := flag.String("test-email", "", "An email address you control; opts into the password-reset-spam check. Will SEND a real email to this address if the project allows it.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Scans leaked Google API keys (AIza...) and reports potential findings for each key, together with their PoCs.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  # Simple")
		fmt.Fprintln(os.Stderr, "  cat keys.txt | aiza-key-analyzer")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  # Complete")
		fmt.Fprintln(os.Stderr, "  aiza-key-analyzer -f keys.txt -o findings.md -project-id my-project-dev -test-phone +15551234567 -test-email me@mybox.example -proxy http://127.0.0.1:8080")
	}
	flag.Parse()

	analyzer.Verbose = *flagVerbose

	transport := &http.Transport{
		// Close pooled idle connections after 30s so Go beats the server (and
		// most proxies) to closing them. Without this, parallelized scans hit
		// the "http: server closed idle connection" race surprisingly often
		// because requests get pulled from the pool right as the server
		// expires the keep-alive.
		IdleConnTimeout: 30 * time.Second,
	}

	// Force IPv4 by default. Google's API hosts publish both A and AAAA
	// records; on a machine whose IPv6 route exists but is black-holed, Go's
	// dual-stack dialer keeps surfacing "connect: network is unreachable"
	// against the AAAA addresses (and the wasted attempts also push other
	// requests past the timeout). Rewriting tcp/tcp6 to tcp4 sidesteps IPv6
	// entirely. -dual-stack restores the stdlib default for IPv6-only nets.
	if !*flagDualStack {
		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network == "tcp" || network == "tcp6" {
				network = "tcp4"
			}
			return dialer.DialContext(ctx, network, addr)
		}
	}
	if *flagProxy != "" {
		proxyURL, err := url.Parse(*flagProxy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid -proxy URL %q: %v\n", *flagProxy, err)
			os.Exit(1)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		// Burp / mitmproxy use self-signed certs by default. Skipping TLS
		// verification while proxied is the pragmatic choice — the operator
		// just opted into inspecting every byte anyway.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		// Burp closes idle keep-alives much more aggressively than upstream
		// servers (default ~10s), which makes the stale-conn race extremely
		// likely on proxied scans. Bypass the pool entirely — each request
		// gets a fresh connection. The extra handshake overhead is fine for
		// scan-time pentesting.
		transport.DisableKeepAlives = true
	}
	analyzer.Client = &http.Client{
		Timeout:   time.Duration(*flagTimeout) * time.Second,
		Transport: transport,
	}

	keys := analyzer.CollectKeys(*flagKey, *flagFile)
	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "No keys provided. Use -k, -f, or pipe via stdin.")
		flag.Usage()
		os.Exit(1)
	}

	// Warn about keys that don't match expected format, with specific credential type hints
	for _, k := range keys {
		if !analyzer.KeyPattern.MatchString(k) {
			trimmed := strings.TrimSpace(k)
			switch {
			case strings.HasPrefix(trimmed, "ya29."):
				fmt.Fprintf(os.Stderr, "[WARN] %q looks like an OAuth2 access token, not an API key\n", trimmed)
			case strings.HasPrefix(trimmed, "{"):
				preview := trimmed
				if len(preview) > 40 {
					preview = preview[:40] + "..."
				}
				fmt.Fprintf(os.Stderr, "[WARN] %q appears to be JSON (service account key?), not an API key\n", preview)
			case strings.HasPrefix(trimmed, "GOCSPX-") || strings.HasPrefix(trimmed, "GOOG"):
				fmt.Fprintf(os.Stderr, "[WARN] %q looks like an OAuth client secret, not an API key\n", trimmed)
			default:
				fmt.Fprintf(os.Stderr, "[WARN] Key %q does not match expected AIzaSy... format\n", k)
			}
		}
	}

	checks := analyzer.BuildChecks(*flagTestPhone, *flagTestEmail)

	// Filter by category if specified
	if *flagCategories != "" {
		allowed := make(map[string]bool)
		for _, c := range strings.Split(*flagCategories, ",") {
			allowed[strings.TrimSpace(c)] = true
		}
		var filtered []analyzer.ServiceCheck
		for _, c := range checks {
			if allowed[c.Category] {
				filtered = append(filtered, c)
			}
		}
		checks = filtered
	}

	var jsonlFile *os.File
	if *flagJsonl != "" {
		var err error
		jsonlFile, err = os.OpenFile(*flagJsonl, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening JSONL file: %v\n", err)
			os.Exit(1)
		}
		defer jsonlFile.Close()
	}

	var outputFile *os.File
	if *flagOutput != "" {
		var err error
		outputFile, err = os.OpenFile(*flagOutput, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
			os.Exit(1)
		}
		defer outputFile.Close()
		// Top-of-document Markdown header for the file.
		fmt.Fprint(outputFile, analyzer.MarkdownFindingsHeader)
	}

	var outputMu sync.Mutex

	// With multiple keys, per-check live output from parallel goroutines
	// interleaves into nonsense. Suppress it and rely on the grouped
	// summaries at the end. Single-key runs keep their live trace.
	if len(keys) > 1 && analyzer.Silent == 0 {
		analyzer.Silent = 1
	}

	// Multi-key runs lose the per-key check spinner (it's silenced above), so
	// show one overall "N/Total keys" progress line on stderr instead.
	var keyProgress *analyzer.MultiKeyProgress
	if len(keys) > 1 {
		keyProgress = analyzer.NewMultiKeyProgress(len(keys))
		keyProgress.Start()
	}

	sem := make(chan struct{}, *flagWorkers)
	var wg sync.WaitGroup
	allResults := make([]analyzer.KeyResult, len(keys))

	for i, key := range keys {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, k string) {
			defer wg.Done()
			defer func() { <-sem }()
			kr := analyzer.ValidateKey(k, *flagProject, checks)
			allResults[idx] = kr
			if keyProgress != nil {
				keyProgress.Tick()
			}

			if jsonlFile != nil {
				data, err := json.Marshal(kr)
				if err == nil {
					outputMu.Lock()
					jsonlFile.Write(data)
					jsonlFile.Write([]byte("\n"))
					outputMu.Unlock()
				}
			}

			if outputFile != nil {
				// Same Markdown the terminal renders (without colors).
				outputMu.Lock()
				analyzer.WriteKeyMarkdown(outputFile, kr)
				outputMu.Unlock()
			}
		}(i, key)
	}
	wg.Wait()
	if keyProgress != nil {
		keyProgress.Stop()
	}

	// Print summaries together, in input order, so multi-key runs are
	// readable end-to-end instead of interleaved.
	if analyzer.Silent < 2 {
		analyzer.PrintFindingsHeader()
	}
	for _, kr := range allResults {
		analyzer.PrintSummary(kr)
	}
}
