package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// CollectKeys gathers API keys from the priority chain: -k flag → -f file →
// stdin. Returns an empty slice if nothing was provided; callers should treat
// that as a usage error.
func CollectKeys(flagKey, flagFile string) []string {
	var keys []string

	if flagKey != "" {
		keys = append(keys, strings.TrimSpace(flagKey))
		return keys
	}

	if flagFile != "" {
		data, err := os.ReadFile(flagFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", flagFile, err)
			os.Exit(1)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				keys = append(keys, line)
			}
		}
		return keys
	}

	// Try stdin
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line != "" {
				keys = append(keys, line)
			}
		}
	}

	return keys
}
