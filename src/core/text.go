package core

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// textWidth is the column reasons are wrapped at: $COLUMNS when set, else 100.
func textWidth() int {
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n >= 40 {
		return n - 1
	}

	return 100
}

// wrap word-wraps text to width, prefixing every line with indent. Runs of whitespace,
// including the newlines advisory summaries sometimes carry, become single spaces.
func wrap(text, indent string, width int) string {
	var (
		b    strings.Builder
		line = indent
	)

	for _, word := range strings.Fields(text) {
		if line != indent && len(line)+1+len(word) > width {
			b.WriteString(line + "\n")
			line = indent
		}

		if line != indent {
			line += " "
		}

		line += word
	}

	b.WriteString(line + "\n")

	return b.String()
}

// clip shortens text to width runes, whitespace collapsed, ending in "…" when cut.
func clip(text string, width int) string {
	r := []rune(strings.Join(strings.Fields(text), " "))
	if len(r) <= width {
		return string(r)
	}

	return strings.TrimRight(string(r[:width-1]), " ") + "…"
}

// plural is "1 alert", "2 alerts", "2 advisories".
func plural(n int, word string) string {
	switch {
	case n == 1:
		return fmt.Sprintf("%d %s", n, word)
	case strings.HasSuffix(word, "y"):
		return fmt.Sprintf("%d %sies", n, strings.TrimSuffix(word, "y"))
	default:
		return fmt.Sprintf("%d %ss", n, word)
	}
}

// numberRanges writes alert numbers compactly: #3-8, #10-20.
func numberRanges(numbers []int) string {
	sorted := append([]int(nil), numbers...)
	sort.Ints(sorted)

	var parts []string

	for i := 0; i < len(sorted); {
		j := i
		for j+1 < len(sorted) && sorted[j+1] == sorted[j]+1 {
			j++
		}

		switch {
		case j == i:
			parts = append(parts, fmt.Sprintf("#%d", sorted[i]))
		case j == i+1:
			parts = append(parts, fmt.Sprintf("#%d", sorted[i]), fmt.Sprintf("#%d", sorted[j]))
		default:
			parts = append(parts, fmt.Sprintf("#%d-%d", sorted[i], sorted[j]))
		}

		i = j + 1
	}

	return strings.Join(parts, ", ")
}
