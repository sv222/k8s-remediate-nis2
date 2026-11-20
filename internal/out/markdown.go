package out

import (
	"fmt"
	"strings"
)

// Markdown renders the change summary for --format markdown. Findings are
// grouped by check id and title; every remediation target file is listed with
// a one-line resource description. The output depends only on the report, so
// the same input gives byte-identical output on every run.
func Markdown(rep Report) []byte {
	var b strings.Builder
	fmt.Fprintln(&b, "# Remediation summary")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "> Nothing was applied. These are proposals; apply them, then re-scan to confirm the findings are fixed.")
	fmt.Fprintln(&b)
	if len(rep.Rows) == 0 {
		fmt.Fprintln(&b, "No failed findings.")
		return []byte(b.String())
	}
	type group struct {
		id    string
		title string
		rows  []SummaryRow
	}
	groups := []group{}
	index := map[string]int{}
	for _, r := range rep.Rows {
		k := r.Scanner + "\x00" + r.CheckID + "\x00" + r.Title
		gi, ok := index[k]
		if !ok {
			gi = len(groups)
			index[k] = gi
			groups = append(groups, group{id: r.Scanner + "/" + r.CheckID, title: r.Title})
		}
		groups[gi].rows = append(groups[gi].rows, r)
	}
	for i, g := range groups {
		if i > 0 {
			fmt.Fprintln(&b)
		}
		fmt.Fprintf(&b, "## %s", code(g.id))
		if t := cell(g.title); t != "" {
			fmt.Fprintf(&b, " — %s", t)
		}
		fmt.Fprintln(&b)
		fmt.Fprintln(&b)
		for _, r := range g.rows {
			desc := resourceDesc(r)
			switch {
			case desc == "":
				fmt.Fprintf(&b, "- `%s`\n", r.Status)
			case len(r.Files) == 0:
				fmt.Fprintf(&b, "- %s — `%s`\n", desc, r.Status)
			default:
				for _, f := range r.Files {
					fmt.Fprintf(&b, "- %s — %s — `%s`\n", code(f), desc, r.Status)
				}
			}
		}
	}
	return []byte(b.String())
}

// resourceDesc is the one-line description of the remediation target: the
// resource, its region and its account, for the rows that have them.
func resourceDesc(r SummaryRow) string {
	var parts []string
	if c := code(r.ResourceID); c != "" {
		parts = append(parts, c)
	}
	if c := code(r.Region); c != "" {
		parts = append(parts, c)
	}
	if c := code(r.Account); c != "" {
		parts = append(parts, "account "+c)
	}
	return strings.Join(parts, ", ")
}
