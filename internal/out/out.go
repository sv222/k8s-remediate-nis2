package out

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nis2rem/k8s-remediate-nis2/internal/render"
)

type SummaryRow struct {
	Scanner    string
	CheckID    string
	ResourceID string
	Articles   []string
	Files      []string
	Status     string
}

func Write(outDir string, files []render.RenderedFile, rows []SummaryRow) error {
	for _, f := range files {
		p := filepath.Join(outDir, f.RelPath)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(f.Content), 0o644); err != nil {
			return err
		}
	}
	var b strings.Builder
	fmt.Fprintln(&b, "# Remediation mapping")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Scanner | Check | Resource | Articles | Generated | Status |")
	fmt.Fprintln(&b, "|---|---|---|---|---|---|")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
			r.Scanner, r.CheckID, r.ResourceID,
			strings.Join(r.Articles, ", "), strings.Join(r.Files, ", "), r.Status)
	}
	return os.WriteFile(filepath.Join(outDir, "mapping.md"), []byte(b.String()), 0o644)
}
