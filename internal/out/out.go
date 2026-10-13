package out

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nis2rem/k8s-remediate-nis2/internal/finding"
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

func WriteEvidence(outDir string, findings []finding.Finding, rows []SummaryRow, inputs []string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	var b strings.Builder
	fmt.Fprintln(&b, "# Remediation evidence report")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "> **Technical Remediation & Evidence Assistant for NIS2/DORA.**",
		"This tool does not certify compliance; risk acceptance remains with the client's management.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Generated: %s · Tool: k8s-remediate-nis2 v0.1.0 · Findings: %d · Remediated: %d\n",
		now, len(findings), countRemediated(rows))
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Input integrity")
	fmt.Fprintln(&b)
	for _, in := range inputs {
		sum, err := fileSHA256(in)
		if err != nil {
			fmt.Fprintf(&b, "- `%s` — unreadable: %v\n", in, err)
			continue
		}
		fmt.Fprintf(&b, "- `%s` — SHA-256 `%s`\n", in, sum)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Findings and mappings")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Scanner | Check | Resource | Status | Articles | Files |")
	fmt.Fprintln(&b, "|---|---|---|---|---|---|")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
			r.Scanner, r.CheckID, r.ResourceID, r.Status,
			strings.Join(r.Articles, ", "), strings.Join(r.Files, ", "))
	}
	return os.WriteFile(filepath.Join(outDir, "evidence.md"), []byte(b.String()), 0o644)
}

func countRemediated(rows []SummaryRow) int {
	n := 0
	for _, r := range rows {
		if r.Status == "remediated" {
			n++
		}
	}
	return n
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
