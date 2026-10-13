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
	"github.com/nis2rem/k8s-remediate-nis2/internal/version"
)

const (
	StatusRemediated      = "remediated"
	StatusGuidanceOnly    = "guidance only"
	StatusNoMapping       = "no mapping"
	StatusInvalidResource = "skipped: invalid resource id"
)

type SummaryRow struct {
	Scanner    string
	CheckID    string
	ResourceID string
	Severity   string
	Region     string
	Articles   []string
	Files      []string
	Status     string
	Note       string
}

func cell(s string) string {
	return strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\\", "\\\\", "|", "\\|", "<", "&lt;", ">", "&gt;").Replace(s)
}

func cells(items []string) string {
	esc := make([]string, len(items))
	for i, it := range items {
		esc[i] = cell(it)
	}
	return strings.Join(esc, ", ")
}

func Write(outDir string, files []render.RenderedFile, rows []SummaryRow) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for _, f := range files {
		rel := filepath.FromSlash(f.RelPath)
		if !filepath.IsLocal(rel) {
			return fmt.Errorf("refusing to write outside the output directory: %q", f.RelPath)
		}
		p := filepath.Join(outDir, rel)
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
	fmt.Fprintln(&b, "| Scanner | Check | Resource | Articles | Generated | Status | Note |")
	fmt.Fprintln(&b, "|---|---|---|---|---|---|---|")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			cell(r.Scanner), cell(r.CheckID), cell(r.ResourceID),
			cells(r.Articles), cells(r.Files), cell(r.Status), cell(r.Note))
	}
	return os.WriteFile(filepath.Join(outDir, "mapping.md"), []byte(b.String()), 0o644)
}

func WriteEvidence(outDir string, findings []finding.Finding, rows []SummaryRow, inputs []string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var b strings.Builder
	fmt.Fprintln(&b, "# Remediation evidence report")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "> **Technical Remediation & Evidence Assistant for NIS2/DORA.**",
		"This tool does not certify compliance; risk acceptance remains with the client's management.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Generated: %s | Tool: k8s-remediate-nis2 %s | Findings: %d | Failed: %d | Remediated: %d | Guidance only: %d | Unmapped: %d | Skipped: %d\n",
		now, version.Version, len(findings), len(rows),
		count(rows, StatusRemediated), count(rows, StatusGuidanceOnly),
		count(rows, StatusNoMapping), count(rows, StatusInvalidResource))
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Input integrity")
	fmt.Fprintln(&b)
	for _, in := range inputs {
		sum, err := fileSHA256(in)
		if err != nil {
			fmt.Fprintf(&b, "- `%s` - unreadable: %v\n", cell(in), err)
			continue
		}
		fmt.Fprintf(&b, "- `%s` - SHA-256 `%s`\n", cell(in), sum)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Failed findings and mappings")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Scanner | Check | Resource | Severity | Region | Status | Articles | Files | Note |")
	fmt.Fprintln(&b, "|---|---|---|---|---|---|---|---|---|")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			cell(r.Scanner), cell(r.CheckID), cell(r.ResourceID), cell(r.Severity), cell(r.Region),
			cell(r.Status), cells(r.Articles), cells(r.Files), cell(r.Note))
	}
	return os.WriteFile(filepath.Join(outDir, "evidence.md"), []byte(b.String()), 0o644)
}

func count(rows []SummaryRow, status string) int {
	n := 0
	for _, r := range rows {
		if r.Status == status {
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
