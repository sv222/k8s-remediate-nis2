package out

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sv222/k8s-remediate-nis2/internal/render"
	"github.com/sv222/k8s-remediate-nis2/internal/version"
	"github.com/sv222/k8s-remediate-nis2/mapping"
)

const (
	StatusCodeGenerated = "code generated"
	StatusFollowUp      = "follow-up required"
	StatusGuidanceOnly  = "guidance only"
	StatusNoMapping     = "no mapping"
	StatusSkipped       = "skipped"

	ManifestName = "manifest.json"
	maxTokenLen  = 256
)

type SummaryRow struct {
	Scanner    string
	CheckID    string
	ResourceID string
	Severity   string
	Region     string
	Account    string
	Articles   []string
	Files      []string
	Status     string
	Note       string
}

type Item struct {
	Scanner    string
	CheckID    string
	ResourceID string
	Status     string
	Region     string
	Account    string
}

type Stats struct {
	Records     int
	Failed      int
	ManualWarn  int
	Manual      int
	Other       int
	Passed      int
	Suppressed  int
	Duplicates  int
	Unsupported int
}

type Input struct {
	Path   string
	SHA256 string
}

type Report struct {
	Rows       []SummaryRow
	Stats      Stats
	Inputs     []Input
	Accounts   []string
	Manual     []Item
	Suppressed []Item
}

type Manifest struct {
	Tool          string         `json:"tool"`
	Version       string         `json:"version"`
	MappingVer    int            `json:"mapping_version"`
	MappingSHA256 string         `json:"mapping_sha256"`
	Files         []ManifestFile `json:"files"`
}

type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func isTokenRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("._:/@+=,-", r)
}

func code(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxTokenLen {
			break
		}
		if isTokenRune(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
		n++
	}
	if b.Len() == 0 {
		return ""
	}
	return "`" + b.String() + "`"
}

func codes(items []string) string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		if c := code(it); c != "" {
			out = append(out, c)
		}
	}
	return strings.Join(out, ", ")
}

func looseCode(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '`' || r < 0x20 || r == 0x7f {
			return '\''
		}
		return r
	}, s)
	return "`" + s + "`"
}

func cell(s string) string {
	return strings.NewReplacer(
		"\r\n", " ", "\n", " ", "\r", " ",
		"\\", "\\\\", "|", "\\|", "`", "\\`",
		"[", "\\[", "]", "\\]", "!", "\\!", "*", "\\*",
		"<", "&lt;", ">", "&gt;",
	).Replace(s)
}

func cells(items []string) string {
	esc := make([]string, len(items))
	for i, it := range items {
		esc[i] = cell(it)
	}
	return strings.Join(esc, ", ")
}

func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func prepareDir(outDir string, force bool) error {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return os.MkdirAll(outDir, 0o755)
		}
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if !force {
		return fmt.Errorf("output directory %s is not empty: use an empty directory, or --force to replace the files of a previous run", outDir)
	}
	return removePrevious(outDir)
}

func removePrevious(outDir string) error {
	data, err := os.ReadFile(filepath.Join(outDir, ManifestName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("%s in %s is not valid, remove it by hand: %w", ManifestName, outDir, err)
	}
	dirs := map[string]bool{}
	for _, f := range m.Files {
		rel := filepath.FromSlash(f.Path)
		if !filepath.IsLocal(rel) {
			return fmt.Errorf("%s lists a path outside the output directory: %q", ManifestName, f.Path)
		}
		p := filepath.Join(outDir, rel)
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if d := filepath.Dir(rel); d != "." {
			dirs[d] = true
		}
	}
	for d := range dirs {
		_ = os.Remove(filepath.Join(outDir, d))
	}
	if err := os.Remove(filepath.Join(outDir, ManifestName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func Write(outDir string, force bool, files []render.RenderedFile, rep Report, evidence bool) error {
	if err := prepareDir(outDir, force); err != nil {
		return err
	}
	var manifest []ManifestFile
	write := func(rel string, data []byte) error {
		r := filepath.FromSlash(rel)
		if !filepath.IsLocal(r) {
			return fmt.Errorf("refusing to write outside the output directory: %q", rel)
		}
		p := filepath.Join(outDir, r)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return err
		}
		manifest = append(manifest, ManifestFile{Path: filepath.ToSlash(rel), SHA256: sha(data)})
		return nil
	}
	for _, f := range files {
		if err := write(f.RelPath, []byte(f.Content)); err != nil {
			return err
		}
	}
	if err := write("mapping.md", []byte(mappingMD(rep))); err != nil {
		return err
	}
	if evidence {
		if err := write("evidence.md", []byte(evidenceMD(files, rep, time.Now()))); err != nil {
			return err
		}
	}
	mv, msha := mapping.Info()
	data, err := json.MarshalIndent(Manifest{
		Tool: "k8s-remediate-nis2", Version: version.Get(), MappingVer: mv, MappingSHA256: msha, Files: manifest,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, ManifestName), append(data, '\n'), 0o644)
}

const disclaimer = "> **Technical Remediation & Evidence Assistant for NIS2/DORA.** " +
	"This tool does not certify compliance; risk acceptance remains with the client's management."

func mappingMD(rep Report) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Remediation mapping")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, disclaimer)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "> **Nothing was applied.** Generated files are proposals. Status `code generated` or `follow-up required`",
		"does not mean the finding is fixed. See the Note column for what stays open.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Scanner | Check | Resource | Articles | Generated | Status | Note |")
	fmt.Fprintln(&b, "|---|---|---|---|---|---|---|")
	for _, r := range rep.Rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			code(r.Scanner), code(r.CheckID), code(r.ResourceID),
			cells(r.Articles), codes(r.Files), cell(r.Status), cell(r.Note))
	}
	return b.String()
}

func evidenceMD(files []render.RenderedFile, rep Report, now time.Time) string {
	st := rep.Stats
	mv, msha := mapping.Info()
	var b strings.Builder
	fmt.Fprintln(&b, "# Remediation evidence report")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, disclaimer)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "> **Nothing in this report was applied.** This tool only generates proposals. It changed no AWS account and no cluster.",
		"A row with status `code generated` or `follow-up required` is not a closed finding. Re-scan after you apply the changes.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Generated (UTC): %s, from the clock of the machine that ran the tool | Tool: k8s-remediate-nis2 %s | Mapping: version %d, SHA-256 `%s`\n",
		now.UTC().Format(time.RFC3339), cell(version.Get()), mv, msha)
	fmt.Fprintln(&b)
	if len(rep.Accounts) > 0 {
		fmt.Fprintf(&b, "AWS account: %s\n\n", codes(rep.Accounts))
	}
	fmt.Fprintln(&b, "## Summary")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Records read: %d | Failed findings (FAIL): %d | Manual WARN treated as gap: %d | Passed: %d | Manual or not assessed: %d | Other status: %d | Suppressed (muted): %d | Duplicate records ignored: %d\n",
		st.Records, st.Failed, st.ManualWarn, st.Passed, st.Manual, st.Other, st.Suppressed, st.Duplicates)
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Status of the %d rows below: code generated: %d | follow-up required: %d | guidance only: %d | no mapping: %d | skipped: %d\n",
		len(rep.Rows), count(rep.Rows, StatusCodeGenerated), count(rep.Rows, StatusFollowUp),
		count(rep.Rows, StatusGuidanceOnly), count(rep.Rows, StatusNoMapping), count(rep.Rows, StatusSkipped))
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "- `code generated`: a file was written. It is not applied. Apply it, then re-scan.")
	fmt.Fprintln(&b, "- `follow-up required`: a file was written, but the risk stays open until you do more (see Note).")
	fmt.Fprintln(&b, "- `guidance only`: no code is safe to generate. The Note lists manual steps.")
	fmt.Fprintln(&b, "- `no mapping`: the tool has no mapping for this check.")
	fmt.Fprintln(&b, "- `skipped`: the tool did not act on the finding (see Note).")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Input integrity")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "SHA-256 of the exact bytes that were parsed.")
	fmt.Fprintln(&b)
	for _, in := range rep.Inputs {
		fmt.Fprintf(&b, "- %s - SHA-256 `%s`\n", looseCode(in.Path), in.SHA256)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Generated files")
	fmt.Fprintln(&b)
	if len(files) == 0 {
		fmt.Fprintln(&b, "No files were generated.")
	}
	for _, f := range files {
		fmt.Fprintf(&b, "- %s - SHA-256 `%s`\n", code(f.RelPath), sha([]byte(f.Content)))
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Failed findings and mappings")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Scanner | Check | Resource | Severity | Region | Account | Status | Articles | Files | Note |")
	fmt.Fprintln(&b, "|---|---|---|---|---|---|---|---|---|---|")
	for _, r := range rep.Rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			code(r.Scanner), code(r.CheckID), code(r.ResourceID), code(r.Severity), code(r.Region), code(r.Account),
			cell(r.Status), cells(r.Articles), codes(r.Files), cell(r.Note))
	}
	writeItems(&b, "Manual or not assessed by the scanner", rep.Manual)
	writeItems(&b, "Suppressed (muted) findings, not remediated", rep.Suppressed)
	return b.String()
}

func writeItems(b *strings.Builder, title string, items []Item) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintln(b)
	fmt.Fprintf(b, "## %s\n\n", title)
	fmt.Fprintln(b, "| Scanner | Check | Resource | Status | Region | Account |")
	fmt.Fprintln(b, "|---|---|---|---|---|---|")
	for _, it := range items {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s |\n",
			code(it.Scanner), code(it.CheckID), code(it.ResourceID), code(it.Status), code(it.Region), code(it.Account))
	}
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
