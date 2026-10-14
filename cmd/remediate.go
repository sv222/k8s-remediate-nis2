package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sv222/k8s-remediate-nis2/internal/finding"
	"github.com/sv222/k8s-remediate-nis2/internal/kubebench"
	"github.com/sv222/k8s-remediate-nis2/internal/out"
	"github.com/sv222/k8s-remediate-nis2/internal/prowler"
	"github.com/sv222/k8s-remediate-nis2/internal/render"
	"github.com/sv222/k8s-remediate-nis2/mapping"
)

type options struct {
	prowler   string
	kubeBench string
	outDir    string
	evidence  bool
	force     bool
}

func newRemediateCmd() *cobra.Command {
	var o options
	c := &cobra.Command{
		Use:   "remediate",
		Short: "Generate remediation code from Prowler/kube-bench findings",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return run(c.OutOrStdout(), o)
		},
	}
	c.Flags().StringVar(&o.prowler, "prowler", "", "Prowler JSON report (json-ocsf or legacy json)")
	c.Flags().StringVar(&o.kubeBench, "kube-bench", "", "kube-bench JSON report")
	c.Flags().StringVar(&o.outDir, "out", "./remediation", "output directory (must be empty unless --force is set)")
	c.Flags().BoolVar(&o.evidence, "export-evidence", false, "also write evidence.md for auditors")
	c.Flags().BoolVar(&o.force, "force", false, "allow a non-empty output directory: remove the files listed in its manifest.json, then write")
	return c
}

func loadFindings(o options) ([]finding.Finding, []out.Input, error) {
	var findings []finding.Finding
	var inputs []out.Input
	load := func(path string, parse func([]byte, string) ([]finding.Finding, error)) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fs, err := parse(data, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		inputs = append(inputs, out.Input{Path: path, SHA256: hex.EncodeToString(sum[:])})
		findings = append(findings, fs...)
		return nil
	}
	if o.prowler != "" {
		if err := load(o.prowler, prowler.Parse); err != nil {
			return nil, nil, err
		}
	}
	if o.kubeBench != "" {
		if err := load(o.kubeBench, kubebench.Parse); err != nil {
			return nil, nil, err
		}
	}
	return findings, inputs, nil
}

func dedupe(findings []finding.Finding) ([]finding.Finding, int) {
	seen := map[string]bool{}
	var res []finding.Finding
	dups := 0
	for _, f := range findings {
		key := strings.Join([]string{f.Scanner, f.Benchmark, f.CheckID, f.AccountID, f.Region, f.ResourceID, f.Status, fmt.Sprint(f.Suppressed)}, "\x00")
		if seen[key] {
			dups++
			continue
		}
		seen[key] = true
		res = append(res, f)
	}
	return res, dups
}

func accountsOf(findings []finding.Finding) []string {
	set := map[string]bool{}
	for _, f := range findings {
		if f.AccountID != "" {
			set[f.AccountID] = true
		}
	}
	var accounts []string
	for a := range set {
		accounts = append(accounts, a)
	}
	sort.Strings(accounts)
	return accounts
}

const idNote = "The resource id has unsupported characters and is shown with ? in their place."

type candidate struct {
	f          finding.Finding
	e          mapping.Entry
	mapped     bool
	manualWarn bool
}

func groupKey(c candidate) string {
	return c.e.Group + "|" + render.NormalizeResourceID(c.f.ResourceID)
}

func run(w io.Writer, o options) error {
	if o.prowler == "" && o.kubeBench == "" {
		return errors.New("at least one of --prowler or --kube-bench is required")
	}
	all, inputs, err := loadFindings(o)
	if err != nil {
		return err
	}
	records := len(all)
	findings, dups := dedupe(all)
	accounts := accountsOf(findings)
	if len(accounts) > 1 {
		return fmt.Errorf("the input has findings of %d AWS accounts (%s): the generated files do not say which account they belong to, so run the tool once per account with one report each",
			len(accounts), strings.Join(accounts, ", "))
	}
	rep := out.Report{Inputs: inputs, Accounts: accounts}
	rep.Stats.Records = records
	rep.Stats.Duplicates = dups

	var cands []candidate
	for _, f := range findings {
		item := out.Item{Scanner: f.Scanner, CheckID: f.CheckID, ResourceID: f.ResourceID, Status: f.Status, Region: f.Region, Account: f.AccountID}
		switch {
		case f.Suppressed:
			rep.Stats.Suppressed++
			rep.Suppressed = append(rep.Suppressed, item)
			continue
		case f.Status == "PASS":
			rep.Stats.Passed++
			continue
		case f.Status != "FAIL" && !f.IsManualWarn():
			if f.Manual || f.Status == "MANUAL" {
				rep.Stats.Manual++
				rep.Manual = append(rep.Manual, item)
			} else {
				rep.Stats.Other++
			}
			continue
		}
		e, ok, err := mapping.For(f)
		if err != nil {
			return err
		}
		if !ok && f.IsManualWarn() {
			rep.Stats.Manual++
			rep.Manual = append(rep.Manual, item)
			continue
		}
		if f.IsManualWarn() {
			rep.Stats.ManualWarn++
		} else {
			rep.Stats.Failed++
		}
		cands = append(cands, candidate{f: f, e: e, mapped: ok, manualWarn: f.IsManualWarn()})
	}

	best := map[string]candidate{}
	for _, c := range cands {
		if !c.mapped || c.e.Group == "" {
			continue
		}
		k := groupKey(c)
		if cur, ok := best[k]; !ok || c.e.Rank > cur.e.Rank {
			best[k] = c
		}
	}

	set := render.NewSet()
	for _, c := range cands {
		f, e := c.f, c.e
		row := out.SummaryRow{
			Scanner: f.Scanner, CheckID: f.CheckID, ResourceID: f.ResourceID,
			Severity: f.Severity, Region: f.Region, Account: f.AccountID,
		}
		idErr := render.ValidateResourceID(f.ResourceID)
		if !c.mapped {
			row.Status = out.StatusNoMapping
			if idErr != nil {
				row.Note = idNote
			}
			rep.Rows = append(rep.Rows, row)
			continue
		}
		row.Articles = e.Articles
		if e.Group != "" {
			if w := best[groupKey(c)]; w.e.Rank > e.Rank {
				row.Status = out.StatusSkipped
				row.Note = "Superseded by the stronger fix for the same resource: " + w.e.Title + ". Both would write conflicting Terraform resources."
				rep.Rows = append(rep.Rows, row)
				continue
			}
		}
		rf, err := render.Render(e, f)
		if errors.Is(err, render.ErrInvalidResourceID) {
			row.Status = out.StatusSkipped
			row.Note = err.Error()
			rep.Rows = append(rep.Rows, row)
			continue
		}
		if err != nil {
			return err
		}
		set.Add(rf)
		for _, x := range rf {
			row.Files = append(row.Files, x.RelPath)
		}
		row.Status, row.Note = statusAndNote(e, len(rf) > 0, c.manualWarn)
		if idErr != nil {
			row.Note = strings.TrimSpace(row.Note + " " + idNote)
		}
		rep.Rows = append(rep.Rows, row)
	}
	files, err := set.Files()
	if err != nil {
		return err
	}
	if err := out.Write(o.outDir, o.force, files, rep, o.evidence); err != nil {
		return err
	}
	fmt.Fprintf(w, "failed findings: %d, files written: %d (nothing is applied), output: %s\n", len(rep.Rows), len(files), o.outDir)
	return nil
}

func statusAndNote(e mapping.Entry, generated, manualWarn bool) (string, string) {
	var parts []string
	if manualWarn {
		parts = append(parts, "kube-bench reports this control as manual (WARN).")
	}
	var status string
	switch {
	case !generated:
		status = out.StatusGuidanceOnly
		parts = append(parts, e.Guidance)
	case e.FollowUp != "":
		status = out.StatusFollowUp
		parts = append(parts, "Not applied. "+e.FollowUp)
	default:
		status = out.StatusCodeGenerated
		parts = append(parts, "Not applied. Apply it, then re-scan to confirm.")
	}
	if e.Caution != "" {
		parts = append(parts, "Caution: "+e.Caution)
	}
	if generated && e.Guidance != "" {
		parts = append(parts, e.Guidance)
	}
	return status, strings.TrimSpace(strings.Join(parts, " "))
}
