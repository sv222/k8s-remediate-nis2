package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

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
	c.Flags().StringVar(&o.outDir, "out", "./remediation", "output directory")
	c.Flags().BoolVar(&o.evidence, "export-evidence", false, "also write evidence.md for auditors")
	return c
}

func loadFindings(o options) ([]finding.Finding, error) {
	var findings []finding.Finding
	if o.prowler != "" {
		data, err := os.ReadFile(o.prowler)
		if err != nil {
			return nil, err
		}
		fs, err := prowler.Parse(data, o.prowler)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fs...)
	}
	if o.kubeBench != "" {
		data, err := os.ReadFile(o.kubeBench)
		if err != nil {
			return nil, err
		}
		fs, err := kubebench.Parse(data, o.kubeBench)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}

func run(w io.Writer, o options) error {
	if o.prowler == "" && o.kubeBench == "" {
		return errors.New("at least one of --prowler or --kube-bench is required")
	}
	findings, err := loadFindings(o)
	if err != nil {
		return err
	}
	set := render.NewSet()
	var rows []out.SummaryRow
	for _, f := range findings {
		if f.Status != "FAIL" {
			continue
		}
		row := out.SummaryRow{
			Scanner: f.Scanner, CheckID: f.CheckID, ResourceID: f.ResourceID,
			Severity: f.Severity, Region: f.Region,
		}
		e, ok, err := mapping.For(f)
		if err != nil {
			return err
		}
		if !ok {
			row.Status = out.StatusNoMapping
			rows = append(rows, row)
			continue
		}
		row.Articles = e.Articles
		rf, err := render.Render(e, f)
		if errors.Is(err, render.ErrInvalidResourceID) {
			row.Status = out.StatusInvalidResource
			row.Note = err.Error()
			rows = append(rows, row)
			continue
		}
		if err != nil {
			return err
		}
		set.Add(rf)
		for _, x := range rf {
			row.Files = append(row.Files, x.RelPath)
		}
		if len(rf) == 0 {
			row.Status = out.StatusGuidanceOnly
		} else {
			row.Status = out.StatusRemediated
		}
		row.Note = e.Guidance
		rows = append(rows, row)
	}
	files := set.Files()
	if err := out.Write(o.outDir, files, rows); err != nil {
		return err
	}
	if o.evidence {
		if err := out.WriteEvidence(o.outDir, findings, rows, inputPaths(o)); err != nil {
			return err
		}
	}
	fmt.Fprintf(w, "failed findings: %d, files written: %d, output: %s\n", len(rows), len(files), o.outDir)
	return nil
}

func inputPaths(o options) []string {
	var p []string
	if o.prowler != "" {
		p = append(p, o.prowler)
	}
	if o.kubeBench != "" {
		p = append(p, o.kubeBench)
	}
	return p
}
