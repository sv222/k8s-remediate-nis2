package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/nis2rem/k8s-remediate-nis2/internal/finding"
	"github.com/nis2rem/k8s-remediate-nis2/internal/kubebench"
	"github.com/nis2rem/k8s-remediate-nis2/internal/out"
	"github.com/nis2rem/k8s-remediate-nis2/internal/prowler"
	"github.com/nis2rem/k8s-remediate-nis2/internal/render"
	"github.com/nis2rem/k8s-remediate-nis2/mapping"
)

var (
	prowlerFile   string
	kubebenchFile string
	outDir        string
	evidence      bool
)

var remediateCmd = &cobra.Command{
	Use:   "remediate",
	Short: "Generate remediation code from Prowler/kube-bench findings",
	RunE: func(c *cobra.Command, args []string) error {
		var findings []finding.Finding
		if prowlerFile != "" {
			data, err := os.ReadFile(prowlerFile)
			if err != nil {
				return err
			}
			fs, err := prowler.Parse(data, prowlerFile)
			if err != nil {
				return err
			}
			findings = append(findings, fs...)
		}
		if kubebenchFile != "" {
			data, err := os.ReadFile(kubebenchFile)
			if err != nil {
				return err
			}
			fs, err := kubebench.Parse(data, kubebenchFile)
			if err != nil {
				return err
			}
			findings = append(findings, fs...)
		}
		var files []render.RenderedFile
		var rows []out.SummaryRow
		for _, f := range findings {
			if f.Status != "FAIL" {
				continue
			}
			e, ok := mapping.For(f)
			if !ok {
				rows = append(rows, out.SummaryRow{Scanner: f.Scanner, CheckID: f.CheckID,
					ResourceID: f.ResourceID, Status: "no mapping (v1 seed set)"})
				continue
			}
			rf, err := render.Render(e, f)
			if err != nil {
				return err
			}
			files = append(files, rf...)
			var rels []string
			for _, x := range rf {
				rels = append(rels, x.RelPath)
			}
			rows = append(rows, out.SummaryRow{Scanner: f.Scanner, CheckID: f.CheckID,
				ResourceID: f.ResourceID, Articles: e.Articles, Files: rels, Status: "remediated"})
		}
		if err := out.Write(outDir, files, rows); err != nil {
			return err
		}
		if len(files) == 0 {
			os.Exit(1)
		}
		return nil
	},
}

func inputPaths() []string {
	var p []string
	if prowlerFile != "" {
		p = append(p, prowlerFile)
	}
	if kubebenchFile != "" {
		p = append(p, kubebenchFile)
	}
	return p
}

func init() {
	remediateCmd.Flags().StringVar(&prowlerFile, "prowler", "", "Prowler v4 JSON report")
	remediateCmd.Flags().StringVar(&kubebenchFile, "kube-bench", "", "kube-bench JSON report")
	remediateCmd.Flags().StringVar(&outDir, "out", "./remediation", "output directory")
	remediateCmd.Flags().BoolVar(&evidence, "export-evidence", false, "also write evidence.md for auditors")
	rootCmd.AddCommand(remediateCmd)
}
