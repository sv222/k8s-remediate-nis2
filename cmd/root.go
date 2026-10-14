package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sv222/k8s-remediate-nis2/internal/version"
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "k8s-remediate-nis2",
		Short:         "Turn Prowler/kube-bench findings into Kyverno/Terraform remediation code mapped to NIS2/DORA",
		Version:       version.Get(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	root.AddCommand(newRemediateCmd())
	return root
}

func Execute() error {
	if err := NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return err
	}
	return nil
}
