package main

import (
	"os"

	"github.com/nis2rem/k8s-remediate-nis2/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(2)
	}
}
