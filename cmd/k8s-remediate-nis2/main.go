package main

import (
	"os"

	"github.com/sv222/k8s-remediate-nis2/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(2)
	}
}
