// Package cmd contains all of the commands that may be executed in the cli
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	useColor bool
	output   string

	rootCmd = &cobra.Command{
		Use:     "shs",
		Short:   `Security Security Health Score Calculator`,
		Version: "0.0.1",
	}
)

// Execute creates the command tree and handles any error condition returned
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
}
