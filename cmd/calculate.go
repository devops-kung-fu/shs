package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/devops-kung-fu/go-shs/api/v1"
)

// calculateCmd represents the calculate command
var (
	calculateCmd = &cobra.Command{
		Use:   "calculate",
		Short: "Calculates the Security Health Score",
		Long:  `Calculates the Security Health Score`,
		Run: func(cmd *cobra.Command, args []string) {
		
		},
	}
)

// Vector - Single CVSS vector string.
var Vector string

func init() {
	rootCmd.Flags().StringVarP(&Vector, "vector", "v", "", "Calculates security health score based on a single vector string.")
	rootCmd.AddCommand(calculateCmd)
}

func calculateVector(vector string) int {
	goSHS := v1.NewAPI()
	goSHS.Cal
}