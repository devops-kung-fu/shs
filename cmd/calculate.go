package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/devops-kung-fu/go-shs/calculate"
)

// calculateCmd represents the calculate command
var (
	calculateCmd = &cobra.Command{
		Use:   "calculate",
		Short: "Calculates the Security Health Score",
		Long:  `Calculates the Security Health Score`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Security Health Score:", calculateVector(Vector))
		},
	}
)

// Vector - Single CVSS vector string.
var Vector []string

func init() {
	calculateCmd.Flags().StringArrayVarP(&Vector, "vector", "v", []string{}, "Calculates security health score based on a single vector string.")
	calculateCmd.MarkFlagRequired("vector")
	rootCmd.AddCommand(calculateCmd)
}

func calculateVector(vector []string) int {
	goSHS := api.NewAPI(api.DefaultConfig())
	score := goSHS.CalculateVectors(vector)
	return score
}