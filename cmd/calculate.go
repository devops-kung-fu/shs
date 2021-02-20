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
// Weight - Specify the weight to be used for calculations.
var Weight float32

func init() {
	calculateCmd.Flags().StringArrayVarP(&Vector, "vector", "v", []string{}, "Calculates security health score based on a single vector string.")
	calculateCmd.MarkFlagRequired("vector")
	calculateCmd.Flags().Float32VarP(&Weight, "weight", "w", 1.05, "Specify the weight to be used in calculating score. Default: 1.05.")
	calculateCmd.MarkFlagRequired("weight")
	rootCmd.AddCommand(calculateCmd)
}

func calculateVector(vector []string) int {
	goSHS := api.NewAPI(api.DefaultConfig())
	score := goSHS.CalculateVectors(vector)
	return score
}