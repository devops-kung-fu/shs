package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// calculateCmd represents the calculate command
var (
	calculateCmd = &cobra.Command{
		Use:   "calculate",
		Short: "Calculates the Security Health Score",
		Long:  `Calculates the Security Health Score`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Ran Calculate Command")
		},
	}
)

func init() {
	rootCmd.AddCommand(calculateCmd)
}
