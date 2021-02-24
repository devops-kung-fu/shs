package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// interactiveCmd enters user into CVSS Builder Mode
var (
	interactiveCmd = &cobra.Command{
		Use:   "interactive",
		Short: "interactive mode",
		Long:  `Builds a CVSSv3 vector based on user input.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("CVSSv3:", interactiveMode())
		},
	}
)


func init() {
	rootCmd.AddCommand(interactiveCmd)
}

func interactiveMode() string {
	fmt.Println("CVSSv3 Builder\n")
	fmt.Println("Base:")
	fmt.Println("Temporal:")
	fmt.Println("Environmental:")
	fmt.Println()

	return "ok"
}