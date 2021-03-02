package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/manifoldco/promptui"
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

func menuSelect(label string, items []string) string {
	prompt := promptui.Select{
		Label: label,
		Items: items,
	}
	_, promptResult, err := prompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return ""
	}
	return promptResult
}

func interactiveMode() string {
	fmt.Println("CVSSv3 Builder")
	fmt.Println()
	fmt.Println("Base Metrics")
	fmt.Println(" Exploitability Metrics")
	attackVector := menuSelect("Attack Vector (AV)", []string{"Network (N)", "Adjacent (A)", "Local (L)", "Physical (P)"})
	fmt.Printf("  Attack Vector (AV): %q\n", attackVector)
	attackComplexity := menuSelect("Attack Complexity (AC)", []string{"Low (L)", "High (H)"})
	fmt.Printf("  Attack Complexity (AC): %q\n", attackComplexity)
	privilegesRequired := menuSelect("Privileges Required (PR)", []string{"None (N)", "Low (L)", "High (H)"})
	fmt.Printf("  Privileges Required (PR): %q\n", privilegesRequired)
	userInteraction := menuSelect("User Interaction (UI)", []string{"None (N)", "Required (R)"})
	fmt.Printf("  User Interaction (UI): %q\n", userInteraction)
	scope := menuSelect("Scope (S)", []string{"Unchanged (U)", "Changed (C)"})
	fmt.Printf(" Scope (S): %q\n", scope)
	fmt.Println(" Impact Metrics")
	confidentiality := menuSelect("Confidentiality (C)", []string{"High (H)", "Low (L)", "None (N)"})
	fmt.Printf("  Confidentiality (C): %q\n", confidentiality)
	integrity := menuSelect("Integrity (I)", []string{"High (H)", "Low (L)", "None (N)"})
	fmt.Printf("  Integrity (I): %q\n", integrity)
	availability := menuSelect("Availability (A)", []string{"High (H)", "Low (L)", "None (N)"})
	fmt.Printf("  Availability (A): %q\n", availability)
	fmt.Println("Temporal:")
	fmt.Println("Environmental:")
	fmt.Println()
	return "ok"
}