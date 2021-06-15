package cmd

import (
	"fmt"
	"regexp"

	"github.com/devops-kung-fu/go-shs/api"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

// interactiveCmd enters user into CVSS Builder Mode
var (
	interactiveCmd = &cobra.Command{
		Use:   "interactive",
		Short: "interactive mode",
		Long:  `Builds a CVSSv3 vector based on user input.`,
		Run: func(cmd *cobra.Command, args []string) {
			interactiveMode()
		},
	}
)

func init() {
	rootCmd.AddCommand(interactiveCmd)
}

func getLetter(selection string) string {
	paren := regexp.MustCompile(`\([A-Z]+\)`).FindString(selection)
	return regexp.MustCompile(`[A-Z]+`).FindString(paren)
}

func confirmPrompt(label string) string {
	prompt := promptui.Prompt{
		Label:     label,
		IsConfirm: true,
	}
	promptResult, err := prompt.Run()
	if err != nil {
		fmt.Printf("Skipping Temporal Vector %v\n", err)
		return ""
	}
	return promptResult
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

func exploitabilityVector() string {
	attackVector := menuSelect("Attack Vector (AV)", []string{"Network (N)", "Adjacent (A)", "Local (L)", "Physical (P)"})
	fmt.Printf("  Attack Vector (AV): %s\n", attackVector)
	attackVectorLetter := getLetter(attackVector)

	attackComplexity := menuSelect("Attack Complexity (AC)", []string{"Low (L)", "High (H)"})
	fmt.Printf("  Attack Complexity (AC): %s\n", attackComplexity)
	attackComplexityLetter := getLetter(attackComplexity)

	privilegesRequired := menuSelect("Privileges Required (PR)", []string{"None (N)", "Low (L)", "High (H)"})
	fmt.Printf("  Privileges Required (PR): %s\n", privilegesRequired)
	privilegesRequiredLetter := getLetter(privilegesRequired)

	userInteraction := menuSelect("User Interaction (UI)", []string{"None (N)", "Required (R)"})
	fmt.Printf("  User Interaction (UI): %s\n", userInteraction)
	userInteractionLetter := getLetter(userInteraction)

	scope := menuSelect("Scope (S)", []string{"Unchanged (U)", "Changed (C)"})
	fmt.Printf(" Scope (S): %s\n", scope)
	scopeLetter := getLetter(scope)

	return fmt.Sprintf("AV:%s/AC:%s/PR:%s/UI:%s/S:%s", attackVectorLetter, attackComplexityLetter, privilegesRequiredLetter, userInteractionLetter, scopeLetter)
}

func impactVector() string {
	confidentiality := menuSelect("Confidentiality (C)", []string{"High (H)", "Low (L)", "None (N)"})
	fmt.Printf("  Confidentiality (C): %s\n", confidentiality)
	confidentialityLetter := getLetter(confidentiality)

	integrity := menuSelect("Integrity (I)", []string{"High (H)", "Low (L)", "None (N)"})
	fmt.Printf("  Integrity (I): %s\n", integrity)
	integrityLetter := getLetter(integrity)

	availability := menuSelect("Availability (A)", []string{"High (H)", "Low (L)", "None (N)"})
	fmt.Printf("  Availability (A): %s\n", availability)
	availabilityLetter := getLetter(availability)

	return fmt.Sprintf("C:%s/I:%s/A:%s", confidentialityLetter, integrityLetter, availabilityLetter)
}

func temporalVector() string {
	exploitCodeMaturity := menuSelect("Exploit Code Maturity (E)", []string{"Not Defined (X)", "High (H)", "Functional (F)", "Proof-of-Concept (P)", "Unproven (U)"})
	fmt.Printf("  Exploit Code Maturity (E): %s\n", exploitCodeMaturity)
	exploitCodeMaturityLetter := getLetter(exploitCodeMaturity)

	remediationLevel := menuSelect("Remediation Level (RL)", []string{"Not Defined (X)", "Unavailable (U)", "Workaround (W)", "Temporary Fix (T)", "Official Fix (O)"})
	fmt.Printf("  Remediation Level (RL): %s\n", remediationLevel)
	remediationLevelLetter := getLetter(remediationLevel)

	reportConfidence := menuSelect("Report Confidence (RC)", []string{"Not Defined (X)", "Confirmed (C)", "Reasonable (R)", "Unknown (U)"})
	fmt.Printf("  Report Confidence (RC): %s\n", reportConfidence)
	reportConfidenceLetter := getLetter(reportConfidence)

	return fmt.Sprintf("E:%s/RL:%s/RC:%s", exploitCodeMaturityLetter, remediationLevelLetter, reportConfidenceLetter)
}

func securityRequirements() string {
	confidentialityRequirement := menuSelect("Confidentiality Requirement (CR)", []string{"Not Defined (X)", "High (H)", "Medium (M)", "Low (L)"})
	fmt.Printf("  Confidentiality Requirement (CR): %s\n", confidentialityRequirement)
	confidentialityRequirementLetter := getLetter(confidentialityRequirement)

	integrityRequirement := menuSelect("Integrity Requirement (IR)", []string{"Not Defined (X)", "High (H)", "Medium (M)", "Low (L)"})
	fmt.Printf("  Integrity Requirement (IR): %s\n", integrityRequirement)
	integrityRequirementLetter := getLetter(integrityRequirement)

	availabilityRequirement := menuSelect("Availability Requirement (AR)", []string{"Not Defined (X)", "High (H)", "Medium (M)", "Low (L)"})
	fmt.Printf("  Availability Requirement (AR): %s\n", availabilityRequirement)
	availabilityRequirementLetter := getLetter(availabilityRequirement)

	return fmt.Sprintf("CR:%s/IR:%s/AR:%s", confidentialityRequirementLetter, integrityRequirementLetter, availabilityRequirementLetter)
}

func modifiedBaseMetrics() string {
	modifiedAttackVector := menuSelect("Modified Attack Vector (MAV)", []string{"Not Defined (X)", "Network (N)", "Adjacent (A)", "Local (L)", "Physical (P)"})
	fmt.Printf("  Modified Attack Vector (MAV): %s\n", modifiedAttackVector)
	modifiedAttackVectorLetter := getLetter(modifiedAttackVector)

	modifiedAttackComplexity := menuSelect("Modified Attack Complexity (MAC)", []string{"Not Defined (X)", "Low (L)", "High (H)"})
	fmt.Printf("  Modified Attack Complexity (MAC): %s\n", modifiedAttackComplexity)
	modifiedAttackComplexityLetter := getLetter(modifiedAttackComplexity)

	modifiedPrivilegesRequired := menuSelect("Modified Privileges Required (MPR)", []string{"Not Defined (X)", "None (N)", "Low (L)", "High (H)"})
	fmt.Printf("  Modified Privileges Required (MPR): %s\n", modifiedPrivilegesRequired)
	modifiedPrivilegesRequiredLetter := getLetter(modifiedPrivilegesRequired)

	modifiedUserInteraction := menuSelect("Modified User Interaction (MUI)", []string{"Not Defined (X)", "None (N)", "Required (R)"})
	fmt.Printf("  Modified User Interaction (MUI): %s\n", modifiedUserInteraction)
	modifiedUserInteractionLetter := getLetter(modifiedUserInteraction)

	modifiedScope := menuSelect("Modified Scope (MS)", []string{"Not Defined (X)", "Unchanged (U)", "Changed (C)"})
	fmt.Printf("  Modified Scope (MS): %s\n", modifiedScope)
	modifiedScopeLetter := getLetter(modifiedScope)

	modifiedConfidentiality := menuSelect("Modified Confidentiality (MC)", []string{"Not Defined (X)", "High (H)", "Low (L)", "None (N)"})
	fmt.Printf("  Modified Confidentiality (MC): %s\n", modifiedConfidentiality)
	modifiedConfidentialityLetter := getLetter(modifiedConfidentiality)

	modifiedIntegrity := menuSelect("Modified Integrity (MI)", []string{"Not Defined (X)", "High (H)", "Low (L)", "None (N)"})
	fmt.Printf("  Modified Integrity (MI): %s\n", modifiedIntegrity)
	modifiedIntegrityLetter := getLetter(modifiedIntegrity)

	modifiedAvailability := menuSelect("Modified Availability (MA)", []string{"Not Defined (X)", "High (H)", "Low (L)", "None (N)"})
	fmt.Printf("  Modified Availability (MA): %s\n", modifiedAvailability)
	modifiedAvailabilityLetter := getLetter(modifiedAvailability)

	return fmt.Sprintf(
		"MAV:%s/MAC:%s/MPR:%s/MUI:%s/MS:%s/MC:%s/MI:%s/MA:%s",
		modifiedAttackVectorLetter,
		modifiedAttackComplexityLetter,
		modifiedPrivilegesRequiredLetter,
		modifiedUserInteractionLetter,
		modifiedScopeLetter,
		modifiedConfidentialityLetter,
		modifiedIntegrityLetter,
		modifiedAvailabilityLetter,
	)

}

func interactiveMode() {
	fmt.Println("CVSSv3 Builder")
	fmt.Println()
	fmt.Println("Base Metrics")
	fmt.Println(" Exploitability Metrics")
	exploitabilityVectorString := exploitabilityVector()
	fmt.Println(" Impact Metrics")
	impactVectorString := impactVector()
	fmt.Println()
	baseVector := fmt.Sprintf("CVSS:3.1/%s/%s", exploitabilityVectorString, impactVectorString)
	fmt.Printf("Base Vector: %s\n", baseVector)
	baseScoreValue := api.BaseScore(baseVector)
	fmt.Printf("Base Score: %.2f\n", baseScoreValue)
	fmt.Printf("Severity: %s\n", api.QualitativeSeverity(baseScoreValue))
	fmt.Println()
	fmt.Println("Temporal:")
	temporalVectorString := temporalVector()
	baseTemporalVector := fmt.Sprintf("%s/%s", baseVector, temporalVectorString)
	fmt.Println()
	fmt.Printf("Base+Temporal Vector: %s\n", baseTemporalVector)
	temporalScoreValue := api.TemporalScore(temporalVectorString, baseScoreValue)
	fmt.Printf("Temporal Score: %.2f\n", temporalScoreValue)
	fmt.Printf("Severity: %s\n", api.QualitativeSeverity(temporalScoreValue))
	fmt.Println()
	fmt.Println("Environmental:")
	securityRequirementsString := securityRequirements()
	modifiedBaseMetricsString := modifiedBaseMetrics()
	environmentalVectorString := fmt.Sprintf("%s/%s", securityRequirementsString, modifiedBaseMetricsString)
	baseTemporalEnvironmentalVector := fmt.Sprintf("%s/%s", baseTemporalVector, environmentalVectorString)
	fmt.Println()
	fmt.Printf("Base+Temporal+Environmental Vector: %s\n", baseTemporalEnvironmentalVector)
	environmentalScoreValue := api.EnvironmentalScore(environmentalVectorString, temporalVectorString)
	fmt.Printf("Environmental Score: %.2f\n", environmentalScoreValue)
	fmt.Printf("Severity: %s\n", api.QualitativeSeverity(environmentalScoreValue))

}
