package cmd

import (
	"fmt"
	"math"
	"regexp"

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
		Label: label,
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

func getMetricValue(key string) float64 {
	metricValue := map[string]float64{
		"AV:N": 0.85,
		"AV:A": 0.62,
		"AV:L": 0.55,
		"AV:P": 0.2,
		"MAV:N": 0.85,
		"MAV:A": 0.62,
		"MAV:L": 0.55,
		"MAV:P": 0.2,
		"AC:L": 0.77,
		"AC:H": 0.44,
		"MAC:L": 0.77,
		"MAC:H": 0.44,
		"PR:N": 0.85,
		"PR:L": 0.62,
		"PR:LC": 0.68,
		"PR:H": 0.27,
		"PR:HC": 0.5,
		"MPR:N": 0.85,
		"MPR:L": 0.62,
		"MPR:LC": 0.68,
		"MPR:H": 0.27,
		"MPR:HC": 0.5,
		"UI:N": 0.85,
		"UI:R": 0.62,
		"MUI:N": 0.85,
		"MUI:R": 0.62,
		"C:H": 0.56,
		"C:L": 0.22,
		"C:N": 0,
		"MC:H": 0.56,
		"MC:L": 0.22,
		"MC:N": 0,
		"I:H": 0.56,
		"I:L": 0.22,
		"I:N": 0,
		"MI:H": 0.56,
		"MI:L": 0.22,
		"MI:N": 0,
		"A:H": 0.56,
		"A:L": 0.22,
		"A:N": 0,
		"MA:H": 0.56,
		"MA:L": 0.22,
		"MA:N": 0,
		"E:X": 1,
		"E:H": 1,
		"E:F": 0.97,
		"E:P": 0.94,
		"E:U": 0.91,
		"RL:X": 1,
		"RL:U": 1,
		"RL:W": 0.97,
		"RL:T": 0.96,
		"RL:O": 0.95,
		"RC:X": 1,
		"RC:C": 1,
		"RC:R": 0.96,
		"RC:U": 0.92,
	}
	value, _ := metricValue[key]
	return value
}

func baseScore(cvss string) float64 {
	metricSections := regexp.MustCompile(`[A-Z]{1,2}:[A-Z]{1,2}`).FindAllString(cvss, -1)
	s := metricSections[4]
	av := getMetricValue(metricSections[0])
	ac := getMetricValue(metricSections[1])
	var pr float64
	if s == "S:C" && metricSections[2] != "PR:N" {
		pr = getMetricValue(fmt.Sprintf("%sC", metricSections[2]))
	} else {
		pr = getMetricValue(metricSections[2])
	}
	ui := getMetricValue(metricSections[3])
	c := getMetricValue(metricSections[5])
	i := getMetricValue(metricSections[6])
	a := getMetricValue(metricSections[7])
	var iss float64 = 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if s == "S:U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52 * (iss - 0.029) - 3.25 * math.Pow(iss - 0.02, 15)
	}
	exploitability := 8.22 * av * ac * pr * ui
	var base float64 = 0
	if impact <= 0 {
		return base
	} else {
		if s == "S:U" {
			return math.Ceil((math.Min(impact + exploitability, 10)) * 10) / 10
		} else {
			return math.Ceil(math.Min(1.08 * (impact + exploitability), 10) * 10) / 10
		}
	}
}

func temporalScore(cvss string, baseScore float64) float64 {
	metricSections := regexp.MustCompile(`[A-Z]{1,2}:[A-Z]{1,2}`).FindAllString(cvss, -1)
	e := getMetricValue(metricSections[0])
	rl := getMetricValue(metricSections[1])
	rc := getMetricValue(metricSections[2])
	return math.Ceil((baseScore * e * rl * rc) * 10) / 10
}

func environmentalScore(environmentalVector string, temporalVector string) float64 {
	environmentalMetricSections := regexp.MustCompile(`[A-Z]{1,2}:[A-Z]{1,2}`).FindAllString(environmentalVector, -1)
	cr := getMetricValue(environmentalMetricSections[0])
	ir := getMetricValue(environmentalMetricSections[1])
	ar := getMetricValue(environmentalMetricSections[2])
	mav := getMetricValue(environmentalMetricSections[3])
	mac := getMetricValue(environmentalMetricSections[4])
	mpr := getMetricValue(environmentalMetricSections[5])
	mui := getMetricValue(environmentalMetricSections[6])
	ms := environmentalMetricSections[7]
	mc := getMetricValue(environmentalMetricSections[8])
	mi := getMetricValue(environmentalMetricSections[9])
	ma := getMetricValue(environmentalMetricSections[10])
	temporalMetricSections := regexp.MustCompile(`[A-Z]{1,2}:[A-Z]{1,2}`).FindAllString(temporalVector, -1)
	e := getMetricValue(temporalMetricSections[0])
	rl := getMetricValue(temporalMetricSections[1])
	rc := getMetricValue(temporalMetricSections[2])
	miss := math.Min(1 - ((1 - cr - mc) * (1 - ir - mi) * (1 - ar - ma)), 0.915)
	var modifiedImpact float64
	if ms == "MS:U" {
		modifiedImpact = 6.42 * miss
	} else if ms == "MS:C" {
		modifiedImpact = 7.52 * (miss - 0.029) - 3.25 * math.Pow((miss * 0.9731 - 0.02), 13)
	}
	modifiedExploitability := 8.22 * mav * mac * mpr * mui
	var environmentalScoreValue float64 = 0
	if modifiedImpact <= 0 {
		environmentalScoreValue = 0
	} else {
		if ms == "MS:U" {
			environmentalScoreValue = math.Ceil(((math.Ceil(math.Min((modifiedImpact + modifiedExploitability), 10) * 10) / 10) * e * rl * rc) * 10) / 10
		} else if ms == "MS:C" {
			environmentalScoreValue = math.Ceil(((math.Ceil(math.Min(1.08 * (modifiedImpact + modifiedExploitability), 10) * 10) / 10) * e * rl * rc) * 10) / 10
		} 
	}
	return environmentalScoreValue
}

func qualitativeSeverity(score float64) string {
	if score == 0 {
		return "None"
	} else if (score > 0 && score < 4) {
		return "Low"
	} else if (score >= 4 && score < 7) {
		return "Medium"
	} else if (score >= 7 && score < 9) {
		return "High"
	} else {
		return "Critical"
	}
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
	baseScoreValue := baseScore(baseVector)
	fmt.Printf("Base Score: %.2f\n", baseScoreValue)
	fmt.Printf("Severity: %s\n", qualitativeSeverity(baseScoreValue))
	fmt.Println()
	fmt.Println("Temporal:")
	temporalVectorString := temporalVector()
	baseTemporalVector := fmt.Sprintf("%s/%s", baseVector, temporalVectorString)
	fmt.Println()
	fmt.Printf("Base+Temporal Vector: %s\n", baseTemporalVector)
	temporalScoreValue := temporalScore(temporalVectorString, baseScoreValue)
	fmt.Printf("Temporal Score: %.2f\n", temporalScoreValue)
	fmt.Printf("Severity: %s\n", qualitativeSeverity(temporalScoreValue))
	fmt.Println()
	fmt.Println("Environmental:")
	securityRequirementsString := securityRequirements()
	modifiedBaseMetricsString := modifiedBaseMetrics()
	environmentalVectorString := fmt.Sprintf("%s/%s", securityRequirementsString, modifiedBaseMetricsString)
	baseTemporalEnvironmentalVector := fmt.Sprintf("%s/%s", baseTemporalVector, environmentalVectorString)
	fmt.Println()
	fmt.Printf("Base+Temporal+Environmental Vector: %s\n", baseTemporalEnvironmentalVector)
	environmentalScoreValue := environmentalScore(environmentalVectorString, temporalVectorString)
 	fmt.Printf("Environmental Score: %.2f\n", environmentalScoreValue)
	fmt.Printf("Severity: %s\n", qualitativeSeverity(environmentalScoreValue))

}