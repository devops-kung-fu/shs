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
			fmt.Println("CVSSv3:", interactiveMode())
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

func exploitabilityVector() string {
	attackVector := menuSelect("Attack Vector (AV)", []string{"Network (N)", "Adjacent (A)", "Local (L)", "Physical (P)"})
	fmt.Printf("  Attack Vector (AV): %q\n", attackVector)
	attackVectorLetter := getLetter(attackVector)

	attackComplexity := menuSelect("Attack Complexity (AC)", []string{"Low (L)", "High (H)"})
	fmt.Printf("  Attack Complexity (AC): %q\n", attackComplexity)
	attackComplexityLetter := getLetter(attackComplexity)
	
	privilegesRequired := menuSelect("Privileges Required (PR)", []string{"None (N)", "Low (L)", "High (H)"})
	fmt.Printf("  Privileges Required (PR): %q\n", privilegesRequired)
	privilegesRequiredLetter := getLetter(privilegesRequired)

	userInteraction := menuSelect("User Interaction (UI)", []string{"None (N)", "Required (R)"})
	fmt.Printf("  User Interaction (UI): %q\n", userInteraction)
	userInteractionLetter := getLetter(userInteraction)

	scope := menuSelect("Scope (S)", []string{"Unchanged (U)", "Changed (C)"})
	fmt.Printf(" Scope (S): %q\n", scope)
	scopeLetter := getLetter(scope)

	return fmt.Sprintf("AV:%s/AC:%s/PR:%s/UI:%s/S:%s", attackVectorLetter, attackComplexityLetter, privilegesRequiredLetter, userInteractionLetter, scopeLetter)
}

func impactVector() string {
	confidentiality := menuSelect("Confidentiality (C)", []string{"High (H)", "Low (L)", "None (N)"})
	fmt.Printf("  Confidentiality (C): %q\n", confidentiality)
	confidentialityLetter := getLetter(confidentiality)

	integrity := menuSelect("Integrity (I)", []string{"High (H)", "Low (L)", "None (N)"})
	fmt.Printf("  Integrity (I): %q\n", integrity)
	integrityLetter := getLetter(integrity)

	availability := menuSelect("Availability (A)", []string{"High (H)", "Low (L)", "None (N)"})
	fmt.Printf("  Availability (A): %q\n", availability)
	availabilityLetter := getLetter(availability)

	return fmt.Sprintf("C:%s/I:%s/A:%s", confidentialityLetter, integrityLetter, availabilityLetter)
}

func interactiveMode() string {
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
	fmt.Printf("Base Score: %.2f\n", baseScore(baseVector))
	fmt.Println()
	fmt.Println("Temporal:")
	fmt.Println("Environmental:")
	fmt.Println()
	return "ok"
}