package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateHighSeverity(t *testing.T) {
	api := NewAPI(DefaultConfig())

	cves := []Cve{
		{"CVE-2019-1302", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"},
		{"CVE-2019-9511", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
		{"CVE-2019-1010259", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}
	score := api.CalculateCves(cves)
	assert.Equal(t, 113, score, "The score should equal 113.")
}

func TestCalculateLowSeverity(t *testing.T) {
	api := NewAPI(DefaultConfig())

	cves := []Cve{
		{"CVE-2020-7299 ", "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N"},
		{"CVE-2020-1592", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"},
		{"CVE-2020-24348", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"},
	}
	score := api.CalculateCves(cves)
	assert.Equal(t, 561, score, "The score should equal 561.")
}
