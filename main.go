package main

import (
	"os"

	"github.com/djschleen/shs/cmd"
)

func main() {
	defer os.Exit(0)
	cmd.Execute()
}
