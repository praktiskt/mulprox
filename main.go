package main

import (
	"os"

	"github.com/praktiskt/mulprox/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
