package main

import (
	"fmt"
	"os"

	"github.com/ihildy/magnit-vms-hour-logging-cli/internal/cli"
)

func main() {
	root := cli.NewRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
