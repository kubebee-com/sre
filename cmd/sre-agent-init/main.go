// Deprecated compatibility entry point; use sre-agent init.
package main

import (
	"github.com/kubebee-com/sre/pkg/agent/bootstrap"
	"os"
)

func main() {
	if bootstrap.Run(os.Args[1:]) != nil {
		os.Stderr.WriteString("Agent bootstrap initialization failed\n")
		os.Exit(1)
	}
}
