// Synthetic acceptance workload. It contains no customer data or credentials.
package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--crash":
			os.Exit(1)
		case "--write-state":
			if os.MkdirAll("/state/private", 0700) != nil || os.WriteFile("/state/private/credential", []byte("synthetic-private-state"), 0600) != nil {
				os.Exit(2)
			}
			return
		case "--check-state":
			d, e := os.Stat("/state/private")
			if e != nil || d.Mode().Perm() != 0700 {
				os.Exit(3)
			}
			f, e := os.Stat("/state/private/credential")
			if e != nil || f.Mode().Perm() != 0600 {
				os.Exit(4)
			}
			b, e := os.ReadFile("/state/private/credential")
			if e != nil || string(b) != "synthetic-private-state" {
				os.Exit(5)
			}
			return
		}
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
}
