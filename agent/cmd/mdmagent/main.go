// Command mdmagent is the SK-MDM device agent.
package main

import (
	"flag"
	"fmt"

	"github.com/officehq/sk-mdm/agent/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print the agent version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Version)
		return
	}

	fmt.Printf("mdmagent %s\n", version.Version)
}
