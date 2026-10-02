// Package version holds the agent's build version.
package version

// Version is the agent version. Release builds override it with
// -ldflags "-X github.com/officehq/sk-mdm/agent/internal/version.Version=<version>".
var Version = "0.0.0-dev"
