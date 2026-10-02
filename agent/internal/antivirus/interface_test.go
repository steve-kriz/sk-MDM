package antivirus_test

import (
	"github.com/officehq/sk-mdm/agent/internal/antivirus"
	"github.com/officehq/sk-mdm/agent/internal/enforce"
)

// The antivirus enforcer plugs into enforce.Run; this package cannot import
// enforce itself without a cycle, so the assertion lives in the external test
// package.
var _ enforce.Enforcer = antivirus.NewEnforcer(nil, nil, "")
