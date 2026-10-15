package executor

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

// Command is one command the backend leased to this device.
//
// The json tags are the item fields the lease endpoint returns, so a
// contract.CommandLeaseResponse item decodes into this struct unchanged.
// Payload is left raw: its shape depends on Type, and this package is the only
// one that decodes it.
type Command struct {
	CommandID string          `json:"commandId"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	IssuedAt  int64           `json:"issuedAt"`
	ExpiresAt int64           `json:"expiresAt"`
}

// RunScriptPayload is the payload of a run_script command.
//
// TimeoutSeconds is optional everywhere: absent or zero means
// DefaultTimeoutSeconds and anything above MaxTimeoutSeconds is capped to it.
type RunScriptPayload struct {
	Interpreter    string `json:"interpreter"`
	Script         string `json:"script"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

// PackagePayload is the payload of an install_package or uninstall_package
// command.
type PackagePayload struct {
	PackageID      string `json:"packageId"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

// InstallApplicationPayload is the payload of an install_application command.
// The download details are not in it: the agent fetches them when it runs the
// command, so no presigned URL ever waits on a queued command. Extra keys (such
// as stopOnFailure) are ignored here.
type InstallApplicationPayload struct {
	ApplicationID   string `json:"applicationId"`
	ApplicationName string `json:"applicationName"`
	TimeoutSeconds  int    `json:"timeoutSeconds"`
}

// timeoutPayload is the common part of every payload: the commands that need
// no field of their own still honour a timeout.
type timeoutPayload struct {
	TimeoutSeconds int `json:"timeoutSeconds"`
}

// The interpreters a run_script payload may name. Anything else is an invalid
// payload rather than an attempt to run it. cmd and powershell run on
// Windows; bash and zsh on macOS.
const (
	InterpreterPowerShell = "powershell"
	InterpreterZsh        = "zsh"
	InterpreterCmd        = "cmd"
	InterpreterBash       = "bash"
)

// interpreterGOOS is the GOOS each interpreter runs on. An interpreter run on
// the other platform is refused with ErrUnsupportedInterpreter.
var interpreterGOOS = map[string]string{
	InterpreterPowerShell: "windows",
	InterpreterCmd:        "windows",
	InterpreterZsh:        "darwin",
	InterpreterBash:       "darwin",
}

// stopPayload is the part of any payload that says whether a failure stops
// the rest of the leased batch. The backend sets it on sequenced commands
// leased while the fleet setting is "stop".
type stopPayload struct {
	StopOnFailure bool `json:"stopOnFailure"`
}

// stopOnFailure reports whether a command's payload carries
// stopOnFailure: true. A payload that does not decode is treated as false.
func stopOnFailure(raw json.RawMessage) bool {
	if len(bytes.TrimSpace(raw)) == 0 {
		return false
	}
	var payload stopPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return false
	}
	return payload.StopOnFailure
}

// Timeout bounds, in seconds.
const (
	// DefaultTimeoutSeconds is used when the payload names no timeout.
	DefaultTimeoutSeconds = 300
	// MaxTimeoutSeconds is the ceiling: a payload asking for more gets this.
	MaxTimeoutSeconds = 3600
)

// EffectiveTimeout is the timeout a payload value really buys: the default
// when it is absent or zero, the ceiling when it is above MaxTimeoutSeconds.
func EffectiveTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		seconds = DefaultTimeoutSeconds
	}
	if seconds > MaxTimeoutSeconds {
		seconds = MaxTimeoutSeconds
	}
	return time.Duration(seconds) * time.Second
}

// decodeRunScript decodes a run_script payload, reporting false for anything
// the executor refuses to run: a missing or non-string script, and any
// interpreter other than the four named above.
func decodeRunScript(raw json.RawMessage) (RunScriptPayload, bool) {
	var payload RunScriptPayload
	if !decodePayload(raw, &payload) {
		return RunScriptPayload{}, false
	}
	if _, known := interpreterGOOS[payload.Interpreter]; !known {
		return RunScriptPayload{}, false
	}
	if strings.TrimSpace(payload.Script) == "" {
		return RunScriptPayload{}, false
	}
	return payload, true
}

// decodePackage decodes a package payload, reporting false when packageId is
// absent, empty or not a string.
func decodePackage(raw json.RawMessage) (PackagePayload, bool) {
	var payload PackagePayload
	if !decodePayload(raw, &payload) {
		return PackagePayload{}, false
	}
	if strings.TrimSpace(payload.PackageID) == "" {
		return PackagePayload{}, false
	}
	return payload, true
}

// decodeInstallApplication decodes an install_application payload, reporting
// false when applicationId is absent, empty or not a string.
func decodeInstallApplication(raw json.RawMessage) (InstallApplicationPayload, bool) {
	var payload InstallApplicationPayload
	if !decodePayload(raw, &payload) {
		return InstallApplicationPayload{}, false
	}
	if strings.TrimSpace(payload.ApplicationID) == "" {
		return InstallApplicationPayload{}, false
	}
	return payload, true
}

// decodeTimeout decodes the timeout of a payload that has no required field of
// its own, reporting false when the payload is not an object or when
// timeoutSeconds is not an integer.
func decodeTimeout(raw json.RawMessage) (int, bool) {
	var payload timeoutPayload
	if !decodePayload(raw, &payload) {
		return 0, false
	}
	return payload.TimeoutSeconds, true
}

// decodePayload unmarshals raw into target, reporting false when the JSON does
// not fit the struct — a field of the wrong type, or a payload that is not an
// object at all.
//
// An absent payload is not refused here: it decodes to the zero struct, and it
// is the required-field check above that decides whether that is usable. A
// restart needs no payload; a run_script needs a script.
func decodePayload(raw json.RawMessage, target any) bool {
	if len(bytes.TrimSpace(raw)) == 0 {
		return true
	}
	return json.Unmarshal(raw, target) == nil
}
