package executor

import (
	"context"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
)

// Script file extensions, so each interpreter is handed a file it recognises.
const (
	powerShellExt = ".ps1"
	zshExt        = ".sh"
	cmdExt        = ".cmd"
	bashExt       = ".sh"
)

// runScript writes the script to a temp file and runs it through the
// interpreter the payload named.
//
// The file is deleted when the run returns, whatever it returned: a script the
// backend sent is not left lying on the device because it exited non-zero.
func runScript(ctx context.Context, cmd Command, deps *Deps) contract.CommandResultRequest {
	payload, ok := decodeRunScript(cmd.Payload)
	if !ok {
		// Nothing is written and nothing is run: the payload is refused
		// before the device is touched at all.
		return deps.fail(ErrInvalidPayload, "")
	}

	// An interpreter for the other platform is refused before anything is
	// written or run.
	if interpreterGOOS[payload.Interpreter] != deps.goos() {
		return deps.fail(ErrUnsupportedInterpreter, "")
	}

	path := deps.tempPath("mdm-script-", cmd.CommandID, scriptExt(payload.Interpreter))
	if err := deps.writeTemp(path, []byte(payload.Script)); err != nil {
		return deps.fail(ErrExecutionFailed, err.Error())
	}
	defer deps.removeTemp(path)

	deps.log(logging.LevelInfo, "running script",
		logging.F("commandId", cmd.CommandID),
		logging.F("interpreter", payload.Interpreter),
	)

	name, args := scriptArgv(payload.Interpreter, path)
	return deps.report(deps.run(ctx, EffectiveTimeout(payload.TimeoutSeconds), name, args...))
}

// scriptArgv is how each interpreter is invoked over a script file.
//
// PowerShell is run with no profile, no prompts and a bypassed execution
// policy: the agent runs as a service, so a user's profile, an interactive
// prompt or a signing policy would each hang or refuse a script the backend
// has already authorised.
//
// cmd is run with /d (no AutoRun commands from the registry) and /c (run the
// file, then exit).
func scriptArgv(interpreter, path string) (string, []string) {
	switch interpreter {
	case InterpreterPowerShell:
		return "powershell.exe", []string{
			"-NoProfile",
			"-NonInteractive",
			"-ExecutionPolicy", "Bypass",
			"-File", path,
		}
	case InterpreterCmd:
		return "cmd.exe", []string{"/d", "/c", path}
	case InterpreterBash:
		return "/bin/bash", []string{path}
	}
	return "/bin/zsh", []string{path}
}

// scriptExt is the extension the temp script is written with.
func scriptExt(interpreter string) string {
	switch interpreter {
	case InterpreterPowerShell:
		return powerShellExt
	case InterpreterCmd:
		return cmdExt
	case InterpreterBash:
		return bashExt
	}
	return zshExt
}
