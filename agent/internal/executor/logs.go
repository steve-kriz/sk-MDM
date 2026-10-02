package executor

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io/fs"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
)

// MaxLogArchiveBytes is the largest archive collect_logs will leave on the
// device. Past it the archive is deleted and the command fails: a device with
// a pathological log directory must not fill its own disk answering a support
// request.
const MaxLogArchiveBytes = 20971520 // 20 MB

// Log directory locations, beside the config, state and spool the installer
// creates.
const (
	// WindowsLogDir is the agent's log directory on Windows.
	WindowsLogDir = `C:\ProgramData\OfficeHQ\MDM\logs`
	// DarwinLogDir is the agent's log directory on macOS.
	DarwinLogDir = "/Library/Application Support/OfficeHQ/MDM/logs"
)

// LogDir returns the log directory for a GOOS value: the Windows path for
// "windows" and the macOS path for anything else, the agent shipping for those
// two platforms only.
func LogDir(goos string) string {
	if goos == "windows" {
		return WindowsLogDir
	}
	return DarwinLogDir
}

// collectLogs zips the agent's log directory to a temp path and reports where
// it put it.
//
// Delivery is local in v1: the archive stays on the device and the result
// names it, so support can collect it over whatever remote access they already
// have. Nothing is uploaded — there is no upload endpoint and no HTTP request
// is made by this command type.
func collectLogs(cmd Command, deps *Deps) contract.CommandResultRequest {
	if _, ok := decodeTimeout(cmd.Payload); !ok {
		return deps.fail(ErrInvalidPayload, "")
	}

	archive, err := buildLogArchive(deps)
	if err != nil {
		return deps.fail(ErrLogsFailed, err.Error())
	}

	path := deps.tempPath("mdm-logs-", cmd.CommandID, ".zip")
	if err := deps.writeTemp(path, archive); err != nil {
		return deps.fail(ErrLogsFailed, err.Error())
	}

	if len(archive) > MaxLogArchiveBytes {
		// It was written before it was measured, so it is removed before the
		// failure is reported: the device is left as it was found.
		deps.removeTemp(path)
		return deps.fail(ErrLogsTooLarge, fmt.Sprintf("%s (%d bytes)", path, len(archive)))
	}

	deps.log(logging.LevelInfo, "collected logs",
		logging.F("commandId", cmd.CommandID),
		logging.F("path", path),
		logging.F("bytes", len(archive)),
	)

	return deps.succeed(fmt.Sprintf("logs: %s (%d bytes)", path, len(archive)))
}

// buildLogArchive is every file in the log directory, zipped in memory.
//
// Sub-directories are skipped and a file that cannot be read costs one warning
// rather than the archive: support would rather have the logs that are
// readable than none at all. A log directory that does not exist is an agent
// that has not logged yet, and yields an empty archive.
func buildLogArchive(deps *Deps) ([]byte, error) {
	dir := deps.LogDir
	if dir == "" {
		dir = LogDir(deps.goos())
	}

	entries, err := deps.FS.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	var buf bytes.Buffer
	archive := zip.NewWriter(&buf)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := deps.FS.ReadFile(joinPath(dir, entry.Name()))
		if err != nil {
			deps.log(logging.LevelWarn, "log file unreadable",
				logging.F("file", entry.Name()),
				logging.F("error", err.Error()),
			)
			continue
		}

		file, err := archive.Create(entry.Name())
		if err != nil {
			return nil, err
		}
		if _, err := file.Write(data); err != nil {
			return nil, err
		}
	}

	if err := archive.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
