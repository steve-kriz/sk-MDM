package antivirus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// SettingAntivirusScanFrequency is the policy setting key the scanner acts on,
// the key the backend validates in backend/src/admin/policies.ts.
const SettingAntivirusScanFrequency = "antivirusScanFrequency"

// scannerName is how the scanner is named in the log.
const scannerName = "antivirus-scan"

// WindowsScanScript runs one Microsoft Defender quick scan and prints how many
// threats were detected since it started, as a threatsFound= line.
const WindowsScanScript = `$start = Get-Date; ` +
	`Start-MpScan -ScanType QuickScan -ErrorAction Stop; ` +
	`$n = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $start }).Count; ` +
	`"threatsFound=$n"`

// Scan state file locations, under the same directory as the agent state
// file. The record has a file of its own so a restart does not re-scan inside
// the interval.
const (
	// WindowsScanStatePath is the scan state location on Windows.
	WindowsScanStatePath = `C:\ProgramData\OfficeHQ\MDM\antivirus-scan.json`
	// DarwinScanStatePath is the scan state location on macOS.
	DarwinScanStatePath = "/Library/Application Support/OfficeHQ/MDM/antivirus-scan.json"
)

// ScanStateFileMode is the mode the scan state file is written with.
const ScanStateFileMode fs.FileMode = 0o600

// ScanStatePath returns the scan state location for a GOOS value: the Windows
// path for "windows" and the macOS path for anything else.
func ScanStatePath(goos string) string {
	if goos == "windows" {
		return WindowsScanStatePath
	}
	return DarwinScanStatePath
}

// Scan results and the one scan type, the values contract.AntivirusScan
// carries.
const (
	ScanTypeQuick          = "quick"
	ScanResultClean        = "clean"
	ScanResultThreatsFound = "threats_found"
	ScanResultFailed       = "failed"
	ScanResultTimeout      = "timeout"
	ScanResultUnsupported  = "unsupported"
	maxScanDetailRunes     = 256
	scanDetailUnparseable  = "unparseable output"
	threatsFoundLinePrefix = "threatsFound="
)

// scanIntervals maps each frequency that turns scanning on to how long after a
// record's startedAt the next scan is due. Any other value means off.
var scanIntervals = map[string]time.Duration{
	"daily":   24 * time.Hour,
	"weekly":  168 * time.Hour,
	"monthly": 720 * time.Hour,
}

// Scanner runs scheduled Microsoft Defender quick scans in the background. It
// implements agent/internal/enforce's Enforcer and is built once per agent, so
// its in-flight guard and last record survive across cycles. All methods are
// safe for concurrent use.
type Scanner struct {
	runner platform.CommandRunner
	clock  platform.Clock
	fsys   platform.FileSystem
	goos   string
	logger *logging.Logger
	path   string

	mu       sync.Mutex
	inFlight bool
	record   *contract.AntivirusScan
	// frequencyOn is whether the last Apply saw a frequency that turns
	// scanning on; on a platform without scans it makes Last report
	// "unsupported".
	frequencyOn bool

	// wg tracks the background scan so tests can wait for it to finish.
	wg sync.WaitGroup
}

// NewScanner returns the scanner for goos, persisting its record at path. The
// record already at path, if any, is loaded now; a file that cannot be read or
// decoded costs one warning line and counts as no record. A nil logger is
// allowed.
func NewScanner(runner platform.CommandRunner, clock platform.Clock, fsys platform.FileSystem, goos string, logger *logging.Logger, path string) *Scanner {
	s := &Scanner{runner: runner, clock: clock, fsys: fsys, goos: goos, logger: logger, path: path}
	s.record = s.load()
	return s
}

// Name identifies the scanner in the log.
func (s *Scanner) Name() string { return scannerName }

// Apply starts one quick scan on a goroutine when goos is windows, the
// effective antivirusScanFrequency is daily, weekly or monthly, no scan is in
// flight and one is due: there is no record, or the frequency's interval has
// passed since the record's startedAt. It never waits for the scan and always
// returns nil. ctx bounds the scan: when it is cancelled before the command
// returns, no record is written.
func (s *Scanner) Apply(ctx context.Context, effective map[string]any, _ contract.Posture) error {
	frequency, _ := effective[SettingAntivirusScanFrequency].(string)
	interval, on := scanIntervals[frequency]

	s.mu.Lock()
	defer s.mu.Unlock()
	s.frequencyOn = on

	if s.goos != "windows" || !on || s.inFlight {
		return nil
	}
	if !s.dueLocked(interval) {
		return nil
	}

	s.inFlight = true
	s.wg.Add(1)
	go s.scan(ctx)
	return nil
}

// Last returns a copy of the record to report on the next check-in, or nil
// when there is none. On a platform without scans it is the "unsupported"
// record while the last Apply saw scanning on.
func (s *Scanner) Last() *contract.AntivirusScan {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.goos != "windows" && s.frequencyOn {
		return &contract.AntivirusScan{ScanType: ScanTypeQuick, Result: ScanResultUnsupported}
	}
	return copyScan(s.record)
}

// wait blocks until the background scan, if any, has finished.
func (s *Scanner) wait() { s.wg.Wait() }

// dueLocked reports whether a scan is due under interval. s.mu must be held.
func (s *Scanner) dueLocked(interval time.Duration) bool {
	if s.record == nil || s.record.StartedAt == nil {
		return true
	}
	started, err := time.Parse(time.RFC3339Nano, *s.record.StartedAt)
	if err != nil {
		return true
	}
	return s.clock.Now().Sub(started) >= interval
}

// scan runs the scan command once, maps its outcome to a record and persists
// it, unless ctx was cancelled first.
func (s *Scanner) scan(ctx context.Context) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		s.inFlight = false
		s.mu.Unlock()
	}()

	startedAt := s.clock.Now().UTC()
	out, err, timedOut := s.runScan(ctx)
	completedAt := s.clock.Now().UTC()

	// A cancelled agent context (service stop) also surfaces as a runner
	// error; it must never be recorded as a failed scan.
	if ctx.Err() != nil {
		return
	}

	started := startedAt.Format(time.RFC3339)
	completed := completedAt.Format(time.RFC3339)
	record := &contract.AntivirusScan{
		ScanType:    ScanTypeQuick,
		StartedAt:   &started,
		CompletedAt: &completed,
	}
	switch {
	case timedOut:
		record.Result = ScanResultTimeout
	case err != nil:
		record.Result = ScanResultFailed
		record.Detail = truncateRunes(err.Error(), maxScanDetailRunes)
	case out.ExitCode != 0:
		record.Result = ScanResultFailed
		record.Detail = fmt.Sprintf("exit code %d", out.ExitCode)
	default:
		n, ok := parseThreatsFound(out.Stdout)
		switch {
		case !ok:
			record.Result = ScanResultFailed
			record.Detail = scanDetailUnparseable
		case n == 0:
			record.Result = ScanResultClean
		default:
			record.Result = ScanResultThreatsFound
			record.ThreatsFound = n
		}
	}

	s.save(record)
	s.mu.Lock()
	s.record = record
	s.mu.Unlock()
}

// runScan runs WindowsScanScript and waits at most ScanTimeout on the clock,
// or until ctx is cancelled. The third return is true when the deadline passed
// first; the command's context is cancelled in every case on return.
func (s *Scanner) runScan(ctx context.Context) (platform.CommandResult, error, bool) {
	cmdCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan commandResult, 1)
	deadline := s.clock.After(ScanTimeout)

	go func() {
		out, err := s.runner.Run(cmdCtx, windowsShell, windowsArgs(WindowsScanScript)...)
		results <- commandResult{out: out, err: err}
	}()

	select {
	case res := <-results:
		return res.out, res.err, false
	case <-ctx.Done():
		return platform.CommandResult{}, ctx.Err(), false
	case <-deadline:
		select {
		case res := <-results:
			return res.out, res.err, false
		default:
			return platform.CommandResult{}, nil, true
		}
	}
}

// parseThreatsFound reads the last threatsFound= line as a non-negative
// integer. The second return is false when there is no such line.
func parseThreatsFound(stdout string) (int, bool) {
	n, found := 0, false
	for _, line := range splitLines(stdout) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, threatsFoundLinePrefix) {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, threatsFoundLinePrefix)))
		if err != nil || v < 0 {
			found = false
			continue
		}
		n, found = v, true
	}
	return n, found
}

// load reads the persisted record. A missing file is no record; a file that
// cannot be read or does not hold a record with a valid startedAt is no record
// and one warning line.
func (s *Scanner) load() *contract.AntivirusScan {
	data, err := s.fsys.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		s.warn("antivirus scan state unreadable", logging.F("path", s.path), logging.F("error", err.Error()))
		return nil
	}
	var record contract.AntivirusScan
	if err := json.Unmarshal(data, &record); err != nil {
		s.warn("antivirus scan state corrupt", logging.F("path", s.path), logging.F("error", err.Error()))
		return nil
	}
	if record.StartedAt == nil {
		s.warn("antivirus scan state corrupt", logging.F("path", s.path), logging.F("error", "missing startedAt"))
		return nil
	}
	if _, err := time.Parse(time.RFC3339Nano, *record.StartedAt); err != nil {
		s.warn("antivirus scan state corrupt", logging.F("path", s.path), logging.F("error", err.Error()))
		return nil
	}
	return &record
}

// save writes record atomically with mode 0600. A failure costs one warning
// line; the in-memory record is still kept.
func (s *Scanner) save(record *contract.AntivirusScan) {
	data, err := json.Marshal(record)
	if err == nil {
		err = platform.WriteFileAtomic(s.fsys, s.path, data, ScanStateFileMode)
	}
	if err != nil {
		s.warn("antivirus scan state not saved", logging.F("path", s.path), logging.F("error", err.Error()))
	}
}

// warn writes one warning, or nothing when there is no logger.
func (s *Scanner) warn(msg string, fields ...logging.Field) {
	if s.logger == nil {
		return
	}
	_ = s.logger.Log(logging.LevelWarn, msg, fields...)
}

// copyScan returns a deep copy of record, or nil.
func copyScan(record *contract.AntivirusScan) *contract.AntivirusScan {
	if record == nil {
		return nil
	}
	c := *record
	if record.StartedAt != nil {
		v := *record.StartedAt
		c.StartedAt = &v
	}
	if record.CompletedAt != nil {
		v := *record.CompletedAt
		c.CompletedAt = &v
	}
	return &c
}
