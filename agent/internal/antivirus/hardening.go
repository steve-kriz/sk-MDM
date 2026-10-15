package antivirus

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// The policy setting keys the hardener acts on, the keys the backend validates
// in backend/src/admin/policies.ts. The five boolean keys are required when
// they hold the boolean true; SettingDefenderRansomwareProtection is required
// when it holds the string "audit" or "block". Anything else (absent, false or
// wrong-typed) means not required, never "turn off".
const (
	SettingDefenderRealTimeProtection   = "defenderRealTimeProtection"
	SettingDefenderCloudProtection      = "defenderCloudProtection"
	SettingDefenderNetworkProtection    = "defenderNetworkProtection"
	SettingDefenderRansomwareProtection = "defenderRansomwareProtection"
	SettingDefenderReputationProtection = "defenderReputationProtection"
	SettingDefenderDailySignatureUpdate = "defenderDailySignatureUpdate"
)

// The two defenderRansomwareProtection modes.
const (
	RansomwareModeAudit = "audit"
	RansomwareModeBlock = "block"
)

// The 14 items a DefenderHardening block reports, one per protection switch.
const (
	ItemRealTimeMonitoring      = "realTimeMonitoring"
	ItemBehaviorMonitoring      = "behaviorMonitoring"
	ItemIOAVProtection          = "ioavProtection"
	ItemScriptScanning          = "scriptScanning"
	ItemMAPSReporting           = "mapsReporting"
	ItemSubmitSamplesConsent    = "submitSamplesConsent"
	ItemNetworkProtection       = "networkProtection"
	ItemControlledFolderAccess  = "controlledFolderAccess"
	ItemPUAProtection           = "puaProtection"
	ItemSmartScreenWindows      = "smartScreenWindows"
	ItemSmartScreenEdge         = "smartScreenEdge"
	ItemSignatureUpdateInterval = "signatureUpdateInterval"
	ItemSignatureScheduleDay    = "signatureScheduleDay"
	ItemSignatureUpdate         = "signatureUpdate"
)

// The states one reported item can be in.
const (
	HardeningStateOK            = "ok"
	HardeningStateApplied       = "applied"
	HardeningStateFailed        = "failed"
	HardeningStateTamperBlocked = "tamper_blocked"
	HardeningStateNotApplicable = "not_applicable"
	HardeningStateWaiting       = "waiting"
)

// The fixed details an item can carry. A caught write error is carried
// verbatim instead, cut to MaxHardeningDetailRunes.
const (
	HardeningDetailDefenderUnavailable = "defender_unavailable"
	HardeningDetailDefenderPassive     = "defender_passive"
	HardeningDetailReadFailed          = "read_failed"
	HardeningDetailWriteFailed         = "write_failed"
	HardeningDetailTimeout             = "timeout"
	HardeningDetailUnparseable         = "unparseable"
	HardeningDetailUnchanged           = "unchanged after write"
	hardeningDetailWaitingPrefix       = "next attempt after "
)

// MaxHardeningDetailRunes is the longest detail one item carries.
const MaxHardeningDetailRunes = 256

// hardenerName is how the hardener is named in the log.
const hardenerName = "defender-hardening"

// runningModeNormal is the AMRunningMode of an active (not passive) Defender.
const runningModeNormal = "Normal"

// The registry keys the SmartScreen items read and write.
const (
	smartScreenSystemKey = `HKLM:\SOFTWARE\Policies\Microsoft\Windows\System`
	smartScreenEdgeKey   = `HKLM:\SOFTWARE\Policies\Microsoft\Edge`
)

// hardeningItem is one reported item: the policy key that drives it and
// whether it is a Defender preference (Set-MpPreference or Update-MpSignature)
// rather than a SmartScreen registry value.
type hardeningItem struct {
	name     string
	key      string
	defender bool
}

// hardeningItems lists every item in the fixed report order.
var hardeningItems = []hardeningItem{
	{ItemRealTimeMonitoring, SettingDefenderRealTimeProtection, true},
	{ItemBehaviorMonitoring, SettingDefenderRealTimeProtection, true},
	{ItemIOAVProtection, SettingDefenderRealTimeProtection, true},
	{ItemScriptScanning, SettingDefenderRealTimeProtection, true},
	{ItemMAPSReporting, SettingDefenderCloudProtection, true},
	{ItemSubmitSamplesConsent, SettingDefenderCloudProtection, true},
	{ItemNetworkProtection, SettingDefenderNetworkProtection, true},
	{ItemControlledFolderAccess, SettingDefenderRansomwareProtection, true},
	{ItemPUAProtection, SettingDefenderReputationProtection, true},
	{ItemSmartScreenWindows, SettingDefenderReputationProtection, false},
	{ItemSmartScreenEdge, SettingDefenderReputationProtection, false},
	{ItemSignatureUpdateInterval, SettingDefenderDailySignatureUpdate, true},
	{ItemSignatureScheduleDay, SettingDefenderDailySignatureUpdate, true},
	{ItemSignatureUpdate, SettingDefenderDailySignatureUpdate, true},
}

// hardeningPreferenceProperties is the Get-MpPreference property list the read
// body selects into "preferences".
const hardeningPreferenceProperties = `DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection, ` +
	`DisableScriptScanning, MAPSReporting, SubmitSamplesConsent, EnableNetworkProtection, ` +
	`EnableControlledFolderAccess, PUAProtection, SignatureUpdateInterval, SignatureScheduleDay`

// hardeningPrelude starts every hardening script: the errors table the write
// fragments fill and the two SmartScreen registry key paths.
const hardeningPrelude = `$errors = @{}; ` +
	`$sysKey = '` + smartScreenSystemKey + `'; ` +
	`$edgeKey = '` + smartScreenEdgeKey + `'; `

// hardeningReadBody reads every value the predicates judge and prints one JSON
// object. It only reads; every source carries -ErrorAction SilentlyContinue,
// so a stopped Defender yields defenderAvailable false, not an error. It never
// spells a PowerShell true literal, so no write script (which re-runs it)
// contains one.
const hardeningReadBody = `$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; ` +
	`$p = Get-MpPreference -ErrorAction SilentlyContinue; ` +
	`$ss = Get-ItemProperty -Path $sysKey -ErrorAction SilentlyContinue; ` +
	`$es = Get-ItemProperty -Path $edgeKey -ErrorAction SilentlyContinue; ` +
	`$prefs = if ($null -ne $p) { $p | Select-Object ` + hardeningPreferenceProperties + ` } else { $null }; ` +
	`$mode = if ($null -ne $s) { [string]$s.AMRunningMode } else { $null }; ` +
	`$tamper = if ($null -ne $s) { [bool]$s.IsTamperProtected } else { $null }; ` +
	`$age = if ($null -ne $s) { $s.AntivirusSignatureAge } else { $null }; ` +
	`$smart = [pscustomobject]@{enableSmartScreen=$ss.EnableSmartScreen; shellSmartScreenLevel=$ss.ShellSmartScreenLevel; ` +
	`edgeSmartScreenEnabled=$es.SmartScreenEnabled; edgeSmartScreenPuaEnabled=$es.SmartScreenPuaEnabled}; ` +
	`[pscustomobject]@{defenderAvailable=(($null -ne $s) -and ($null -ne $p)); runningMode=$mode; tamperProtected=$tamper; ` +
	`antivirusSignatureAge=$age; preferences=$prefs; smartScreen=$smart; errors=$errors} | ConvertTo-Json -Compress -Depth 4`

// HardeningReadScript is the read process: it prints the read body's JSON
// object with an empty errors object.
const HardeningReadScript = hardeningPrelude + hardeningReadBody

// SignatureUpdateScript is the signature update process: it updates the
// Defender signatures and prints the antivirus signature age afterwards as an
// antivirusSignatureAge= line.
const SignatureUpdateScript = `Update-MpSignature -ErrorAction Stop; ` +
	`$s = Get-MpComputerStatus -ErrorAction Stop; ` +
	`"antivirusSignatureAge=$($s.AntivirusSignatureAge)"`

// signatureAgeLinePrefix is the line SignatureUpdateScript prints.
const signatureAgeLinePrefix = "antivirusSignatureAge="

// Hardener keeps Microsoft Defender's protections switched on where a policy
// requires them, on Windows only. It implements agent/internal/enforce's
// Enforcer and is built once per agent, so its last block and the signature
// update retry window survive across cycles (in memory only). It never turns
// a protection off and never weakens a stronger value. All methods are safe
// for concurrent use.
type Hardener struct {
	runner platform.CommandRunner
	clock  platform.Clock
	goos   string

	mu sync.Mutex
	// last is the block of the last Apply, or nil before the first.
	last *contract.DefenderHardening
	// signatureFailedAt is when the last signature update failed; zero when
	// the last attempt succeeded or none failed.
	signatureFailedAt time.Time
}

// NewHardener returns the Defender hardener for goos.
func NewHardener(runner platform.CommandRunner, clock platform.Clock, goos string) *Hardener {
	return &Hardener{runner: runner, clock: clock, goos: goos}
}

// Name identifies the hardener in the log.
func (h *Hardener) Name() string { return hardenerName }

// Last returns a copy of the last Apply's block, or nil before the first Apply
// and always on a goos other than windows.
func (h *Hardener) Last() *contract.DefenderHardening {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.last == nil {
		return nil
	}
	c := &contract.DefenderHardening{EvaluatedAt: h.last.EvaluatedAt, Items: make([]contract.DefenderHardeningItem, len(h.last.Items))}
	copy(c.Items, h.last.Items)
	return c
}

// hardeningRead is one parsed read-body object.
type hardeningRead struct {
	available   bool
	runningMode string
	tamper      bool
	prefs       map[string]any
	smart       map[string]any
	errors      map[string]any
	// signatureAge is the antivirus signature age; signatureAgeKnown is false
	// when it was missing or non-numeric.
	signatureAge      int64
	signatureAgeKnown bool
}

// Apply runs one hardening pass on windows: a read process, at most one write
// process for the required items the read found not satisfied, and at most one
// signature update process. On any other goos it runs nothing and returns nil.
// It never writes twice and never loops; the next cycle tries again. It
// returns an error naming every item left failed or tamper_blocked.
func (h *Hardener) Apply(ctx context.Context, effective map[string]any, _ contract.Posture) error {
	if h.goos != "windows" {
		return nil
	}

	cfaMode := ransomwareMode(effective)
	required := requiredItems(effective, cfaMode)
	evaluatedAt := h.clock.Now().UTC().Format(time.RFC3339)
	results := map[string]contract.DefenderHardeningItem{}

	if len(required) == 0 {
		h.record(evaluatedAt, required, results)
		return nil
	}

	// 1. The read process.
	out, err, timedOut := runBounded(ctx, h.runner, h.clock, HardeningTimeout, windowsShell, windowsArgs(HardeningReadScript)...)
	var failDetail string
	switch {
	case timedOut:
		failDetail = HardeningDetailTimeout
	case err != nil || out.ExitCode != 0:
		failDetail = HardeningDetailReadFailed
	}
	var read hardeningRead
	if failDetail == "" {
		var ok bool
		if read, ok = parseHardeningRead(out.Stdout); !ok {
			failDetail = HardeningDetailUnparseable
		}
	}
	if failDetail != "" {
		for _, item := range required {
			results[item.name] = contract.DefenderHardeningItem{Item: item.name, State: HardeningStateFailed, Detail: failDetail}
		}
		h.record(evaluatedAt, required, results)
		return hardeningError(required, results)
	}

	// Defender items are not applicable when Defender is unavailable or
	// passive; everything else is judged against the read.
	var notApplicable string
	switch {
	case !read.available:
		notApplicable = HardeningDetailDefenderUnavailable
	case read.runningMode != runningModeNormal:
		notApplicable = HardeningDetailDefenderPassive
	}
	signatureRequired := false
	var toWrite []hardeningItem
	for _, item := range required {
		if item.defender && notApplicable != "" {
			results[item.name] = contract.DefenderHardeningItem{Item: item.name, State: HardeningStateNotApplicable, Detail: notApplicable}
			continue
		}
		if item.name == ItemSignatureUpdate {
			signatureRequired = true
			continue
		}
		if itemSatisfied(item.name, read, cfaMode) {
			results[item.name] = contract.DefenderHardeningItem{Item: item.name, State: HardeningStateOK}
			continue
		}
		toWrite = append(toWrite, item)
	}

	// 2. The write process, once, for every unsatisfied item.
	ageRead := read
	if len(toWrite) > 0 {
		script := hardeningWriteScript(toWrite, read, cfaMode)
		out, err, timedOut := runBounded(ctx, h.runner, h.clock, HardeningTimeout, windowsShell, windowsArgs(script)...)
		failDetail = ""
		switch {
		case timedOut:
			failDetail = HardeningDetailTimeout
		case err != nil || out.ExitCode != 0:
			failDetail = HardeningDetailWriteFailed
		}
		var after hardeningRead
		if failDetail == "" {
			var ok bool
			if after, ok = parseHardeningRead(out.Stdout); !ok {
				failDetail = HardeningDetailUnparseable
			}
		}
		for _, item := range toWrite {
			switch {
			case failDetail != "":
				results[item.name] = contract.DefenderHardeningItem{Item: item.name, State: HardeningStateFailed, Detail: failDetail}
			case itemSatisfied(item.name, after, cfaMode):
				results[item.name] = contract.DefenderHardeningItem{Item: item.name, State: HardeningStateApplied}
			default:
				state := HardeningStateFailed
				if item.defender && (after.tamper || read.tamper) {
					state = HardeningStateTamperBlocked
				}
				detail := HardeningDetailUnchanged
				if message, ok := after.errors[item.name].(string); ok && message != "" {
					detail = truncateRunes(message, MaxHardeningDetailRunes)
				}
				results[item.name] = contract.DefenderHardeningItem{Item: item.name, State: state, Detail: detail}
			}
		}
		if failDetail == "" {
			ageRead = after
		}
	}

	// 3. The signature update process.
	if signatureRequired {
		results[ItemSignatureUpdate] = h.updateSignatures(ctx, ageRead)
	}

	h.record(evaluatedAt, required, results)
	return hardeningError(required, results)
}

// updateSignatures decides and, when due, runs the signature update process.
// Fresh signatures (age 0) are ok with no process; inside the retry window
// after a failed attempt the item is waiting.
func (h *Hardener) updateSignatures(ctx context.Context, read hardeningRead) contract.DefenderHardeningItem {
	item := contract.DefenderHardeningItem{Item: ItemSignatureUpdate}
	if read.signatureAgeKnown && read.signatureAge == 0 {
		item.State = HardeningStateOK
		return item
	}

	h.mu.Lock()
	failedAt := h.signatureFailedAt
	h.mu.Unlock()
	if !failedAt.IsZero() {
		next := failedAt.Add(SignatureUpdateRetryInterval)
		if h.clock.Now().Before(next) {
			item.State = HardeningStateWaiting
			item.Detail = hardeningDetailWaitingPrefix + next.UTC().Format(time.RFC3339)
			return item
		}
	}

	out, err, timedOut := runBounded(ctx, h.runner, h.clock, SignatureUpdateTimeout, windowsShell, windowsArgs(SignatureUpdateScript)...)
	item.State = HardeningStateFailed
	switch {
	case timedOut:
		item.Detail = HardeningDetailTimeout
	case err != nil:
		item.Detail = truncateRunes(err.Error(), MaxHardeningDetailRunes)
	case out.ExitCode != 0:
		item.Detail = fmt.Sprintf("exit code %d", out.ExitCode)
	default:
		age, ok := parseSignatureAge(out.Stdout)
		switch {
		case !ok:
			item.Detail = HardeningDetailUnparseable
		case age == 0:
			item.State = HardeningStateApplied
		default:
			item.Detail = fmt.Sprintf("antivirusSignatureAge=%d after update", age)
		}
	}

	h.mu.Lock()
	if item.State == HardeningStateApplied {
		h.signatureFailedAt = time.Time{}
	} else {
		h.signatureFailedAt = h.clock.Now()
	}
	h.mu.Unlock()
	return item
}

// record stores this Apply's block: the required items in fixed order.
func (h *Hardener) record(evaluatedAt string, required []hardeningItem, results map[string]contract.DefenderHardeningItem) {
	block := &contract.DefenderHardening{EvaluatedAt: evaluatedAt, Items: make([]contract.DefenderHardeningItem, 0, len(required))}
	for _, item := range required {
		if result, ok := results[item.name]; ok {
			block.Items = append(block.Items, result)
		}
	}
	h.mu.Lock()
	h.last = block
	h.mu.Unlock()
}

// hardeningError names every failed or tamper_blocked item with its state, or
// is nil when there is none.
func hardeningError(required []hardeningItem, results map[string]contract.DefenderHardeningItem) error {
	var parts []string
	for _, item := range required {
		result, ok := results[item.name]
		if !ok || (result.State != HardeningStateFailed && result.State != HardeningStateTamperBlocked) {
			continue
		}
		part := result.Item + " " + result.State
		if result.Detail != "" {
			part += " (" + result.Detail + ")"
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return nil
	}
	return fmt.Errorf("defender hardening: %s", strings.Join(parts, ", "))
}

// ransomwareMode is the effective defenderRansomwareProtection mode, or "" when
// it is not "audit" or "block".
func ransomwareMode(effective map[string]any) string {
	mode, _ := effective[SettingDefenderRansomwareProtection].(string)
	if mode == RansomwareModeAudit || mode == RansomwareModeBlock {
		return mode
	}
	return ""
}

// requiredItems lists the items the effective settings require, in fixed
// order.
func requiredItems(effective map[string]any, cfaMode string) []hardeningItem {
	required := []hardeningItem{}
	for _, item := range hardeningItems {
		if item.key == SettingDefenderRansomwareProtection {
			if cfaMode != "" {
				required = append(required, item)
			}
			continue
		}
		if on, ok := effective[item.key].(bool); ok && on {
			required = append(required, item)
		}
	}
	return required
}

// itemSatisfied applies the read-back predicate of one item. A missing or
// non-numeric value is not satisfied.
func itemSatisfied(name string, read hardeningRead, cfaMode string) bool {
	pref := func(key string) (int64, bool) { return integerOf(read.prefs[key]) }
	isFalse := func(key string) bool {
		b, ok := read.prefs[key].(bool)
		return ok && !b
	}
	equals := func(key string, want ...int64) bool {
		n, ok := pref(key)
		if !ok {
			return false
		}
		for _, w := range want {
			if n == w {
				return true
			}
		}
		return false
	}
	smartEquals := func(key string, want int64) bool {
		n, ok := integerOf(read.smart[key])
		return ok && n == want
	}

	switch name {
	case ItemRealTimeMonitoring:
		return isFalse("DisableRealtimeMonitoring")
	case ItemBehaviorMonitoring:
		return isFalse("DisableBehaviorMonitoring")
	case ItemIOAVProtection:
		return isFalse("DisableIOAVProtection")
	case ItemScriptScanning:
		return isFalse("DisableScriptScanning")
	case ItemMAPSReporting:
		return equals("MAPSReporting", 2)
	case ItemSubmitSamplesConsent:
		return equals("SubmitSamplesConsent", 1, 3)
	case ItemNetworkProtection:
		return equals("EnableNetworkProtection", 1)
	case ItemControlledFolderAccess:
		if cfaMode == RansomwareModeBlock {
			return equals("EnableControlledFolderAccess", 1)
		}
		return equals("EnableControlledFolderAccess", 1, 2, 3)
	case ItemPUAProtection:
		return equals("PUAProtection", 1)
	case ItemSmartScreenWindows:
		return smartEquals("enableSmartScreen", 1) && shellLevelStrongEnough(read)
	case ItemSmartScreenEdge:
		return smartEquals("edgeSmartScreenEnabled", 1) && smartEquals("edgeSmartScreenPuaEnabled", 1)
	case ItemSignatureUpdateInterval:
		n, ok := pref("SignatureUpdateInterval")
		return ok && n >= 1 && n <= 24
	case ItemSignatureScheduleDay:
		return equals("SignatureScheduleDay", 0)
	case ItemSignatureUpdate:
		return read.signatureAgeKnown && read.signatureAge == 0
	}
	return false
}

// shellLevelStrongEnough reports whether ShellSmartScreenLevel is Warn or
// Block.
func shellLevelStrongEnough(read hardeningRead) bool {
	level, _ := read.smart["shellSmartScreenLevel"].(string)
	return level == "Warn" || level == "Block"
}

// hardeningWriteScript builds the write process: the prelude, each item's
// write fragment inside its own try/catch, then the read body again so the
// process prints the read-back with errors filled in.
func hardeningWriteScript(items []hardeningItem, read hardeningRead, cfaMode string) string {
	var b strings.Builder
	b.WriteString(hardeningPrelude)
	for _, item := range items {
		fragment := writeFragment(item.name, read, cfaMode)
		if fragment == "" {
			continue
		}
		b.WriteString("try { ")
		b.WriteString(fragment)
		b.WriteString(" } catch { $errors['")
		b.WriteString(item.name)
		b.WriteString("'] = $_.Exception.Message }; ")
	}
	b.WriteString(hardeningReadBody)
	return b.String()
}

// writeFragment is one unsatisfied item's write. No fragment ever disables a
// protection, writes a registry value of 0 or downgrades a stronger value.
func writeFragment(name string, read hardeningRead, cfaMode string) string {
	switch name {
	case ItemRealTimeMonitoring:
		return `Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop`
	case ItemBehaviorMonitoring:
		return `Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop`
	case ItemIOAVProtection:
		return `Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop`
	case ItemScriptScanning:
		return `Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop`
	case ItemMAPSReporting:
		return `Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop`
	case ItemSubmitSamplesConsent:
		return `Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop`
	case ItemNetworkProtection:
		return `Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop`
	case ItemControlledFolderAccess:
		if cfaMode == RansomwareModeBlock {
			return `Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop`
		}
		// Audit is only written for 0, 4 or a missing value: 1, 2 and 3
		// satisfy audit, so a value of 1 never reaches here.
		return `Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction Stop`
	case ItemPUAProtection:
		return `Set-MpPreference -PUAProtection Enabled -ErrorAction Stop`
	case ItemSmartScreenWindows:
		fragment := `if (-not (Test-Path -Path $sysKey)) { New-Item -Path $sysKey -Force -ErrorAction Stop | Out-Null }; ` +
			`Set-ItemProperty -Path $sysKey -Name EnableSmartScreen -Type DWord -Value 1 -ErrorAction Stop`
		if !shellLevelStrongEnough(read) {
			fragment += `; Set-ItemProperty -Path $sysKey -Name ShellSmartScreenLevel -Type String -Value Warn -ErrorAction Stop`
		}
		return fragment
	case ItemSmartScreenEdge:
		return `if (-not (Test-Path -Path $edgeKey)) { New-Item -Path $edgeKey -Force -ErrorAction Stop | Out-Null }; ` +
			`Set-ItemProperty -Path $edgeKey -Name SmartScreenEnabled -Type DWord -Value 1 -ErrorAction Stop; ` +
			`Set-ItemProperty -Path $edgeKey -Name SmartScreenPuaEnabled -Type DWord -Value 1 -ErrorAction Stop`
	case ItemSignatureUpdateInterval:
		return `Set-MpPreference -SignatureUpdateInterval 24 -ErrorAction Stop`
	case ItemSignatureScheduleDay:
		return `Set-MpPreference -SignatureScheduleDay Everyday -ErrorAction Stop`
	}
	return ""
}

// parseHardeningRead reads the read body's single JSON object. The second
// return is false when stdout is too large or not exactly one object.
func parseHardeningRead(stdout string) (hardeningRead, bool) {
	if len(stdout) > MaxStatusOutputBytes {
		return hardeningRead{}, false
	}
	fields, err := decodeObject(stdout)
	if err != nil {
		return hardeningRead{}, false
	}
	read := hardeningRead{}
	read.available, _ = fields["defenderAvailable"].(bool)
	read.runningMode, _ = fields["runningMode"].(string)
	read.tamper, _ = fields["tamperProtected"].(bool)
	read.prefs, _ = fields["preferences"].(map[string]any)
	read.smart, _ = fields["smartScreen"].(map[string]any)
	read.errors, _ = fields["errors"].(map[string]any)
	read.signatureAge, read.signatureAgeKnown = integerOf(fields["antivirusSignatureAge"])
	return read, true
}

// parseSignatureAge reads the last antivirusSignatureAge=<integer> line. The
// second return is false when there is no such line with an integer.
func parseSignatureAge(stdout string) (int64, bool) {
	age, found := int64(0), false
	for _, line := range splitLines(stdout) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, signatureAgeLinePrefix) {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, signatureAgeLinePrefix)), 10, 64)
		if err != nil {
			found = false
			continue
		}
		age, found = n, true
	}
	return age, found
}
