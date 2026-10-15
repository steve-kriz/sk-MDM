// Package contract holds the frozen agent-to-backend wire contract: the
// message types the agent exchanges with the Lambda and the request signing
// scheme that authenticates them.
//
// Every json tag here matches a field name in backend/src/contract/types.ts,
// in contract/openapi.yaml and in the golden messages under
// contract/testdata/messages/. Renaming a field means changing all four.
//
// Two authentication schemes exist on this API:
//   - POST /api/v1/enroll is authenticated by the X-MDM-Enrollment-Token
//     header alone, over TLS (the token is installer-provided, or minted at
//     sign-in with the user's Entra token); at enroll time there is no
//     device id and no device secret, so the HMAC scheme cannot be applied
//     there.
//   - Every /api/v1/devices/... operation is authenticated by the device HMAC
//     scheme in signing.go.
//
// Timestamps documented as "ISO-8601 UTC" are strings such as
// "2026-10-02T07:15:00Z". The signing scheme uses epoch seconds instead, as
// does a command result's FinishedAt; a command's own IssuedAt and ExpiresAt
// are epoch milliseconds. Each field's unit is stated on the field.
package contract

import "encoding/json"

// EnrollRequest is the body of POST /api/v1/enroll.
//
// HardwareUUID is the stable hardware identifier — the machine UUID on
// Windows and the hardware UUID on macOS — and is what lets the backend
// recognise a device that enrolls a second time after a re-install.
type EnrollRequest struct {
	Hostname     string `json:"hostname"`
	Platform     string `json:"platform"` // "windows" or "darwin"
	OSVersion    string `json:"osVersion"`
	HardwareUUID string `json:"hardwareUuid"`
	AgentVersion string `json:"agentVersion"`
	// Ownership is "officehq" or "byoc". It is optional on the wire: the
	// backend reads an absent value as "officehq".
	Ownership string `json:"ownership,omitempty"`
}

// EnrollResponse is the body of a successful POST /api/v1/enroll. It carries
// the device HMAC secret exactly once; the agent must persist it immediately.
type EnrollResponse struct {
	DeviceID               string `json:"deviceId"`
	DeviceSecret           string `json:"deviceSecret"` // lower-case hex HMAC key
	CheckInIntervalSeconds int    `json:"checkInIntervalSeconds"`
	ServerTime             string `json:"serverTime"` // ISO-8601 UTC
}

// InventoryHardware is the hardware block of Inventory.
type InventoryHardware struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	SerialNumber string `json:"serialNumber"`
	CPU          string `json:"cpu"`
	RAMBytes     int64  `json:"ramBytes"`
	DiskBytes    int64  `json:"diskBytes"`

	// The device-detail fields below are optional: an agent that does not
	// collect them marshals the block exactly as before.
	SystemFamily         string `json:"systemFamily,omitempty"`
	SystemSKU            string `json:"systemSku,omitempty"`
	CPUCores             int    `json:"cpuCores,omitempty"`
	CPULogicalProcessors int    `json:"cpuLogicalProcessors,omitempty"`
}

// InventoryOS is the os block of Inventory.
type InventoryOS struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Build        string `json:"build"`
	Architecture string `json:"architecture"`

	// The device-detail fields below are optional. UBR is a pointer so a
	// revision of 0 is distinguishable from "not collected".
	Edition        string `json:"edition,omitempty"`
	DisplayVersion string `json:"displayVersion,omitempty"`
	UBR            *int   `json:"ubr,omitempty"`
	InstallDate    string `json:"installDate,omitempty"` // ISO-8601 UTC
	LastBootAt     string `json:"lastBootAt,omitempty"`  // ISO-8601 UTC
	Locale         string `json:"locale,omitempty"`
}

// InventoryFirmware is the optional firmware block of Inventory. The booleans
// are pointers: nil means the value could not be read, which is not the same
// as false.
type InventoryFirmware struct {
	Type              string `json:"type,omitempty"` // "uefi" or "bios"
	BIOSVersion       string `json:"biosVersion,omitempty"`
	BIOSReleaseDate   string `json:"biosReleaseDate,omitempty"` // ISO-8601 UTC
	SecureBootEnabled *bool  `json:"secureBootEnabled,omitempty"`
	TPMPresent        *bool  `json:"tpmPresent,omitempty"`
	TPMReady          *bool  `json:"tpmReady,omitempty"`
	TPMVersion        string `json:"tpmVersion,omitempty"`
}

// InventoryDisk is one fixed logical volume in Inventory.Disks.
type InventoryDisk struct {
	DeviceID   string `json:"deviceId,omitempty"`
	FileSystem string `json:"fileSystem,omitempty"`
	SizeBytes  int64  `json:"sizeBytes,omitempty"`
	FreeBytes  int64  `json:"freeBytes,omitempty"`
}

// InventoryPhysicalDisk is one physical drive in Inventory.PhysicalDisks.
type InventoryPhysicalDisk struct {
	Model     string `json:"model,omitempty"`
	MediaType string `json:"mediaType,omitempty"` // "ssd", "hdd", "scm" or "unspecified"
	SizeBytes int64  `json:"sizeBytes,omitempty"`
}

// InventoryNetworkAdapter is one IP-enabled adapter in Inventory.Network.
type InventoryNetworkAdapter struct {
	Description string   `json:"description,omitempty"`
	MACAddress  string   `json:"macAddress,omitempty"`
	IPv4        []string `json:"ipv4,omitempty"`
	IPv6        []string `json:"ipv6,omitempty"`
	DHCPEnabled *bool    `json:"dhcpEnabled,omitempty"`
	DNSServers  []string `json:"dnsServers,omitempty"`
	Gateways    []string `json:"gateways,omitempty"`
}

// InventoryJoin is the optional directory-join block of Inventory.
type InventoryJoin struct {
	AzureADJoined *bool  `json:"azureAdJoined,omitempty"`
	DomainJoined  *bool  `json:"domainJoined,omitempty"`
	Domain        string `json:"domain,omitempty"`
	TenantName    string `json:"tenantName,omitempty"`
	TenantID      string `json:"tenantId,omitempty"`
	EntraDeviceID string `json:"entraDeviceId,omitempty"`
}

// SoftwareEntry is one installed application in Inventory.Software.
type SoftwareEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstalledAt string `json:"installedAt"` // ISO-8601 UTC
}

// Inventory is the hardware, OS and software snapshot the agent collects.
//
// Warnings is omitempty: a collection with no warnings marshals without a
// "warnings" key rather than with "warnings": null.
type Inventory struct {
	Hardware InventoryHardware `json:"hardware"`
	OS       InventoryOS       `json:"os"`
	Software []SoftwareEntry   `json:"software"`

	// The device-detail blocks are optional and omitted when not collected,
	// so an inventory from an agent without them marshals as before.
	Firmware      *InventoryFirmware        `json:"firmware,omitempty"`
	Disks         []InventoryDisk           `json:"disks,omitempty"`
	PhysicalDisks []InventoryPhysicalDisk   `json:"physicalDisks,omitempty"`
	Network       []InventoryNetworkAdapter `json:"network,omitempty"`
	Join          *InventoryJoin            `json:"join,omitempty"`

	Warnings []string `json:"warnings,omitempty"`
}

// DiskEncryption is the diskEncryption block of Posture.
type DiskEncryption struct {
	Enabled bool   `json:"enabled"`
	Method  string `json:"method"` // "bitlocker" or "filevault"
}

// Firewall is the firewall block of Posture. It carries no field but Enabled.
type Firewall struct {
	Enabled bool `json:"enabled"`
}

// Antivirus is the antivirus block of Posture.
type Antivirus struct {
	Name string `json:"name"`
	// Enabled is true when antivirus is active on the device. On Windows that
	// means Microsoft Defender reports itself enabled with real-time
	// protection on (Microsoft Defender counts as enabled only when real-time
	// protection is on), or any antivirus product registered with Windows
	// Security Center is active; on macOS it means the XProtect bundle is
	// present.
	Enabled            bool `json:"enabled"`
	DefinitionsAgeDays int  `json:"definitionsAgeDays"`
}

// OSUpdate is the osUpdate block of Posture.
type OSUpdate struct {
	LastCheckedAt  string `json:"lastCheckedAt"` // ISO-8601 UTC
	PendingCount   int    `json:"pendingCount"`
	RebootRequired bool   `json:"rebootRequired"`
}

// Posture is the security posture snapshot the agent collects.
//
// Warnings is omitempty, exactly as on Inventory.
type Posture struct {
	DiskEncryption DiskEncryption `json:"diskEncryption"`
	Firewall       Firewall       `json:"firewall"`
	Antivirus      Antivirus      `json:"antivirus"`
	OSUpdate       OSUpdate       `json:"osUpdate"`
	LocalAdmins    []string       `json:"localAdmins"`
	Warnings       []string       `json:"warnings,omitempty"`
}

// PolicyComplianceEntry is one locally evaluated policy result.
//
// Violations is always present, as an empty array when Compliant is true, so
// the backend never has to tell absent from empty inside an entry.
type PolicyComplianceEntry struct {
	PolicyID   string   `json:"policyId"`
	Version    int      `json:"version"`
	Compliant  bool     `json:"compliant"`
	Violations []string `json:"violations"` // e.g. "firewall_disabled"
}

// AntivirusFinding is one threat detection the device's antivirus reported:
// a Microsoft Defender detection on Windows, an XProtect Remediator event on
// macOS. The first six fields are always present. The eight after them are
// optional (omitempty): only a Windows Defender detection carries them, and an
// agent omits each one it could not read. Active is a pointer so a missing
// threat record is never reported as not active.
type AntivirusFinding struct {
	FindingID  string   `json:"findingId"`
	ThreatName string   `json:"threatName"`
	Severity   string   `json:"severity"`   // unknown, low, moderate, high or severe
	DetectedAt string   `json:"detectedAt"` // ISO-8601 UTC
	Resources  []string `json:"resources"`
	Remediated bool     `json:"remediated"`

	Category           string `json:"category,omitempty"`           // e.g. "Trojan"
	Status             string `json:"status,omitempty"`             // e.g. "quarantined"
	Action             string `json:"action,omitempty"`             // e.g. "quarantine"
	Active             *bool  `json:"active,omitempty"`             // whether the threat is still active
	LastStatusChangeAt string `json:"lastStatusChangeAt,omitempty"` // ISO-8601 UTC
	RemediatedAt       string `json:"remediatedAt,omitempty"`       // ISO-8601 UTC
	ProcessName        string `json:"processName,omitempty"`        // at most 260 runes
	User               string `json:"user,omitempty"`               // at most 256 runes
}

// CheckInRequest is the body of POST /api/v1/devices/{deviceId}/checkin.
//
// PolicyCompliance and AgentVersion are omitempty: a check-in that reports
// nothing marshals without a "policyCompliance" key, and an agent that does not
// name its build marshals without an "agentVersion" one. AntivirusFindings is
// omitempty too: a cycle with no detections sends no "antivirusFindings" key.
// Analytics is a pointer with omitempty: an agent that collects no endpoint
// analytics sends no "analytics" key. TimeZone is omitempty as well: an agent
// that could not work out the device's IANA time zone sends no "timeZone" key.
// AntivirusScan is a pointer with omitempty: an agent with no scan result to
// report sends no "antivirusScan" key. AntivirusStatus is a pointer with
// omitempty as well: a cycle whose status probe failed, or a platform with no
// status collector, sends no "antivirusStatus" key. DefenderHardening is a
// pointer with omitempty too: an agent whose Defender hardener has not applied
// (macOS, or no result yet) sends no "defenderHardening" key. AgentErrors is
// omitempty as well: a cycle whose agent logged no warn or error record since
// the last check-in body sends no "agentErrors" key. AgentActions is omitempty
// too: a cycle in which the agent performed no reportable action since the
// last check-in body sends no "agentActions" key.
type CheckInRequest struct {
	CollectedAt       string                  `json:"collectedAt"` // ISO-8601 UTC
	Inventory         Inventory               `json:"inventory"`
	Posture           Posture                 `json:"posture"`
	AgentVersion      string                  `json:"agentVersion,omitempty"`
	TimeZone          string                  `json:"timeZone,omitempty"` // IANA zone name
	PolicyCompliance  []PolicyComplianceEntry `json:"policyCompliance,omitempty"`
	AntivirusFindings []AntivirusFinding      `json:"antivirusFindings,omitempty"`
	Analytics         *Analytics              `json:"analytics,omitempty"`
	AntivirusScan     *AntivirusScan          `json:"antivirusScan,omitempty"`
	AntivirusStatus   *AntivirusStatus        `json:"antivirusStatus,omitempty"`
	DefenderHardening *DefenderHardening      `json:"defenderHardening,omitempty"`
	AgentErrors       []AgentError            `json:"agentErrors,omitempty"`  // at most 50
	AgentActions      []AgentAction           `json:"agentActions,omitempty"` // at most 20
}

// Agent action types: the wire and device event "type" of an AgentAction.
const (
	ActionFirewallEnabled       = "enforce.firewall_enabled"
	ActionAntivirusEnabled      = "enforce.antivirus_enabled"
	ActionDomainsUpdated        = "enforce.domains_updated"
	ActionAgentUpdateRolledBack = "agent.update_rolled_back"
)

// AgentAction is one action the agent performed on the device, reported on
// check-in so it appears in the device History. The agent sends no summary:
// the backend builds it from Type and Details. Details marshals as an empty
// object, never null, when it is nil.
type AgentAction struct {
	Type       string            `json:"type"`
	OccurredAt string            `json:"occurredAt"` // ISO-8601 UTC, seconds
	Details    map[string]string `json:"details"`
}

// MarshalJSON writes Details as {} when it is nil.
func (a AgentAction) MarshalJSON() ([]byte, error) {
	type plain AgentAction
	p := plain(a)
	if p.Details == nil {
		p.Details = map[string]string{}
	}
	return json.Marshal(p)
}

// AgentError is one distinct warn or error record the agent logged, with
// repeats of the same (level, component, message) collapsed into Count.
// Fields holds the latest record's fields (at most 8, values at most 256
// runes, keys at most 64); it is an empty object, never null, when the record
// had none.
type AgentError struct {
	Level     string            `json:"level"`     // "warn" or "error"
	Component string            `json:"component"` // at most 64 runes
	Message   string            `json:"message"`   // at most 256 runes
	Fields    map[string]string `json:"fields"`
	Count     int               `json:"count"`   // >= 1
	FirstAt   string            `json:"firstAt"` // ISO-8601 UTC
	LastAt    string            `json:"lastAt"`  // ISO-8601 UTC
}

// DefenderHardening is what the Defender protections hardener did to each
// protection a policy requires, in one Apply. Items lists only required
// items, in the fixed item order, and is an empty slice (marshalled as []),
// never nil, when nothing is required.
type DefenderHardening struct {
	EvaluatedAt string                  `json:"evaluatedAt"` // ISO-8601 UTC
	Items       []DefenderHardeningItem `json:"items"`       // at most 14
}

// DefenderHardeningItem is one protection's outcome. Item is one of the 14
// item names (realTimeMonitoring ... signatureUpdate); State is ok, applied,
// failed, tamper_blocked, not_applicable or waiting. Detail is omitted when
// there is nothing to add.
type DefenderHardeningItem struct {
	Item   string `json:"item"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"` // at most 256 runes
}

// AntivirusStatus is the device antivirus's full status: protection states,
// versions, signature ages, the antivirus's own last scans, its computer state
// and the products Windows Security Center lists. Every key is always sent; a
// nil pointer marshals as null when the device did not report the value.
// SecurityCenterProducts is an empty slice (marshalled as []), never nil.
type AntivirusStatus struct {
	Product                string                  `json:"product"` // "Microsoft Defender" or "XProtect"
	DefenderAvailable      bool                    `json:"defenderAvailable"`
	RunningMode            *string                 `json:"runningMode"` // at most 64 runes
	Protection             AntivirusProtection     `json:"protection"`
	Versions               AntivirusVersions       `json:"versions"`
	Signatures             AntivirusSignatures     `json:"signatures"`
	Scans                  AntivirusScans          `json:"scans"`
	ComputerState          *int                    `json:"computerState"` // 0..65535
	RebootRequired         *bool                   `json:"rebootRequired"`
	SecurityCenterProducts []SecurityCenterProduct `json:"securityCenterProducts"`
}

// AntivirusProtection is the Defender protection switches.
type AntivirusProtection struct {
	AMServiceEnabled          *bool `json:"amServiceEnabled"`
	AntispywareEnabled        *bool `json:"antispywareEnabled"`
	AntivirusEnabled          *bool `json:"antivirusEnabled"`
	BehaviorMonitorEnabled    *bool `json:"behaviorMonitorEnabled"`
	IoavProtectionEnabled     *bool `json:"ioavProtectionEnabled"`
	OnAccessProtectionEnabled *bool `json:"onAccessProtectionEnabled"`
	RealTimeProtectionEnabled *bool `json:"realTimeProtectionEnabled"`
	NISEnabled                *bool `json:"nisEnabled"`
	TamperProtected           *bool `json:"tamperProtected"`
}

// AntivirusVersions is the engine, platform and signature versions. Each is
// at most 64 runes.
type AntivirusVersions struct {
	Engine               *string `json:"engine"`
	Product              *string `json:"product"`
	Service              *string `json:"service"`
	NISEngine            *string `json:"nisEngine"`
	AntivirusSignature   *string `json:"antivirusSignature"`
	AntispywareSignature *string `json:"antispywareSignature"`
	NISSignature         *string `json:"nisSignature"`
	XProtectDefinitions  *string `json:"xprotectDefinitions"`
	XProtectRemediator   *string `json:"xprotectRemediator"`
}

// AntivirusSignatures is when each signature set was last updated (ISO-8601
// UTC) and its age in days (0..36500).
type AntivirusSignatures struct {
	AntivirusLastUpdatedAt   *string `json:"antivirusLastUpdatedAt"`
	AntivirusAgeDays         *int    `json:"antivirusAgeDays"`
	AntispywareLastUpdatedAt *string `json:"antispywareLastUpdatedAt"`
	AntispywareAgeDays       *int    `json:"antispywareAgeDays"`
	NISLastUpdatedAt         *string `json:"nisLastUpdatedAt"`
	NISAgeDays               *int    `json:"nisAgeDays"`
	OutOfDate                *bool   `json:"outOfDate"`
}

// AntivirusScans is the antivirus's own last quick and full scans (ISO-8601
// UTC times, ages in days 0..36500).
type AntivirusScans struct {
	QuickStartedAt *string `json:"quickStartedAt"`
	QuickEndedAt   *string `json:"quickEndedAt"`
	QuickAgeDays   *int    `json:"quickAgeDays"`
	QuickOverdue   *bool   `json:"quickOverdue"`
	FullStartedAt  *string `json:"fullStartedAt"`
	FullEndedAt    *string `json:"fullEndedAt"`
	FullAgeDays    *int    `json:"fullAgeDays"`
	FullOverdue    *bool   `json:"fullOverdue"`
	FullRequired   *bool   `json:"fullRequired"`
}

// SecurityCenterProduct is one antivirus product Windows Security Center
// lists. State is on, off, snoozed, expired or unknown.
type SecurityCenterProduct struct {
	Name                string `json:"name"` // at most 128 runes
	State               string `json:"state"`
	DefinitionsUpToDate *bool  `json:"definitionsUpToDate"`
}

// AntivirusScan is the result of the last scheduled antivirus scan the agent
// ran, or on macOS the report that scans are unsupported. StartedAt and
// CompletedAt are nil (marshalled as null) when no scan ran. Detail is omitted
// when there is nothing to add.
type AntivirusScan struct {
	ScanType     string  `json:"scanType"`         // always "quick"
	Result       string  `json:"result"`           // clean, threats_found, failed, timeout or unsupported
	StartedAt    *string `json:"startedAt"`        // ISO-8601 UTC or null
	CompletedAt  *string `json:"completedAt"`      // ISO-8601 UTC or null
	ThreatsFound int     `json:"threatsFound"`     // >= 0
	Detail       string  `json:"detail,omitempty"` // at most 256 runes
}

// Analytics is the endpoint analytics block of a check-in. Boot, Performance
// and Crashes are always sent; Crashes must be an empty slice (marshalled as
// []), never nil, when there are none. At most 50 crashes are sent.
type Analytics struct {
	Boot        AnalyticsBoot        `json:"boot"`
	Performance AnalyticsPerformance `json:"performance"`
	Crashes     []AppCrash           `json:"crashes"`
	Warnings    []string             `json:"warnings,omitempty"`
}

// AnalyticsBoot carries boot timings. Every field is always sent; a nil one
// marshals as null when the OS did not report it.
type AnalyticsBoot struct {
	LastBootAt          *string  `json:"lastBootAt"`          // ISO-8601 UTC
	BootDurationSeconds *float64 `json:"bootDurationSeconds"` // seconds, fractional allowed
	UptimeSeconds       *int64   `json:"uptimeSeconds"`       // whole seconds
}

// AnalyticsPerformance is a performance sample taken at collection. Every
// field is always sent; a nil one marshals as null.
type AnalyticsPerformance struct {
	CPUPercent           *float64 `json:"cpuPercent"`           // 0..100
	MemoryUsedBytes      *int64   `json:"memoryUsedBytes"`      // bytes
	MemoryTotalBytes     *int64   `json:"memoryTotalBytes"`     // bytes
	SystemDiskFreeBytes  *int64   `json:"systemDiskFreeBytes"`  // bytes, OS/system volume
	SystemDiskTotalBytes *int64   `json:"systemDiskTotalBytes"` // bytes, OS/system volume
}

// AppCrash is one application crash or hang. All four fields are always
// sent; AppVersion is null when unknown.
type AppCrash struct {
	AppName    string  `json:"appName"`
	AppVersion *string `json:"appVersion"`
	OccurredAt string  `json:"occurredAt"` // ISO-8601 UTC
	Kind       string  `json:"kind"`       // crash or hang
}

// AgentRelease is the agent build a device is being moved to: the agent
// downloads URL, refuses the bytes whose SHA-256 is not SHA256, and swaps
// itself for them.
type AgentRelease struct {
	Version string `json:"version"` // major.minor.patch
	URL     string `json:"url"`     // always https
	SHA256  string `json:"sha256"`  // lower-case hex
}

// CheckInResponse is the body of a successful check-in.
//
// The key set is exactly the two required keys -- how long the agent waits
// before the next check-in, and whether a command poll would find work -- plus
// AgentRelease when, and only when, a newer build is published for this
// device's platform. It is a pointer so "no update" is told from an update to
// an empty build. AnalyticsEnabled is present only as false, when an admin has
// turned the device's analytics collection off; it is absent (nil) when
// collection is on. No policy information is carried here -- a device's
// policies come from GET /api/v1/devices/{deviceId}/policies.
// HeartbeatIntervalSeconds is present only when an admin has turned the
// device's heartbeat on; it is absent (nil) when the heartbeat is off.
type CheckInResponse struct {
	CheckInIntervalSeconds   int           `json:"checkInIntervalSeconds"`
	PendingCommandCount      int           `json:"pendingCommandCount"`
	AgentRelease             *AgentRelease `json:"agentRelease,omitempty"`
	AnalyticsEnabled         *bool         `json:"analyticsEnabled,omitempty"`
	HeartbeatIntervalSeconds *int          `json:"heartbeatIntervalSeconds,omitempty"`
}

// HeartbeatRequest is the body of POST /api/v1/devices/{deviceId}/heartbeat:
// one point-in-time performance sample. Warnings is omitted when no probe failed.
// Network is omitted when no active physical adapter was sampled.
type HeartbeatRequest struct {
	CollectedAt string                    `json:"collectedAt"`
	Performance AnalyticsPerformance      `json:"performance"`
	Network     []HeartbeatNetworkAdapter `json:"network,omitempty"`
	Warnings    []string                  `json:"warnings,omitempty"`
}

// HeartbeatNetworkAdapter is one active physical network adapter's load,
// measured over about one second at collection. Every field is always sent; a
// nil one marshals as null. Rates are per second over the sample window; the
// error and discard counts are the OS's cumulative counters.
type HeartbeatNetworkAdapter struct {
	Name                     string   `json:"name"`
	LinkSpeedBitsPerSecond   *int64   `json:"linkSpeedBitsPerSecond"`
	ReceiveBitsPerSecond     *int64   `json:"receiveBitsPerSecond"`
	SendBitsPerSecond        *int64   `json:"sendBitsPerSecond"`
	UtilizationPercent       *float64 `json:"utilizationPercent"` // 0..100, busier direction over link speed
	PacketsReceivedPerSecond *float64 `json:"packetsReceivedPerSecond"`
	PacketsSentPerSecond     *float64 `json:"packetsSentPerSecond"`
	ReceiveErrors            *int64   `json:"receiveErrors"`
	SendErrors               *int64   `json:"sendErrors"`
	ReceiveDiscards          *int64   `json:"receiveDiscards"`
	SendDiscards             *int64   `json:"sendDiscards"`
}

// HeartbeatResponse answers a heartbeat with the device's heartbeat frequency
// in seconds, or 0 when its heartbeat is off.
type HeartbeatResponse struct {
	HeartbeatIntervalSeconds int `json:"heartbeatIntervalSeconds"`
}

// Command is one command leased to the device. Payload is left as raw JSON:
// its shape depends on Type, so only the handler for that verb decodes it.
type Command struct {
	CommandID string          `json:"commandId"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	IssuedAt  int64           `json:"issuedAt"`  // epoch milliseconds
	ExpiresAt int64           `json:"expiresAt"` // epoch milliseconds
}

// CommandLeaseResponse is the body of GET /api/v1/devices/{deviceId}/commands.
// The lease expiry is server-side state and is not on the wire.
type CommandLeaseResponse struct {
	Commands []Command `json:"commands"`
}

// CommandResultRequest is the body of
// POST /api/v1/devices/{deviceId}/commands/{commandId}/result. The command is
// named by the path, so it is not repeated in the body.
type CommandResultRequest struct {
	Status     string `json:"status"` // "succeeded" or "failed"
	ExitCode   int    `json:"exitCode"`
	Output     string `json:"output"`     // backend keeps the first 8192 bytes
	FinishedAt int64  `json:"finishedAt"` // epoch seconds
}

// Policy is one policy that contributed to a bundle.
type Policy struct {
	PolicyID string         `json:"policyId"`
	Version  int            `json:"version"`
	Settings map[string]any `json:"settings"`
}

// ConflictLoser is one policy that lost a contested setting.
type ConflictLoser struct {
	PolicyID string `json:"policyId"`
	Value    any    `json:"value"`
}

// Conflict is one setting more than one policy tried to set. Losers always
// holds at least one entry, and WinningPolicyID also appears in the bundle's
// Policies.
type Conflict struct {
	Key             string          `json:"key"`
	WinningPolicyID string          `json:"winningPolicyId"`
	Value           any             `json:"value"`
	Losers          []ConflictLoser `json:"losers"`
}

// PolicyBundleResponse is the body of GET /api/v1/devices/{deviceId}/policies.
//
// Conflicts is deliberately not omitempty: an uncontested bundle emits
// "conflicts": [] so no consumer has to tell absent from empty.
type PolicyBundleResponse struct {
	DeviceID          string         `json:"deviceId"`
	GeneratedAt       string         `json:"generatedAt"` // ISO-8601 UTC
	Policies          []Policy       `json:"policies"`
	EffectiveSettings map[string]any `json:"effectiveSettings"`
	Conflicts         []Conflict     `json:"conflicts"`
}
