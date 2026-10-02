// Package contract holds the frozen agent-to-backend wire contract: the
// message types the agent exchanges with the Lambda and the request signing
// scheme that authenticates them.
//
// Every json tag here matches a field name in backend/src/contract/types.ts,
// in contract/openapi.yaml and in the golden messages under
// contract/testdata/messages/. Renaming a field means changing all four.
//
// Two authentication schemes exist on this API:
//   - POST /api/v1/enroll is authenticated only by the X-MDM-Enrollment-Token
//     header over TLS; at enroll time there is no device id and no device
//     secret, so the HMAC scheme cannot be applied there.
//   - Every /api/v1/devices/... operation is authenticated by the device HMAC
//     scheme in signing.go.
//
// Timestamps documented as "ISO-8601 UTC" are strings such as
// "2026-10-02T07:15:00Z". The signing scheme uses epoch seconds instead.
package contract

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
}

// InventoryOS is the os block of Inventory.
type InventoryOS struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Build        string `json:"build"`
	Architecture string `json:"architecture"`
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
	Warnings []string          `json:"warnings,omitempty"`
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
	Name               string `json:"name"`
	Enabled            bool   `json:"enabled"`
	DefinitionsAgeDays int    `json:"definitionsAgeDays"`
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

// CheckInRequest is the body of POST /api/v1/devices/{deviceId}/checkin.
//
// PolicyCompliance is omitempty: a check-in that reports nothing marshals
// without a "policyCompliance" key.
type CheckInRequest struct {
	CollectedAt      string                  `json:"collectedAt"` // ISO-8601 UTC
	Inventory        Inventory               `json:"inventory"`
	Posture          Posture                 `json:"posture"`
	PolicyCompliance []PolicyComplianceEntry `json:"policyCompliance,omitempty"`
}

// CheckInResponse is the body of a successful check-in.
type CheckInResponse struct {
	DeviceID            string `json:"deviceId"`
	ReceivedAt          string `json:"receivedAt"` // ISO-8601 UTC
	NextCheckInSeconds  int    `json:"nextCheckInSeconds"`
	PendingCommandCount int    `json:"pendingCommandCount"`
}

// Command is one command leased to the device.
type Command struct {
	CommandID      string         `json:"commandId"`
	Type           string         `json:"type"`
	Parameters     map[string]any `json:"parameters"`
	IssuedAt       string         `json:"issuedAt"`       // ISO-8601 UTC
	LeaseExpiresAt string         `json:"leaseExpiresAt"` // ISO-8601 UTC
}

// CommandLeaseResponse is the body of GET /api/v1/devices/{deviceId}/commands.
type CommandLeaseResponse struct {
	DeviceID string    `json:"deviceId"`
	LeasedAt string    `json:"leasedAt"` // ISO-8601 UTC
	Commands []Command `json:"commands"`
}

// CommandResultRequest is the body of
// POST /api/v1/devices/{deviceId}/commands/{commandId}/result.
type CommandResultRequest struct {
	CommandID   string `json:"commandId"`
	Status      string `json:"status"`      // "succeeded" or "failed"
	CompletedAt string `json:"completedAt"` // ISO-8601 UTC
	ExitCode    int    `json:"exitCode"`
	Output      string `json:"output"`
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
