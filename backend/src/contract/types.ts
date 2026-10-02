/**
 * The frozen agent-to-backend wire contract.
 *
 * Every field name here is also pinned by `contract/openapi.yaml`, by the Go
 * structs in `agent/internal/contract/types.go` and by the golden message files
 * in `contract/testdata/messages/`. Renaming a field means changing all four.
 *
 * Two authentication schemes exist on this API:
 *   - `POST /api/v1/enroll` is authenticated only by the `X-MDM-Enrollment-Token`
 *     header carried over TLS. At enroll time the agent has no device id and no
 *     device secret, so the HMAC scheme cannot be applied there.
 *   - Every `/api/v1/devices/...` operation is authenticated by the device HMAC
 *     scheme in `./signing.js` (`X-MDM-Device-Id`, `X-MDM-Timestamp`,
 *     `X-MDM-Nonce`, `X-MDM-Signature`).
 *
 * Timestamps written as "ISO-8601 UTC" are strings such as
 * `2026-10-02T07:15:00Z`. Timestamps used by the signing scheme are integer
 * epoch seconds instead.
 */

/** Body of `POST /api/v1/enroll`. Authenticated by `X-MDM-Enrollment-Token`. */
export interface EnrollRequest {
  /** Machine host name as reported by the OS. */
  hostname: string;
  /** Agent platform: `windows` or `macos`. */
  platform: 'windows' | 'macos';
  /** OS marketing version, e.g. `10.0.22631` or `14.5`. */
  osVersion: string;
  /** Agent build version, e.g. `0.0.0-dev`. */
  agentVersion: string;
  /** Hardware serial number, used to re-attach a re-enrolling device. */
  serialNumber: string;
  /** When the agent sent the request, ISO-8601 UTC. */
  enrolledAt: string;
}

/** Response to `POST /api/v1/enroll`. Carries the device's HMAC secret exactly once. */
export interface EnrollResponse {
  /** Server-assigned device id, used in every later `/api/v1/devices/...` path. */
  deviceId: string;
  /** Lower-case hex HMAC key for `signRequest`. Returned only at enroll time. */
  deviceSecret: string;
  /** How long the agent should wait between check-ins. */
  checkInIntervalSeconds: number;
  /** Server clock at enroll time, ISO-8601 UTC, so the agent can detect skew. */
  serverTime: string;
}

/** Hardware, OS and software facts collected by the agent. */
export interface Inventory {
  hardware: {
    manufacturer: string;
    model: string;
    serialNumber: string;
    cpu: string;
    ramBytes: number;
    diskBytes: number;
  };
  os: {
    name: string;
    version: string;
    build: string;
    architecture: string;
  };
  software: Array<{
    name: string;
    version: string;
    publisher: string;
    /** ISO-8601 UTC install time. */
    installedAt: string;
  }>;
  /** Collector problems that did not stop the rest of the collection. Absent when there are none. */
  warnings?: string[];
}

/** Security posture facts collected by the agent. */
export interface Posture {
  diskEncryption: {
    enabled: boolean;
    method: 'bitlocker' | 'filevault';
  };
  firewall: {
    enabled: boolean;
  };
  antivirus: {
    name: string;
    enabled: boolean;
    definitionsAgeDays: number;
  };
  osUpdate: {
    /** ISO-8601 UTC time of the last update check. */
    lastCheckedAt: string;
    pendingCount: number;
    rebootRequired: boolean;
  };
  /** Local administrator account names. */
  localAdmins: string[];
  /** Collector problems that did not stop the rest of the collection. Absent when there are none. */
  warnings?: string[];
}

/** Body of `POST /api/v1/devices/{deviceId}/checkin`. */
export interface CheckInRequest {
  /** When the agent collected the payload, ISO-8601 UTC. */
  collectedAt: string;
  inventory: Inventory;
  posture: Posture;
  /**
   * Compliance the agent evaluated locally against the policies it last pulled.
   * Absent entirely when the agent has nothing to report; `violations` is an
   * empty array (never absent) on a compliant entry.
   */
  policyCompliance?: Array<{
    policyId: string;
    version: number;
    compliant: boolean;
    /** Violation keys such as `firewall_disabled`. Empty when compliant. */
    violations: string[];
  }>;
}

/** Response to `POST /api/v1/devices/{deviceId}/checkin`. */
export interface CheckInResponse {
  deviceId: string;
  /** Server receive time, ISO-8601 UTC. */
  receivedAt: string;
  /** How long the agent should wait before the next check-in. */
  nextCheckInSeconds: number;
  /** Commands waiting to be leased, so the agent can skip an empty poll. */
  pendingCommandCount: number;
}

/** Response to `GET /api/v1/devices/{deviceId}/commands`: the commands now leased to this device. */
export interface CommandLeaseResponse {
  deviceId: string;
  /** When the lease was granted, ISO-8601 UTC. */
  leasedAt: string;
  commands: Array<{
    commandId: string;
    /** Command verb, e.g. `collect_inventory`, `restart`, `run_script`. */
    type: string;
    /** Command-specific arguments; opaque to the transport. */
    parameters: Record<string, unknown>;
    /** When the backend queued the command, ISO-8601 UTC. */
    issuedAt: string;
    /** After this time the lease may be handed to another poll, ISO-8601 UTC. */
    leaseExpiresAt: string;
  }>;
}

/** Body of `POST /api/v1/devices/{deviceId}/commands/{commandId}/result`. */
export interface CommandResultRequest {
  commandId: string;
  /** Terminal outcome of the command. */
  status: 'succeeded' | 'failed';
  /** When the agent finished the command, ISO-8601 UTC. */
  completedAt: string;
  /** Process exit code, or 0 for commands with no process. */
  exitCode: number;
  /** Combined stdout/stderr, truncated by the agent. Carries the failure text when `status` is `failed`. */
  output: string;
}

/** Response to `GET /api/v1/devices/{deviceId}/policies`: the merged policy bundle. */
export interface PolicyBundleResponse {
  deviceId: string;
  /** When the bundle was merged, ISO-8601 UTC. */
  generatedAt: string;
  policies: Array<{
    policyId: string;
    version: number;
    settings: Record<string, unknown>;
  }>;
  /** The merge result the agent must apply: setting key to winning value. */
  effectiveSettings: Record<string, unknown>;
  /**
   * Settings more than one policy tried to set. Always present: an uncontested
   * bundle carries `[]` rather than omitting the field.
   */
  conflicts: Array<{
    /** The contested setting key, as it appears in `effectiveSettings`. */
    key: string;
    /** The policy that won; it also appears in `policies`. */
    winningPolicyId: string;
    /** The winning value, identical to `effectiveSettings[key]`. */
    value: unknown;
    /** The policies that lost. Always at least one entry. */
    losers: Array<{
      policyId: string;
      value: unknown;
    }>;
  }>;
}
