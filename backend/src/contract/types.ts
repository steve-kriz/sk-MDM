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
 * epoch seconds instead, as is a command result's `finishedAt`; a command's
 * own `issuedAt` and `expiresAt` are integer epoch milliseconds. Each field's
 * unit is stated on the field.
 */

/**
 * Who owns an enrolled machine: an OfficeHQ device or BYOC (a personal
 * device). Recorded and displayed only; nothing behaves differently for it.
 */
export type Ownership = 'officehq' | 'byoc';

/**
 * Body of `POST /api/v1/enroll`. Authenticated by the signed-in user's Entra
 * token in `Authorization: Bearer <token>` or, for legacy installs, by
 * `X-MDM-Enrollment-Token`.
 */
export interface EnrollRequest {
  /** Machine host name as reported by the OS. */
  hostname: string;
  /** Agent platform: `windows` or `darwin`. */
  platform: 'windows' | 'darwin';
  /** OS marketing version, e.g. `10.0.22631` or `14.5`. */
  osVersion: string;
  /** Stable hardware UUID, used to re-attach a re-enrolling device. */
  hardwareUuid: string;
  /** Agent build version, e.g. `0.0.0-dev`. */
  agentVersion: string;
  /** Optional; absent reads as `officehq`. Any other value is a 400 naming `ownership`. */
  ownership?: Ownership;
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
    /** Optional. Win32_ComputerSystem.SystemFamily. */
    systemFamily?: string;
    /** Optional. Win32_ComputerSystem.SystemSKUNumber. */
    systemSku?: string;
    /** Optional. Physical cores summed over all processors. */
    cpuCores?: number;
    /** Optional. Logical processors summed over all processors. */
    cpuLogicalProcessors?: number;
  };
  os: {
    name: string;
    version: string;
    build: string;
    architecture: string;
    /** Optional. Windows EditionID, e.g. "Enterprise". */
    edition?: string;
    /** Optional. Windows feature-update label, e.g. "23H2". */
    displayVersion?: string;
    /** Optional. Windows update build revision (integer >= 0), e.g. 4317. */
    ubr?: number;
    /** Optional. ISO-8601 UTC install time of the OS. */
    installDate?: string;
    /** Optional. ISO-8601 UTC time of the last boot. */
    lastBootAt?: string;
    /** Optional. System locale name, e.g. "en-AU". */
    locale?: string;
  };
  software: Array<{
    name: string;
    version: string;
    publisher: string;
    /** ISO-8601 UTC install time. */
    installedAt: string;
  }>;
  /** Optional. Firmware and platform security. Absent when not collected. */
  firmware?: InventoryFirmware;
  /** Optional. Fixed logical volumes (at most 32). */
  disks?: InventoryDisk[];
  /** Optional. Physical drives (at most 16). */
  physicalDisks?: InventoryPhysicalDisk[];
  /** Optional. IP-enabled network adapters (at most 16). */
  network?: InventoryNetworkAdapter[];
  /** Optional. Directory join state. Absent when not collected. */
  join?: InventoryJoin;
  /** Collector problems that did not stop the rest of the collection. Absent when there are none. */
  warnings?: string[];
}

/** The optional firmware block of Inventory. */
export interface InventoryFirmware {
  type?: 'uefi' | 'bios';
  biosVersion?: string;
  /** ISO-8601 UTC. */
  biosReleaseDate?: string;
  /** Absent on BIOS firmware or when it could not be read. */
  secureBootEnabled?: boolean;
  tpmPresent?: boolean;
  tpmReady?: boolean;
  /** TPM specification version, e.g. "2.0". */
  tpmVersion?: string;
}

/** One fixed logical volume in Inventory.disks. */
export interface InventoryDisk {
  deviceId?: string;
  fileSystem?: string;
  sizeBytes?: number;
  freeBytes?: number;
}

/** One physical drive in Inventory.physicalDisks. */
export interface InventoryPhysicalDisk {
  model?: string;
  mediaType?: 'ssd' | 'hdd' | 'scm' | 'unspecified';
  sizeBytes?: number;
}

/** One IP-enabled adapter in Inventory.network. Address lists hold at most 16 entries. */
export interface InventoryNetworkAdapter {
  description?: string;
  macAddress?: string;
  ipv4?: string[];
  ipv6?: string[];
  dhcpEnabled?: boolean;
  dnsServers?: string[];
  gateways?: string[];
}

/** The optional directory-join block of Inventory. */
export interface InventoryJoin {
  azureAdJoined?: boolean;
  domainJoined?: boolean;
  /** Set only when the device is joined to an AD domain. */
  domain?: string;
  tenantName?: string;
  tenantId?: string;
  entraDeviceId?: string;
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
    /**
     * True when antivirus is active. Windows: Microsoft Defender reports itself
     * enabled with real-time protection on (Microsoft Defender counts as
     * enabled only when real-time protection is on), or any antivirus product
     * registered with Windows Security Center is active. macOS: the XProtect
     * bundle is present.
     */
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
   * The agent build posting this check-in. Absent from an older agent, which
   * is why the backend falls back to the version stored on the device profile.
   */
  agentVersion?: string;
  /**
   * The device's IANA time zone name (machine-wide OS zone). Absent when the
   * agent could not work it out; an unusable value is ignored by the backend.
   */
  timeZone?: string;
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
  /**
   * Threat detections from Microsoft Defender (Windows) or XProtect (macOS),
   * at most 20. Absent entirely when there are none. Never affects compliance.
   */
  antivirusFindings?: AntivirusFinding[];
  /**
   * Endpoint analytics: boot times, a performance sample and application
   * crashes. Absent from an agent that does not collect it. Never affects
   * compliance, and a malformed block never fails the check-in.
   */
  analytics?: Analytics;
  /**
   * The last scheduled antivirus scan result. Absent when the agent has
   * nothing to report. Never affects compliance, and a malformed value never
   * fails the check-in.
   */
  antivirusScan?: AntivirusScan;
  /**
   * The device antivirus's full status. Absent when the agent's status probe
   * failed or the platform has none. Never affects compliance, and a
   * malformed value never fails the check-in.
   */
  antivirusStatus?: AntivirusStatus;
  /**
   * What the agent's Defender protections hardener did to each required
   * protection in this cycle. Absent on macOS or before the hardener has run.
   * Stored for the admin only; never read to compute compliance, and a
   * malformed value never fails the check-in.
   */
  defenderHardening?: DefenderHardening;
  /**
   * The warn and error records the agent logged since its last check-in body,
   * repeats collapsed into one entry with a count. At most 50. Absent when
   * there are none. A malformed value or entry is ignored, never refused, and
   * never affects compliance.
   */
  agentErrors?: AgentError[];
  /**
   * The actions the agent performed on the device since its last check-in
   * body. At most 20. Absent when there are none. A malformed value or entry
   * is ignored, never refused.
   */
  agentActions?: AgentAction[];
}

/**
 * One action the agent performed on the device. The agent sends no summary:
 * the server builds it from `type` and `details`.
 */
export interface AgentAction {
  type:
    | 'enforce.firewall_enabled'
    | 'enforce.antivirus_enabled'
    | 'enforce.domains_updated'
    | 'agent.update_rolled_back';
  /** ISO-8601 UTC, to the second. */
  occurredAt: string;
  /** At most 8 entries; keys at most 64 characters, values at most 256. */
  details: Record<string, string>;
}

/**
 * One distinct warn or error record the agent logged: records with the same
 * level, component and message collapsed into `count`, with the first and
 * latest timestamps and the latest record's fields.
 */
export interface AgentError {
  level: 'warn' | 'error';
  /** At most 64 characters. */
  component: string;
  /** At most 256 characters. */
  message: string;
  /** At most 8 entries; keys at most 64 characters, values at most 256. */
  fields: Record<string, string>;
  /** At least 1. */
  count: number;
  /** The first record's timestamp, ISO-8601 UTC. */
  firstAt: string;
  /** The latest record's timestamp, ISO-8601 UTC. */
  lastAt: string;
}

/** One item a `DefenderHardening` block may report. */
export type DefenderHardeningItemName =
  | 'realTimeMonitoring'
  | 'behaviorMonitoring'
  | 'ioavProtection'
  | 'scriptScanning'
  | 'mapsReporting'
  | 'submitSamplesConsent'
  | 'networkProtection'
  | 'controlledFolderAccess'
  | 'puaProtection'
  | 'smartScreenWindows'
  | 'smartScreenEdge'
  | 'signatureUpdateInterval'
  | 'signatureScheduleDay'
  | 'signatureUpdate';

/** The state one Defender protection item is in. */
export type DefenderHardeningState = 'ok' | 'applied' | 'failed' | 'tamper_blocked' | 'not_applicable' | 'waiting';

/** One Defender protection item's outcome. */
export interface DefenderHardeningItem {
  item: DefenderHardeningItemName;
  state: DefenderHardeningState;
  /** At most 256 characters. */
  detail?: string;
}

/** The Defender protections hardener's last pass: only required items, in fixed order. */
export interface DefenderHardening {
  /** When the hardener evaluated, ISO-8601 UTC. */
  evaluatedAt: string;
  /** At most 14 entries. */
  items: DefenderHardeningItem[];
}

/**
 * The last scheduled antivirus scan the agent ran. On macOS, while a scan
 * frequency is set, `result` is `unsupported` with null times.
 */
export interface AntivirusScan {
  scanType: 'quick';
  result: 'clean' | 'threats_found' | 'failed' | 'timeout' | 'unsupported';
  /** ISO-8601 UTC, or `null` when no scan ran. */
  startedAt: string | null;
  /** ISO-8601 UTC, or `null` when no scan ran. */
  completedAt: string | null;
  /** Threats detected by the scan, an integer >= 0. */
  threatsFound: number;
  /** Why a scan failed, at most 256 characters. Absent when there is nothing to add. */
  detail?: string;
}

/**
 * The endpoint analytics block of a check-in. `boot`, `performance` and
 * `crashes` are always present; `crashes` is `[]` (never absent) when empty.
 */
export interface Analytics {
  boot: AnalyticsBoot;
  performance: AnalyticsPerformance;
  /** Crash/hang events since the previous successful check-in, at most 50. */
  crashes: AppCrash[];
  /** Collector problems. Absent when there are none. */
  warnings?: string[];
}

/** Boot timings. Every key is present; `null` when the OS did not report it. */
export interface AnalyticsBoot {
  /** When the device last booted, ISO-8601 UTC. */
  lastBootAt: string | null;
  /** How long the last boot took, in seconds (fractional allowed). */
  bootDurationSeconds: number | null;
  /** Seconds since the last boot, an integer. */
  uptimeSeconds: number | null;
}

/** A performance sample. Every key is present; `null` when the OS did not report it. */
export interface AnalyticsPerformance {
  /** CPU utilisation in percent, 0..100, sampled at collection. */
  cpuPercent: number | null;
  /** Memory in use, integer bytes. */
  memoryUsedBytes: number | null;
  /** Installed memory, integer bytes. */
  memoryTotalBytes: number | null;
  /** Free space on the OS/system volume, integer bytes. */
  systemDiskFreeBytes: number | null;
  /** Size of the OS/system volume, integer bytes. */
  systemDiskTotalBytes: number | null;
}

/** One application crash or hang. All four keys are present. */
export interface AppCrash {
  /** The application's name; never empty. */
  appName: string;
  /** The application's version, or `null` when unknown. */
  appVersion: string | null;
  /** When it happened, ISO-8601 UTC. */
  occurredAt: string;
  kind: 'crash' | 'hang';
}

/**
 * One threat detection reported on a check-in. The first six fields are
 * always present; the eight after them are optional and only a Windows
 * Defender detection carries them.
 */
export interface AntivirusFinding {
  /** Defender DetectionID, or the derived XProtect id. */
  findingId: string;
  threatName: string;
  severity: 'unknown' | 'low' | 'moderate' | 'high' | 'severe';
  /** ISO-8601 UTC. */
  detectedAt: string;
  resources: string[];
  remediated: boolean;
  /** The Defender threat category, e.g. `Trojan`. At most 64 characters. */
  category?: string;
  status?: AntivirusFindingStatus;
  action?: AntivirusFindingAction;
  /** Whether the threat is still active. Absent when the threat record is gone. */
  active?: boolean;
  /** When the threat status last changed, ISO-8601 UTC. */
  lastStatusChangeAt?: string;
  /** When the threat was remediated, ISO-8601 UTC. */
  remediatedAt?: string;
  /** The process involved, at most 260 characters. */
  processName?: string;
  /** The user the detection ran under, at most 256 characters. */
  user?: string;
}

/** A Defender threat status. */
export type AntivirusFindingStatus =
  | 'unknown'
  | 'detected'
  | 'cleaned'
  | 'quarantined'
  | 'removed'
  | 'allowed'
  | 'blocked'
  | 'quarantine_failed'
  | 'remove_failed'
  | 'allow_failed'
  | 'abandoned'
  | 'block_failed';

/** A Defender cleaning action. */
export type AntivirusFindingAction =
  | 'unknown'
  | 'clean'
  | 'quarantine'
  | 'remove'
  | 'allow'
  | 'user_defined'
  | 'no_action'
  | 'block';

/**
 * The device antivirus's full status. Every key is present; a value the
 * device did not report is `null`. When `defenderAvailable` is false every
 * Defender field is `null`.
 */
export interface AntivirusStatus {
  /** `Microsoft Defender` on Windows, `XProtect` on macOS. */
  product: string;
  defenderAvailable: boolean;
  /** Defender's AMRunningMode, e.g. `Normal` or `Passive Mode`. At most 64 characters. */
  runningMode: string | null;
  protection: AntivirusProtection;
  versions: AntivirusVersions;
  signatures: AntivirusSignatures;
  scans: AntivirusScans;
  /** Defender's ComputerState flags, an integer 0..65535. */
  computerState: number | null;
  rebootRequired: boolean | null;
  /** The products Windows Security Center lists, at most 10. */
  securityCenterProducts: SecurityCenterProduct[];
}

/** The Defender protection switches. */
export interface AntivirusProtection {
  amServiceEnabled: boolean | null;
  antispywareEnabled: boolean | null;
  antivirusEnabled: boolean | null;
  behaviorMonitorEnabled: boolean | null;
  ioavProtectionEnabled: boolean | null;
  onAccessProtectionEnabled: boolean | null;
  realTimeProtectionEnabled: boolean | null;
  nisEnabled: boolean | null;
  tamperProtected: boolean | null;
}

/** Engine, platform and signature versions, each at most 64 characters. */
export interface AntivirusVersions {
  engine: string | null;
  product: string | null;
  service: string | null;
  nisEngine: string | null;
  antivirusSignature: string | null;
  antispywareSignature: string | null;
  nisSignature: string | null;
  xprotectDefinitions: string | null;
  xprotectRemediator: string | null;
}

/** Signature update times (ISO-8601 UTC) and ages in days (0..36500). */
export interface AntivirusSignatures {
  antivirusLastUpdatedAt: string | null;
  antivirusAgeDays: number | null;
  antispywareLastUpdatedAt: string | null;
  antispywareAgeDays: number | null;
  nisLastUpdatedAt: string | null;
  nisAgeDays: number | null;
  outOfDate: boolean | null;
}

/** The antivirus's own last quick and full scans. */
export interface AntivirusScans {
  quickStartedAt: string | null;
  quickEndedAt: string | null;
  quickAgeDays: number | null;
  quickOverdue: boolean | null;
  fullStartedAt: string | null;
  fullEndedAt: string | null;
  fullAgeDays: number | null;
  fullOverdue: boolean | null;
  fullRequired: boolean | null;
}

/** One antivirus product Windows Security Center lists. */
export interface SecurityCenterProduct {
  /** At most 128 characters, never empty. */
  name: string;
  state: 'on' | 'off' | 'snoozed' | 'expired' | 'unknown';
  definitionsUpToDate: boolean | null;
}

/**
 * The agent build a device is being moved to.
 *
 * The agent downloads `url`, refuses the bytes whose SHA-256 is not `sha256`,
 * and swaps itself for them.
 */
export interface AgentRelease {
  /** The published version, `major.minor.patch`. */
  version: string;
  /** Where the build is downloaded from. Always `https`. */
  url: string;
  /** SHA-256 of the build, lower-case hex. */
  sha256: string;
}

/**
 * Response to `POST /api/v1/devices/{deviceId}/checkin`.
 *
 * The key set is exactly the two required keys, plus `agentRelease` when -- and
 * only when -- a newer build is published for the device's platform, and
 * `analyticsEnabled` when -- and only when -- an admin has turned the device's
 * analytics collection off. No policy information is carried here: a device's
 * policies come from `GET /api/v1/devices/{deviceId}/policies`.
 */
export interface CheckInResponse {
  /** How long the agent should wait before the next check-in. */
  checkInIntervalSeconds: number;
  /** Commands waiting to be leased, so the agent can skip an empty poll. */
  pendingCommandCount: number;
  /** The build to update to. Absent when the device is already on the published one. */
  agentRelease?: AgentRelease;
  /** Present only as `false`, when analytics collection is off; absent when it is on. */
  analyticsEnabled?: boolean;
  /** The heartbeat frequency in seconds; present only when the device's heartbeat is on. */
  heartbeatIntervalSeconds?: number;
}

/** Body of `POST /api/v1/devices/{deviceId}/heartbeat`: one point-in-time performance sample. */
export interface HeartbeatRequest {
  /** When the agent took the sample, ISO-8601 UTC. */
  collectedAt: string;
  performance: AnalyticsPerformance;
  /** Active physical network adapters, at most 8; absent when none was sampled. */
  network?: HeartbeatNetworkAdapter[];
  /** Probes that failed while sampling. */
  warnings?: string[];
}

/**
 * One network adapter's load over about one second. Every key is present;
 * `null` when the OS did not report it. Errors and discards are cumulative.
 */
export interface HeartbeatNetworkAdapter {
  name: string;
  /** Negotiated link speed; `null` when unknown (macOS Wi-Fi). */
  linkSpeedBitsPerSecond: number | null;
  receiveBitsPerSecond: number | null;
  sendBitsPerSecond: number | null;
  /** Saturation 0..100: the busier direction over the link speed. */
  utilizationPercent: number | null;
  packetsReceivedPerSecond: number | null;
  packetsSentPerSecond: number | null;
  receiveErrors: number | null;
  sendErrors: number | null;
  receiveDiscards: number | null;
  sendDiscards: number | null;
}

/** Response to `POST /api/v1/devices/{deviceId}/heartbeat`. */
export interface HeartbeatResponse {
  /** The heartbeat frequency in seconds, or `0` when the device's heartbeat is off. */
  heartbeatIntervalSeconds: number;
}

/**
 * One command handed to the agent by a lease.
 *
 * Both instants are integer epoch *milliseconds*: the queue stores them that
 * way and the lease route echoes them unchanged. The lease itself is server-side
 * state, so `leaseExpiresAt` is never on the wire.
 */
export interface Command {
  commandId: string;
  /** Command verb, e.g. `collect_inventory`, `restart`, `run_script`. */
  type: string;
  /** Command-specific arguments; opaque to the transport. */
  payload: Record<string, unknown>;
  /** When the backend queued the command, epoch milliseconds. */
  issuedAt: number;
  /** After this instant the command is never handed out again, epoch milliseconds. */
  expiresAt: number;
}

/** Response to `GET /api/v1/devices/{deviceId}/commands`: the commands now leased to this device. */
export interface CommandLeaseResponse {
  commands: Command[];
}

/** Body of `POST /api/v1/devices/{deviceId}/commands/{commandId}/result`. */
export interface CommandResultRequest {
  /** Terminal outcome of the command. */
  status: 'succeeded' | 'failed';
  /** Process exit code, or 0 for commands with no process. */
  exitCode: number;
  /** Combined stdout/stderr. The backend keeps the first 8192 bytes and drops the rest. */
  output: string;
  /** When the agent finished the command, epoch seconds. */
  finishedAt: number;
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
