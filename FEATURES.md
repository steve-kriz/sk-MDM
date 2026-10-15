# SK-MDM features

What SK-MDM does today, grouped by area. Each entry names the main code so a
reader can go straight to it. For build, test and deployment instructions see
the [README](README.md).

- [Installers and enrollment](#installers-and-enrollment)
- [Agent](#agent)
- [Data collected](#data-collected)
- [Policies](#policies)
- [Commands and applications](#commands-and-applications)
- [Admin console](#admin-console)
- [Security and platform](#security-and-platform)
- [Known limits](#known-limits)

## Installers and enrollment

| Feature | What it does | Where |
| --- | --- | --- |
| Windows installer | MSI for x64 and ARM64. The wizard asks for the collection URL (https only) and the device type: **OfficeHQ device** or **BYOC (personal device)**. The finish page opens sign-in; a Start menu shortcut, "Sign in to OfficeHQ MDM", does it later. Silent install takes `COLLECTIONURL` and `OWNERSHIP`. | `installers/windows/` |
| macOS installer | Signed pkg for Intel and Apple silicon. Asks for the URL and device type when someone is at the console, then opens sign-in. Ships a sign-in `.command` file and `uninstall.sh`. | `installers/macos/` |
| Sign-in to enroll | The agent opens a browser at the MDM site, the user signs in with Entra (PKCE), and the agent exchanges that sign-in for a single-use enrollment token. `mdmagent login` does the same with a device code from an elevated console. | `backend/src/routes/agentSignIn.ts`, `agent/internal/signin/`, `agent/cmd/mdmagent/login.go` |
| Enrollment | Checks the token (revoked, expired, uses left), records ownership and who enrolled the device, and recognises a re-enrolling machine by hardware UUID (an admin disable survives re-enrollment). The device joins every group that auto-assigns its ownership. | `backend/src/routes/enroll.ts` |
| Enrollment tokens | Admins create tokens with a label, maximum uses and expiry. The token is shown once; tokens can be listed and revoked, with the devices each one enrolled. | `backend/src/admin/enrollmentTokens.ts` |
| Download page | The public page explains what the agent collects, what it never collects, how OfficeHQ devices and BYOD differ, and what the agent may change, with console screenshots. Downloads redirect to presigned S3 links; published versions are shown. | `backend/src/ui/public/landing.html`, `backend/src/routes/downloads.ts` |

## Agent

| Feature | What it does | Where |
| --- | --- | --- |
| Check-in | Reports every 15 minutes by default (the server can change it), with up to 10% jitter; cycles never overlap. | `agent/internal/scheduler/` |
| Offline resend | Failed check-ins are saved to disk (up to 50, oldest dropped) and re-sent oldest first. Command results are stored until delivered. | `agent/internal/scheduler/spool.go`, `agent/internal/executor/store.go` |
| Self-update | The server advertises a build; the agent checks its SHA-256 and that it is newer, swaps the binary and restarts. A build that fails to start is rolled back. | `agent/internal/update/`, `backend/src/admin/agentRelease.ts` |
| Runs as a service | Windows service with automatic restart on failure; macOS LaunchDaemon. | `agent/internal/service/` |
| Signed requests | Every request is signed (HMAC with device id, timestamp and nonce), sent over https, and gzipped when the server supports it. | `agent/internal/client/` |
| Heartbeat | Optional per-device performance samples on their own schedule, turned on by an admin. | `agent/internal/heartbeat/` |
| Error reporting | Agent warnings and errors are de-duplicated and sent with the next check-in, shown on the device page. | `agent/internal/agenterrors/` |
| Action reporting | Changes the agent makes (firewall turned on, antivirus turned on, blocked domains updated, update rolled back) appear in the device History. | `agent/internal/agentactions/` |
| Signed-in user | Reports the signed-in OS user after each check-in, which builds a login history. | `backend/src/routes/userSession.ts` |

## Data collected

| Data | Details | Where |
| --- | --- | --- |
| Hardware and OS | Make, model, serial number, CPU, cores, RAM, disks; OS edition, version, build, architecture, install date, last boot, locale. Windows also: firmware/BIOS, Secure Boot, TPM, physical disks, Entra/domain join. | `agent/internal/inventory/` |
| Network adapters | MAC and IP addresses, DHCP, DNS and gateways. | `agent/internal/inventory/` |
| Time zone | The device's IANA zone; the console shows that device's times in it. | `agent/internal/inventory/timezone.go` |
| Installed software | Names and versions; installs, removals and updates are kept in History for 30 days. | `backend/src/softwareChanges.ts` |
| Security posture | Disk encryption (BitLocker/FileVault), firewall, antivirus (including third-party on Windows), pending OS updates and restart-required, local admins. | `agent/internal/posture/` |
| Antivirus | Microsoft Defender status, detections (XProtect Remediator on macOS), last scheduled scan, and a 14-item Defender hardening report. | `agent/internal/antivirus/` |
| Endpoint analytics | Boot time and duration, uptime, CPU/memory/disk sample, app crashes and hangs. Can be turned off per device. | `agent/internal/analytics/`, `backend/src/admin/analytics.ts` |
| Heartbeat | CPU, memory and disk, plus for each active physical network adapter: link speed, traffic in and out, utilisation %, packets per second, errors and discards. Amounts only, never destinations or content. Stored in CloudWatch Logs. | `agent/internal/analytics/network.go`, `backend/src/routes/heartbeat.ts` |
| Location | Approximate, from the internet connection (CloudFront geo headers). Only when a policy turns on `locationTracking`, at most once a day; the last 30 are kept. | `backend/src/location/capture.ts` |

Never collected: browsing history, websites visited, file contents, emails or
messages, keystrokes, screenshots, camera or microphone.

## Policies

Policies are assigned to **groups** (not to single devices). When two policies
set the same key, the one with the smallest `policyId` wins and the conflict is
reported. Every edit creates a new version. Code: `backend/src/admin/policies.ts`,
`backend/src/policies/merge.ts`.

| Setting | Meaning | Agent behaviour |
| --- | --- | --- |
| `firewallEnabled` | Firewall must be on | **Enforced**: turned on (Windows, macOS); never turned off |
| `antivirusEnabled` | Antivirus must be on | **Enforced** on Windows: Defender real-time protection turned on when no antivirus is active |
| `defenderRealTimeProtection`, `defenderCloudProtection`, `defenderNetworkProtection`, `defenderReputationProtection`, `defenderDailySignatureUpdate`, `defenderRansomwareProtection` (audit/block) | Defender hardening | **Enforced** on Windows |
| `antivirusScanFrequency` | off / daily / weekly / monthly | **Enforced** on Windows: scheduled quick scans |
| `firewallBlockedDomains`, `firewallAllowedDomains` | Up to 500 hostnames each | **Enforced**: blocked through a managed block in the hosts file; allowed entries are exceptions |
| `diskEncryptionRequired` | Disk must be encrypted | Evaluated only |
| `osUpdateMaxAgeDays` (1–180) | Days since the last OS update check | Evaluated only |
| `localAdminAllowlist` | Permitted local admin accounts | Evaluated only |
| `screenLockTimeoutSeconds` (60–3600) | Screen lock timeout | Stored only (not yet enforced or evaluated) |
| `locationTracking` | Allow location capture | Server-side switch |

Compliance: the agent reports violations (`firewall_disabled`,
`disk_encryption_missing`, `antivirus_disabled`, `os_update_overdue`,
`unauthorized_local_admin:<name>`, `defender_protection_failed:…`) and the
backend sets the device's compliance state. `GET /policies/{id}/compliance`
lists violating devices.

## Commands and applications

| Feature | What it does | Where |
| --- | --- | --- |
| Command types | `run_script` (PowerShell/cmd on Windows, bash/zsh on macOS), `restart` (one-minute warning), `lock`, `install_package` / `uninstall_package` (winget, Windows), `collect_logs` (zips logs on the device), `install_application`. Timeouts default to 5 minutes, maximum 1 hour. | `agent/internal/executor/` |
| Command library | Saved scripts, with optional AI generation (Amazon Bedrock). Queue to a device or a whole group (wrong-platform devices are skipped). Library commands run in order per device, never expire, and can be reordered or cancelled. | `backend/src/admin/scripts.ts` |
| Ad-hoc commands | Queue any command type for a device or group; `restart` and `run_script` need confirmation; expire after 24 hours. | `backend/src/admin/commandDispatch.ts` |
| Stop on failure | Fleet setting: continue with the queue, or stop the remaining commands when one fails. | `backend/src/admin/commandSettings.ts` |
| Applications safe list | Approved msi, exe and pkg installers, uploaded (up to 500 MB, hashed in the browser) or from an https URL (hashed by the server, with Retry). Added and edited in a popup; changing the URL re-hashes it. | `backend/src/admin/applications.ts` |
| Install an application | The agent downloads it, checks the SHA-256, then runs the installer. | `agent/internal/executor/application.go` |
| Self-service Applications page | Users sign in with their work account and download approved applications. | `backend/src/routes/applications.ts`, `backend/src/ui/public/applications.js` |

## Admin console

Served at `/admin`, sign-in with Entra. Screens:

- **Devices**: list with ownership filter (hostname, ownership, platform, OS, last seen, compliance).
- **Device detail**: profile (enrolled by, signed-in user, agent version, time zone) with Refresh and Delete; ownership; groups; policies; disable/enable credential; device details; software and application install; posture; run a command and the queue; History (30 days); antivirus status, Defender policy, findings and scans; location; login history; errors; analytics, including heartbeat on/off, frequency and history.
- **Analytics**: slowest boots, most crashes, top crashing apps, resource pressure.
- **Software**: search the fleet's installed software and find the devices with a title.
- **Applications**: the safe list.
- **Groups**: create, rename, delete, add/remove members, **auto-assign** new OfficeHQ or BYOD devices, queue a script on all members.
- **Enrollment tokens**, **Policies** (create, edit, delete, assign), **Commands** (the library), **Audit** (by date range), **Settings** (collection URL, stop on failure).

## Security and platform

| Feature | Details | Where |
| --- | --- | --- |
| Admin sign-in | Entra OIDC with PKCE; admins qualify through the admin group or the `MDM.Administrator` app role. | `backend/src/auth/entra.ts` |
| Device authentication | HMAC signatures, clock-skew check, single-use nonces, revocation. Device secrets are encrypted with a pepper held in Secrets Manager; on Windows the agent protects its secret with DPAPI. | `backend/src/http/deviceAuth.ts` |
| Audit log | Every admin change is recorded. | `backend/src/audit.ts` |
| Security headers | Strict content security policy, no framing, nosniff, no referrer. | `backend/src/ui/index.ts` |
| AWS | Lambda behind a Function URL, DynamoDB (single table, point-in-time recovery, TTL), private S3 installer bucket, CloudWatch heartbeat log, optional CloudFront with custom domain, application hasher Lambda, optional Bedrock. | `backend/src/infra/mdm-stack.ts` |

## Known limits

- **OS updates are checked and reported, not installed.** Installing them is designed but not yet built.
- **Screen-lock timeout is stored but not enforced.** The `lock` command is best-effort when run from the service.
- **BYOD restrictions are policy, not code.** The download page says OfficeHQ does not track location, lock the screen or install software on BYOD. Code only gates location (through the `locationTracking` policy); commands and application installs are not blocked for BYOC devices.
- Defender enforcement, hardening and scans are Windows only; macOS XProtect cannot be switched on.
- Firmware, TPM, join state, physical disks and `install_package` are Windows only.
- Domain blocking uses the hosts file: exact hostnames, no wildcards.
- `collect_logs` leaves the archive on the device; nothing is uploaded.
- Auto-assign only adds devices when they enroll or change ownership; nothing is removed automatically.
- Agent actions and errors not yet sent are lost if the agent stops; heartbeats are not resent.
- Policy compliance has no console screen yet (API only).
- Tokens minted by an admin record no enrolling user.
