# Command library, ordered queues and cmd/bash — design

Date: 2026-10-11
Status: approved in conversation, awaiting spec review

## Goal

Let an admin keep a library of saved commands (scripts) in the console, queue
them on a device or a whole group by picking from that list, and have each
machine run its queue **in the order assigned** at its next check-in. Commands
can be Windows `cmd` or PowerShell, or macOS `bash` or zsh. A fleet-wide
setting decides whether a failure stops the rest of a machine's queue or not.

## Non-goals

- Recurring/scheduled commands. A queued command runs once.
- Script signing, per-admin roles or approval workflows beyond today's typed
  confirmation.
- Uploading files or collected logs alongside a command.
- Changing the existing raw `run_script` dispatch screen (`#/dispatch/<id>`)
  or the non-script command types (`restart`, `lock`, packages, `collect_logs`).
- Linux.

## Decisions taken

| Question | Decision |
|---|---|
| Where are commands assigned? | A device's detail page **and** a group's page (fan-out to members). |
| Run order | The order assigned. Pending commands can be moved up/down or cancelled before the machine picks them up. |
| Failure handling | Fleet-wide setting on the Settings screen: **Continue** (default) or **Stop**. |
| Shells | Windows: `cmd`, `powershell`. macOS: `bash`, `zsh`. |
| Wrong platform | A command only shows for devices of its platform; a group fan-out skips non-matching members and reports how many. |
| Editing a saved command | Does not change anything already queued: the script text is copied into the queued command at assignment. |
| Expiry | Commands queued from the library do not expire; a machine that is offline for a week runs its queue when it returns. |
| Execution path | Reuse the existing `run_script` command type, lease, at-most-once store and result reporting. No new execution channel. |

## Background (what exists today)

- `run_script` (`backend/src/admin/commandDispatch.ts`, `agent/internal/executor`)
  runs `powershell` or `zsh` scripts as LocalSystem / root via a 0600 temp
  file, keeps the last 8 KB of output and reports `{status, exitCode, output}`.
- Commands are stored at `DEVICE#<id>` / `CMD#cmd-<16 hex>` with a 24 h
  `expiresAt`, and are leased by the agent after each check-in (every ~900 s).
- Lease order is effectively random (sort key is random hex). This design
  fixes that.
- The Settings screen is read-only and computed client-side; there is no
  stored fleet setting yet.

## 1. Command library

### Data

`SCRIPT#<scriptId>` / `PROFILE` (new key helpers in `backend/src/db/keys.ts`),
plus a list index item so the library lists by name.

```
{
  scriptId: "scr-<16 hex>",
  name: string,               // 1-100 chars, unique (case-insensitive) in the library
  description: string | null, // ≤ 500 chars
  interpreter: "cmd" | "powershell" | "bash" | "zsh",
  platform: "windows" | "darwin", // derived: cmd/powershell → windows, bash/zsh → darwin
  script: string,             // 1 .. 64 KiB UTF-8
  timeoutSeconds: number,     // 1..3600, default 300
  createdAt, createdBy, updatedAt, updatedBy
}
```

### Admin API (`backend/src/admin/scripts.ts`, prefix `/admin/api/v1`)

| Route | Answer |
|---|---|
| `GET /scripts` | `200 {items: [...]}` sorted by name; optional `?platform=windows\|darwin` |
| `GET /scripts/{id}` | `200 {...}`; unknown → `404 not_found` |
| `POST /scripts` | `201 {...}`; bad fields → `400 invalid_request {fields}`; duplicate name → `409 name_taken` |
| `PUT /scripts/{id}` | `200 {...}`; same errors, plus `404` |
| `DELETE /scripts/{id}` | `204`; already-queued copies are unaffected |

Audit: `script.created`, `script.updated`, `script.deleted` (detail: name,
interpreter; never the script body).

### UI

- New nav entry **Commands** (`#/commands`) between Policies and Audit.
- `backend/src/ui/views/commands.js`: table of name, shell, platform,
  description, updated; **New command** form; row click opens an edit form
  (name, shell select, timeout, description, script textarea in a monospace
  font) with **Save** and **Delete** (delete asks to type the name).

## 2. Queueing and ordering

### Queued command

Queuing creates an ordinary `run_script` command item, extended with:

```
seq: number,                // per-device, strictly increasing at assignment
scriptId: string,           // provenance
scriptName: string,
payload: { interpreter, script, timeoutSeconds }   // copied from the library
```

and **no** `expiresAt` attribute. On the wire (`Command.expiresAt` is a
required number in both contracts) a command without a stored expiry is sent
with `expiresAt = issuedAt + 10 years`, so the agent contract does not change.

`seq` comes from an atomic counter at `DEVICE#<id>` / `CMDSEQ`
(`UpdateItem ADD next :1`). Legacy commands without `seq` sort by `issuedAt`
before any sequenced command.

### Admin API (added to `commandDispatch.ts`)

| Route | Answer |
|---|---|
| `POST /devices/{id}/scripts` `{scriptId, confirm: true}` | `202 {commandId, seq}`; unknown script → `404 script_not_found`; platform mismatch → `409 platform_mismatch`; no confirm → `409 confirmation_required` |
| `POST /groups/{id}/scripts` `{scriptId, confirm: true}` | `202 {queued, skipped: {wrongPlatform}}` — one command per matching member |
| `POST /devices/{id}/commands/{cid}/move` `{direction: "up"\|"down"}` | `200`; swaps `seq` with the neighbouring **pending** command in one transaction; not pending → `409 not_pending`; already at the edge → `200` no-op |
| `POST /devices/{id}/commands/{cid}/cancel` | `200`; pending → `cancelled`; otherwise `409 not_pending` |

Each queues/cancel/move is audited (`command.queued` with `scriptId`,
`command.cancelled`, `command.moved`).

### Statuses

`pending → leased → succeeded | failed`, plus `expired` (legacy only),
`cancelled` (admin) and `skipped` (stop-on-failure, see §3).

### Lease (`backend/src/routes/commands.ts`)

- Read **all** of the device's pending/lease-expired commands (paginate the
  query rather than one page), sort by `(seq ?? -∞, issuedAt)`.
- If an earlier command is `leased` with an unexpired lease, return nothing
  queued after it (a machine never runs command N+1 while N is still out).
- Return up to `max` in that order. The agent already executes a batch
  sequentially in the order received.

### UI

- **Device detail** — new panel **Run a command**: a select of library
  commands filtered to the device's platform, **Queue** button, hostname
  confirmation (as `run_script` today). Below it:
  - **Queue**: pending/leased commands in run order, each with ↑, ↓, Cancel.
  - **History**: the existing Commands table gains `name`, `exitCode` and an
    expandable output row (`<details>`, like Software).
- **Group detail** — the same select (all platforms, labelled) and **Queue on
  members**, confirming by typing the group name; shows
  "Queued N, skipped M (wrong platform)".

## 3. Agent and the on-failure setting

### Shells (`agent/internal/executor/types.go`, `script.go`)

| interpreter | platform | how it runs |
|---|---|---|
| `powershell` | windows | unchanged |
| `cmd` | windows | temp file `<id>.cmd`, `cmd.exe /d /c <file>` |
| `zsh` | darwin | unchanged |
| `bash` | darwin | temp file, `/bin/bash <file>` |

An interpreter not valid for the running OS fails with
`exitCode -1`, output `error: unsupported_interpreter`. The backend's
`run_script` payload validation and `ui/views/dispatch.js` accept the two new
values.

### Fleet setting

`CONFIG` / `COMMANDS` item `{onFailure: "continue" | "stop"}`, default
`continue` when absent.

- `GET /admin/api/v1/settings/commands` → `200 {onFailure}`
- `PUT /admin/api/v1/settings/commands {onFailure}` → `200`; bad value →
  `400 invalid_request`. Audited `settings.commands.updated`.
- Settings screen gains a **When a command fails** select (Continue / Stop
  the remaining commands) with Save.

### Stop behaviour

- At lease time the backend adds `stopOnFailure: true` to the payload of each
  sequenced command when the setting is `stop`.
- Agent: after a command with `stopOnFailure` finishes `failed`, it does not
  run the rest of the leased batch and does not report them.
- Backend: when a `failed` result arrives for a command with
  `stopOnFailure`, every later-`seq` command for that device that is
  `pending` or `leased` becomes `skipped` (with `skippedBecause: <commandId>`),
  so they are never handed out again. The admin can re-queue them.
- With `continue`, a failure has no effect on the rest.

## Error handling summary

- Library validation errors → `400 invalid_request {fields}`; nothing written.
- Deleting a library command never touches queued copies.
- Agent offline: queue simply waits (no expiry).
- Agent crash mid-command: the existing at-most-once store answers the
  re-lease; ordering holds because nothing after it is leased while its lease
  is live.

## Testing

- **Backend unit** (mocked table, `node --test`): scripts CRUD and
  validation; seq allocation; move/cancel rules; platform filter and group
  skip counts; lease ordering incl. legacy commands and the "earlier still
  leased" gate; stop-on-failure marking `skipped`; settings get/put.
- **Agent (Go)**: `cmd` and `bash` decoding and execution plumbing (fake
  runner); wrong-OS interpreter; batch stops after a `stopOnFailure` failure
  and continues otherwise.
- **UI views**: Commands screen render/forms; device Run-a-command panel,
  queue with ↑/↓/Cancel, history output; group queue form; Settings select.
  Gherkin-style scenarios as in `backend/test/ui/views.test.js`.

## Rollout

Backend first (agents that do not know `cmd`/`bash` report
`invalid_payload` for those, and ignore `stopOnFailure`), then the agent
build. The console does not hide `cmd`/`bash` for old agents; an old agent
fails those commands visibly (and does not honour Stop) until it updates.
