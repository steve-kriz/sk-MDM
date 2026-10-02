---
name: orchestrate
description: >-
  Ticket-driven build workflow. Use when the user asks to plan a feature into
  tickets ("/orchestrate plan <feature>", or asks to break work into tasks), to
  build queued tickets ("/orchestrate build"), or to see board status
  ("/orchestrate status"). Manages ticket files in the project's tasks/ folder
  and drives tickets through the board's configured columns via subagents. The
  user watches progress live on the Tasks kanban board.
---

# Orchestrate: ticket-driven development

You drive tickets through the **board's configured columns** — read from
`tasks/team-config.json` — over ticket files stored in the project's `tasks/`
folder. There is no fixed BA → coder → tester → tech-lead pipeline: every
column names an `agent` (or none) and free-text `instructions`, and your job
is the **same for every column** — look up its agent, dispatch it with the
ticket plus that column's instructions, and move the ticket forward. The user
watches progress on a kanban board (the "Tasks" tab) that re-reads these files
every few seconds. Because of that live board, two rules are absolute:

1. **Every status change is written to disk immediately.**
2. **Every ticket file is rewritten in full with a single write — never partial
   appends or in-place edits of one field.** A half-written file can be read
   mid-poll; a whole-file write is atomic enough that the board's
   keep-last-good-parse logic absorbs it.

## Ticket file contract

Tickets live at `tasks/TASK-<nnn>-<slug>.md`. Each file is markdown with flat
frontmatter (simple `key: value` lines — no nested YAML). The structure is:

~~~markdown
---
id: TASK-001
title: Add login form validation
status: todo
created: 2026-07-18T10:00:00Z
updated: 2026-07-18T10:00:00Z
---

## Description
What needs doing and why.

## Acceptance Criteria
- [ ] First testable criterion
- [ ] Second testable criterion

## Cucumber Tests
```gherkin
Feature: Login validation
  Scenario: Empty email is rejected
    Given the login form is open
    When the user submits with an empty email
    Then an "email required" error is shown
```

## Additional Context
(User-owned. Read it before building. Never overwrite it.)
~~~

Rules for the frontmatter:

- `id` is authoritative (the filename slug is cosmetic). Scan `tasks/*.md`
  non-recursively; ignore subfolders.
- `status` is one of the valid enum values: `todo`, `defining`, `in-progress`,
  `testing`, `done`, plus `failed-testing`. Statuses live **only** in
  frontmatter — never track them anywhere else. The board's **five system
  lanes** render in this exact left-to-right order, matching how work moves:
  `todo → defining → in-progress → testing → done` — this is the fixed
  system-lane order; a project's `tasks/team-config.json` may additionally
  insert its own **user columns** anywhere between the system columns (most
  usefully between `defining` and `in-progress`, e.g. the starter board's
  `spec-review` lane), each with its own status slug. See **Column model** below for how a column's status maps
  to a dispatch.
  - `todo` — where new tickets are first created, awaiting work; also the
    landing lane a ticket returns to once the BA has defined it, so the build
    column's **claim** can pick it up.
  - `defining` — the **business-analyst** agent is defining the task (writing
    acceptance criteria and Gherkin) before any coding.
  - `in-progress` — the **coder** agent is implementing the ticket.
  - `testing` — the **tester** agent is creating/checking tests.
  - `done` — complete.
  - `failed-testing` — the ticket's tests failed; its board marker turns **red**
    and the fix loop runs before returning it to `testing`. It **remains the
    fix-loop failure status** and stays claimable, but it **no longer has a
    dedicated lane**: its cards fold into the **Testing** lane (keeping the red
    marker). It still owns its `tasks/failed-testing/` folder.

  There is no `post-processing` status, lane, or `kind: post-processing`
  ticket concept anywhere in this document — that concept has been removed
  from the app entirely; never describe, dispatch, or route to one.
- `created` and `updated` are ISO-8601 timestamps. Bump `updated` on **every**
  write. Preserve `created`.
- `agent` (optional) is the **claim** field: the id of the single agent currently
  building this ticket. It is set atomically when a ticket is claimed and cleared
  when the build reaches a terminal state. It is an extra frontmatter key, kept
  after the leading keys by the serializer, and round-trips untouched by the
  board. See "Concurrency, claims, and isolation" below. (`lib/ticket-queue.js`
  owns the claim/queue/isolation logic as pure, requireable helpers.)
- The `## Additional Context` section belongs to the user. Read it; never edit or
  delete it. Everything else in the body you may edit while a ticket is in your
  care.
- If a ticket file fails to parse (missing frontmatter, no closing `---`), skip
  it and tell the user rather than guessing.

## Routing

- `/orchestrate plan <feature description>` — or any feature request when no
  `todo` tickets exist yet → decompose the request into fresh tickets (the BA
  dispatch described under **Forward movement model**'s `defining` walk-through
  below).
- `/orchestrate build` → run **the generic column dispatch loop** (below) over
  every ticket on the board, repeatedly — batching, claiming, and dispatching
  as slots allow — until the board is clear (nothing left that a column's
  agent can act on right now).
- `/orchestrate status` → summarize the board (count per lane, list ticket
  ids/titles/statuses) and stop.

## Column model (`tasks/team-config.json`)

There is no fixed BA → coder → tester → tech-lead pipeline. Every board
**column** — read from `tasks/team-config.json`'s ordered `columns` array,
normalised by `lib/team-config.js` — names the single **agent** dispatched for
tickets sitting in it, plus free-text **instructions** telling that agent how
to handle a ticket passing through it. Which agent runs is **never**
hardcoded in this document; it is always a lookup against the current column.

- **Column order is board order.** `columns` is left-to-right the same order
  the board renders lanes in. Forward advancement (see **Forward movement
  model** below) follows this configured order, not a hardcoded sequence.
- **Each column has:** `status` (the slug tickets in this column carry),
  `label`, `description`, `agent` (a named subagent type, or `null` for a
  passive column), `instructions` (free text appended to that agent's
  dispatch), and `system` (`true` for one of the five fixed system columns —
  `todo` / `defining` / `in-progress` / `testing` / `done` — `false` for a
  user-added column).
- **Missing/corrupt `tasks/team-config.json`.** When the file is missing or
  fails to parse, `lib/team-config.js`'s `normalizeConfig` falls back to the
  canonical **five system columns** (`todo`, `defining`, `in-progress`,
  `testing`, `done`) with their default agents and instructions
  (`SYSTEM_COLUMN_DEFAULT_AGENTS` / `SYSTEM_COLUMN_DEFAULT_INSTRUCTIONS`) —
  never fewer, never a different order. Treat a corrupt config exactly like a
  fresh project with no user columns: proceed with the canonical five.
- **A system column's default agent**, used when its `agent` is explicitly
  `null`, is `SYSTEM_COLUMN_DEFAULT_AGENTS[<slug>]`: `todo` → none,
  `defining` → `ba`, `in-progress` → `coder`,
  `testing` → `tester`, `done` → none. These defaults are sourced
  from `lib/orchestrate-agents.js`'s `AGENT_TYPES`, not hardcoded twice.
- There is no `post-processing` column anywhere — `tasks/team-config.json`
  drops a legacy one on normalize rather than resurrecting it.

## The generic dispatch loop

For **every** ticket, on every pass of `/orchestrate build`, the orchestrator
runs the same decision — there is no per-role special-casing:

1. **Read the ordered `columns`** from `tasks/team-config.json` (see **Column
   model** above).
2. **Find the ticket's current column** — the column whose `status` slug
   equals the ticket's `status`. A ticket whose `status` matches **no**
   column at all (out-of-enum / `unknown`) is never silently routed anywhere,
   least of all back to `todo`: do not dispatch it, and report it to the user
   as needing manual attention.
3. **Resolve the agent to dispatch, with a fallback chain:**
   - the column's own `agent`, when it names one; else
   - `SYSTEM_COLUMN_DEFAULT_AGENTS[<slug>]`, when the column is one of the
     five system columns and its `agent` is `null`; else
   - **no agent** — the column is **passive** (see step 4).

   Once an agent name is chosen, if it names a specific subagent type that has
   **no definition file** in `.claude/agents/`, fall back to
   `general-purpose` and continue rather than aborting — and **report** which
   named agent was missing (the same fallback-and-report rule every dispatch
   in this skill has always followed).
4. **Dispatch, or wait.**
   - **Passive column** (no agent resolved at all) — `todo`, `done`, or any
     user "parking" column with no agent configured — is **never dispatched**.
     A ticket sitting there waits: `todo` is the **entry queue** (it waits for
     `/orchestrate build` to pick it up), and `done` is terminal.
   - **Column with a resolved agent** — dispatch it (Task tool) with the
     **fixed preamble + the full ticket text + that column's `instructions`
     LAST** (see **Prompt caching** below for why the instructions go last).
     The dispatched agent returns a **distilled** result (see **Distilled
     returns**), never its raw transcript.
5. **Act on the outcome.** A dispatch's outcome is **one of several**, not
   always "advance forward":
   - **Forward** — the common case: on success, advance the ticket to the
     **next column's status** in configured order (whole-file atomic write,
     `updated` bumped) and continue.
   - **Backward** — a ticket can be sent to an **earlier** column (the
     testing column's fix loop, or a RETURN verdict from a spec-review
     column). The concrete rules for when and where a ticket
     moves backward are specified in **Rework, review verdicts, and reaching
     done** below — this loop only guarantees that "advance forward" is never
     the sole hardcoded branch a dispatch can produce.
   - **Park-and-ask** — a dispatch can leave a ticket in place awaiting a
     human answer (e.g. a BA clarifying question) rather than advancing it
     either way; see the `defining` walk-through below.

This is a **loop**, not a one-shot pass: `/orchestrate build` keeps
re-scanning, batching everything eligible in parallel, and — whenever a
dispatch finishes and frees a slot — returns to step 1 to **top up** the free
slots with the next `selectNextBatch` set (see **Concurrency, claims, and
isolation**), until the board is clear.

## Forward movement model

Advancement follows the **configured column order** — left-to-right in
`columns` — which for the **starter board** (`starterConfig` in
`lib/team-config.js`) is exactly:

    todo → defining → spec-review → todo (approved) → in-progress (via claim) → testing → done

and for a bare `defaultConfig` board, with no user columns at all:

    todo → defining → todo (defined) → in-progress (via claim) → testing → done

The starter board's one user column, **`spec-review`**, sits between `defining`
and `in-progress` — the review gates the ticket's **specification before it is
built**, rather than its code after. Everything downstream of the build is
therefore purely forward: a green test result goes straight to `done`.

This is the existing status lifecycle, reframed as column dispatch rather than
a hardcoded phase pipeline:

- **`todo`** — passive (no agent). New tickets are created here. It is the
  **entry queue**: `/orchestrate build` scans it every pass, oldest first.
- **`defining`** (agent: **whatever this column configures**; `ba` only
  when its `agent` is `null`) — a ticket
  parked here while the BA is actively working it. The column's
  **instructions** carry the **definition-skip gate**: when a ticket is
  **already defined** (`isTicketDefined` in `lib/ticket-definition.js` — a
  real, non-placeholder `## Acceptance Criteria` checkbox **and** a
  non-empty ```gherkin block in `## Cucumber Tests`), the instructions tell
  the agent to pass it through unchanged rather than redefining it. Either
  way, a **defined** ticket advances to the **next column in configured
  order** — the `spec-review` column on the starter board, or straight back to
  **`todo`** on a board with no review column. It never goes straight into
  `in-progress`: the build column's **claim** (below) is what actually picks it
  up next.
  - **Run the Definition of Ready gate on the way out.** Before advancing a
    ticket out of `defining`, call `readinessReport` (`lib/ticket-definition.js`)
    on its body. When `ready` is false the ticket does **not** advance: send it
    straight back to the BA with `gaps[]` as the rework list. This mechanical
    floor runs before any reviewer is dispatched — see **The Definition of
    Ready gate** below.
  - **A ticket's `## Acceptance Criteria` freeze on spec-review APPROVE** (or,
    on a board with no review column, when it leaves `defining`). From that
    point no agent widens, narrows, or re-words them — only the user does, via
    an answered `question` or `## Additional Context`. They are the **only**
    basis on which a later column may fail the work, so every criterion has to
    be settled *before* a coder starts, which is exactly what the spec-review
    column exists to check (see **Spec-review columns: two verdicts**).
  - **Multiple undefined `todo` tickets discovered at once** (a fresh
    re-scan, or several created mid-build) are parked into `defining` and
    dispatched together, in **one message** — never one-at-a-time — subject
    to the same free-slot bound as any other batch (see **Concurrency,
    claims, and isolation**).
  - **A BA clarifying question parks only that ticket.** Write it onto the
    ticket's `question` frontmatter field (`lib/ticket-questions.js`, which
    turns its board dot yellow); the rest of the swarm keeps defining/building
    other tickets. A question-parked `defining` ticket does not hold a
    concurrency slot, so it can never starve other ready work.
    - When a parked definition's question is answered and it resumes
      actively-defining, it re-counts as a concurrency slot — so if a build
      meanwhile filled the slot it had freed, live occupancy MAY briefly
      exceed `limit` under a burst of simultaneously-answered definitions.
      This transient is ACCEPTED: it is bounded (by how many answers land at
      once), self-corrects as in-flight builds finish, and never corrupts
      state — so it is preferred over a strict cap-on-resume that could
      deadlock a resuming definition against an always-full bound.
  - **Stale `defining` on a fresh run** (left over from a prior, interrupted
    run with no live BA) is treated as stale intake: re-dispatch the BA to
    finish the definition rather than skipping it.
  - Once defined (and any question answered), the ticket returns to `todo`
    and is evaluated immediately against the free-slot math
    (`canRunInParallel`) — claimed and built right away if a slot is free,
    rather than waiting for a review pause: adding/defining a ticket mid-build
    is implicit consent to proceed.
- **Entry into `in-progress` is a claim, not a plain dispatch.** Unlike every
  other column transition, moving a `todo` (or `failed-testing`) ticket into
  `in-progress` is performed by **`claimTicket`** (`lib/ticket-queue.js`) — a
  compare-and-set, whole-file write that sets `status: in-progress` **and**
  `agent: <build id>` together, and only succeeds when the freshly re-read
  ticket is still claimable and unclaimed. This is unchanged mechanics (see
  **Concurrency, claims, and isolation**); the column model just describes
  *which* agent the claimed build then dispatches: the `in-progress`
  column's configured `agent` (`coder` when it is `null`).
- **`in-progress`** (agent: **whatever this column configures**; `coder`
  only when its `agent` is `null`) — the
  claimed build, running in its own git isolation (branch/worktree — see
  **Concurrency, claims, and isolation**). On success, advance to
  **`testing`**.
- **`testing`** (agent: **whatever this column configures**; `tester` only
  when its `agent` is `null`) — the tester
  writes/extends both e2e and unit tests and runs the suite. A **green**
  result advances forward, following configured column order. A **red**
  result's fix loop is backward movement, specified in **Rework, review
  verdicts, and reaching done** below (this loop only guarantees a red result
  is never silently treated as green).
- **User columns are dispatched serially** — one ticket at a time, in
  configured column order — never in parallel with each other or with the
  shared-git-writing steps of other tickets (see **Concurrency, claims, and
  isolation**'s serialize-only-shared-git rule). The one exception is a
  **read-only** user column whose agent has no write tools at all — the
  starter board's `spec-review` (`tech-lead` on a board that has not
  re-pointed it: Read/Grep/Glob only)
  is one. It touches no shared git state, so it may be **batched in parallel**
  like any BA dispatch, bounded by the same free-slot math. Only tree-writing
  dispatches must serialize.
- **`done`** — terminal; passive (no agent). The concrete rules for exactly
  when a ticket is allowed to reach `done`, and what a backward
  verdict does instead, are specified in **Rework, review verdicts, and
  reaching done** below.

**Batching is unchanged.** Whenever more than one ticket is eligible for the
same kind of dispatch at once — several undefined `todo` tickets awaiting the
BA, or a freshly-claimed batch awaiting their coder dispatch — issue **all**
of those Task-tool calls **in a single message**, never one-at-a-time, capped
only by the free-slot bound (`selectNextBatch` / `canRunInParallel` in
`lib/ticket-queue.js`, default concurrency **3**, clamped to a hard ceiling of
**8**). Claim-before-build ordering is unaffected by batching: each ticket in
a batch is still claimed individually and atomically (`claimTicket`, a
whole-file write, re-read fresh, first writer wins) **before** its dispatch
starts — only the Task-tool calls themselves are issued together, once every
claim in the batch has landed. See **Concurrency, claims, and isolation** for
the full mechanics — they apply identically no matter which column a batch is
dispatching into.

## Model routing (optimise for cost)

The swarm is tuned for cost. In a swarm the token bill is dominated by
**context, not output**: every sub-agent re-reads files, re-loads
instructions, and re-explains state, so most savings come from tiering models
by task difficulty and keeping each sub-agent narrow — not from any single
model choice.

Each agent's model is pinned in its own `.claude/agents/*.md` frontmatter
(`model:` key) — **not** in this document, and never spliced per-ticket, or
per-column, into a dispatch preamble (that would bust the prompt cache; see
**Prompt caching** below). The out-of-the-box tiering for the five system
columns' default agents:

- **Default tier `claude-sonnet-5`** — `coder` (`in-progress`).
  Implementation needs real capability but not the premium tier. This is also
  the fallback every other role degrades to when its own tier is unavailable.
- **Premium tier `claude-opus-4-8`** — `ba` (`defining`) and
  `tech-lead` (the `spec-review` column). The hard reasoning
  steps — decomposing a feature into tickets, and judging whether a spec is
  buildable before anyone builds it — justify the premium tier. Falls back to `claude-sonnet-5` when
  `claude-opus-4-8` is unavailable.
- **Cheap tier `claude-haiku-4-5`** — `tester` (`testing`).
  Writing and running tests from a fully-specified ticket is mechanical,
  high-volume work — the biggest per-ticket saving in the swarm. Falls back to
  `claude-sonnet-5` when `claude-haiku-4-5` is unavailable.

**These tiers are settings, not constants**, owned by each agent's `model:`
line — change a column's effective model by editing the `model:` frontmatter
of the agent it dispatches (or by pointing the column at a different agent),
and the Team tab's **Agents** panel edits it for you, keeping the `assets/`
mirror byte-synced. A user column that names its own agent (or reuses one of
the four above) inherits whatever tier that agent's own file pins — this
document states the policy once, here; no per-column section restates a model
id anywhere.

## Distilled returns (never inherit a sub-agent's raw context)

Every sub-agent returns a **compact, distilled summary** of its work — never
its full working transcript — and the orchestrator works **only** from that
summary, never inheriting a sub-agent's raw context. Concretely: the BA
(`defining`) returns the ticket ids/titles it defined plus any clarifying
questions; the coder (`in-progress`) returns the changed files, a
one-paragraph summary, and (where useful) the diff; the tester (`testing`)
returns pass/fail plus the failing output and the test file names; a
spec-review column's agent returns its verdict plus, on a RETURN, its gap
list. The detailed state lives in
the **ticket files and the code**, which the next agent reads directly, so
nothing is lost by keeping each hand-off small. This is the single biggest
cost lever in the swarm: small hand-offs keep every downstream agent's
context — and therefore the token bill — small.

## Prompt caching (stable prefix, volatile suffix)

Cached input tokens cost roughly a **tenth** of fresh ones, so the swarm is
structured to maximise cache hits. The rule is **stable content first,
volatile content last**, so the unchanging prefix stays cache-warm across
every dispatch and every agent — regardless of which column is dispatching:

- **The agent definition files are the stable, always-cached prefix.** Each
  agent's system prompt (`.claude/agents/*.md`) is identical
  on every dispatch of that agent, so it is reused from cache across the
  whole swarm. **Never regenerate an agent definition or splice per-ticket
  data — or a per-column model id — into it**: keep it byte-stable so its
  cache is reused (this is also why the `assets/` mirror is kept
  byte-identical). Where the queue allows, group repeated dispatches of the
  **same agent** together so its cached system prompt stays warm rather than
  alternating agents and cold-starting each one.
- **Build every dispatch prompt as: fixed preamble + ticket text + that
  column's `instructions`, LAST.** The **stable prefix** is the agent's
  system prompt plus a fixed preamble (the same role reminder and
  ticket-file contract, worded identically on every dispatch, never
  interleaving ids/timestamps/paths). The **volatile tail** — appended after
  the stable prefix — is the full ticket text, with that column's
  `instructions` appended **last of all** (and, for a fix-loop or rework
  dispatch, the failing output/verdict after that). Use the same wording and
  order for the preamble every time so its prefix matches the cache.
- **Front-loaded ticket context is shared, cache-friendly state.** Because the
  BA (`defining`) captures all the context a downstream agent needs **inside
  the ticket body** up front, later agents read that one stable artifact
  instead of re-exploring the repo. Agents read **only the specific files the
  ticket names**, not whole trees.
- **Keep the volatile tail small.** Combined with **Distilled returns** above,
  only the small, changing part of each prompt is fresh (uncached) input,
  while the large, stable part (system prompt + preamble + ticket contract)
  is served from cache. Small volatile tails plus stable prefixes are what
  make the swarm cheap.

## Context optimisation (trim between dispatch hand-offs)

`tasks/team-config.json`'s `skill.contextOptimization` (`{ enabled, level }`,
normalised by `lib/team-config.js`, editable from the Team → Board panel)
makes the swarm's existing context-minimisation habit a **configurable,
persisted setting** instead of unconditional behaviour. It does not replace
or contradict **Distilled returns** or **Prompt caching** above — it is the
directive that tells the orchestrator, at every **column-to-column
movement**, to actually apply them:

- **When to apply it.** At **every dispatch hand-off** — every point a
  sub-agent returns and the next column's dispatch is about to launch,
  forward or backward. This is not a hook on a user manually dragging a card
  between board lanes; it is every agent-dispatch hand-off described
  throughout this document.
- **Enabled check.** Read `skill.contextOptimization.enabled`. Treat it as
  disabled **only** when the value is the literal boolean `false`; a missing
  config file, a missing `contextOptimization` key, or any non-boolean value
  counts as enabled (the config layer normalises it to `true`).
- **What to do when enabled.** At each hand-off: **drop** context that is no
  longer needed (a completed dispatch's full working transcript, files read
  but not touched, exploratory scratch state), **summarise** what must be
  kept (the distilled per-agent return described in **Distilled returns**,
  plus any ticket-file state the next dispatch needs), and **carry forward
  only that minimum** into the next dispatch.
- **The `level` dial.** `skill.contextOptimization.level` is one of
  `conservative`, `standard`, or `aggressive`: `conservative` carries more
  surrounding state forward (useful when a user is debugging a run),
  `standard` is the everyday balance described above, and `aggressive` trims
  to the smallest viable hand-off — distilled summary and ticket-file
  pointers only, nothing extra. A missing or invalid `level` is treated as
  `standard`.
- **Defaults.** Missing/invalid/unparseable config is treated as
  `{ enabled: true, level: "standard" }` — the swarm already optimises
  context unconditionally today, so this default preserves that existing
  behaviour.

## Rework, review verdicts, and reaching done

This section is the concrete backward-movement and terminal-transition
specification that **The generic dispatch loop** and **Forward movement
model** above point to. Two separate loops share the same 3-attempt cap and
park-and-ask shape — the testing column's fix loop (backward to the build
column on a red result) and a spec-review column's RETURN verdict (backward to
the definition column on an inadequate spec) — plus the mechanical Definition
of Ready gate that feeds the second, and the terminal `done` transition.
Neither loop is hardcoded to "the tester phase" or "the tech-lead phase": both
are described purely in terms of the column a ticket sits in, that column's
`agent`, and that column's `instructions`.

Both loops exist to fix a ticket **inside the cycle that raised the problem**.
Neither ever defers work to a new ticket — see **No ticket is ever created
during a build run** below, which is the rule the rest of this section is
built around.

### The testing fix loop (backward movement on a red result)

A **testing-type column** is the system `testing` column, or any user column
whose `instructions` declare it a testing step (free text the orchestrator
reads, not a new schema field). When that column's agent reports a **red**
result:

1. Set the ticket's `status` to **`failed-testing`** (whole-file write,
   `updated` bumped) — it stays claimable, folds into the **Testing** lane
   with a red marker (`laneForStatus`), keeps owning `tasks/failed-testing/`,
   and is re-picked by `selectNextBatch` while attempts remain
   (`CLAIMABLE_STATUSES` in `lib/ticket-queue.js` includes it).
2. Dispatch the agent of the **nearest preceding build column** — walking
   backward through the configured column order from the testing column to
   the closest earlier column whose agent actually implements code (the
   `in-progress` column's configured `agent`, `coder` when it is `null`) —
   with the ticket **plus the failure output** appended after that column's
   `instructions` (see **Prompt caching**'s volatile-tail ordering).
3. On success, return the ticket to the **testing** column's status for
   another run — the same forward step as any other advance, just re-entered.
4. **Cap this fix loop at 3 attempts per ticket.** The orchestrator counts
   attempts from the ticket's own history (its `runs`/`activities` log
   entries for this fix cycle) — no separate counter field is invented. After
   the **third** red result, leave the ticket in `failed-testing`, summarise
   what is still failing, and ask the user how to proceed rather than
   dispatching a fourth fix attempt. This cap is a property of the testing
   column's rework rule, not a hardcoded "Phase 3" — and the testing column's
   default `instructions`
   (`SYSTEM_COLUMN_DEFAULT_INSTRUCTIONS.testing` in `lib/team-config.js`) name
   the "capped at 3 attempts" behaviour so it is visible in config, not just
   in this document.
5. **No preceding build column exists.** A testing-type column with no build
   column anywhere before it in configured order cannot auto-fix: report that
   to the user and leave the ticket in `failed-testing` rather than guessing
   at a target or silently discarding the failure.

### Spec-review columns: two verdicts

A **spec-review column** is a user column positioned **before** the build column
whose agent reviews the ticket's **specification** rather than an
implementation — because none exists yet. The starter board ships exactly one:
`spec-review` → `tech-lead`, sitting between `defining` and
`in-progress` (`STARTER_SPEC_REVIEW_COLUMN` in `lib/team-config.js`).

**Why the review sits before the build and not after it.** A reviewer reading
finished code always finds things nobody wrote down at `defining`, and the only
place to put them was a follow-up ticket — so every run ended with more tickets
than it started with, and the board never converged. It also surfaced scope at
the most expensive possible moment: after the code was written, tested and
reviewed, when acting on a finding means throwing that work away. Reviewing the
**spec** catches the same gaps for the price of one BA dispatch. The
follow-up-ticket mechanism is therefore **gone**, not merely throttled — see
**No ticket is ever created during a build run** below.

Every spec-review dispatch resolves to **exactly one** of two verdicts — never
both, never neither:

**(a) APPROVE (forward).** The ticket is buildable as written. Advance it: like
any defined ticket it returns to **`todo`**, so the build column's **claim** is
what picks it up next (whole-file write, `updated` bumped). On approval the
ticket's `## Acceptance Criteria` are **FROZEN** — from here they are the only
basis on which any later column may fail the work, and no agent may widen,
narrow, or re-word them.

**(b) RETURN (backward).** The reviewer reports a numbered gap list. Send the
ticket **backward** to the **nearest preceding definition column** — walking
backward through the configured column order to the closest earlier column
whose agent defines tickets (the `defining` column's configured `agent`, `ba`
when it is `null`) — and dispatch that agent with the ticket **plus the gap
list**, appended after that column's `instructions` (see **Prompt caching**'s
volatile-tail ordering). On success the ticket re-enters the forward flow and
returns to the spec-review column.

Two structural rules bound both verdicts, and you enforce them on every
dispatch:

- **A gap budget.** A spec reviewer returns **at most 5 gaps, force ranked,
  most blocking first** — and **returning zero is a normal, expected outcome**,
  not a sign the review was shallow. A ticket needing more than five gaps is a
  **sizing problem**, not a long list: the reviewer says so and names the split
  it should become, and you raise that with the user rather than letting the
  list grow.
- **Gaps are about buildability only.** Each gap names the acceptance criterion
  or missing section at fault and what would fix it. Style, naming, formatting
  and hypothetical future refactors are out of scope — as is anything about
  code, of which there is none yet.

**Cap this return ⇄ redefine cycle at 3 attempts per ticket**, mirroring the
testing fix-loop cap exactly and tracked the same way (a per-ticket attempt
count read from the ticket's own `runs`/`activities` history, never a new
frontmatter field). After the **third** return, leave the ticket in `defining`,
summarise the unresolved gaps, and ask the user how to proceed rather than
dispatching a fourth redefinition. A spec that cannot be settled in three passes
needs a human decision, not another agent.

**No definition column precedes it.** A spec-review column with no definition
column anywhere before it in configured order cannot return a ticket for rework:
report that to the user and leave the ticket in place rather than guessing at a
target.

### The Definition of Ready gate (mechanical, runs before the reviewer)

`readinessReport(body)` in `lib/ticket-definition.js` is a **pure, mechanical**
check that a ticket body is fit to build. It returns `{ ready, gaps[] }` and
never throws for any input. Run it on **every** ticket leaving a definition
column, **before** dispatching a spec reviewer: it is cheap, deterministic, and
holds even when an agent drifts from its prose instructions.

It reports a gap for each of:

1. no real acceptance criterion (the skeleton placeholder does not count),
2. any criterion phrased in unfalsifiable terms (`VAGUE_CRITERION_TERMS` —
   *gracefully, properly, appropriately, correctly, robust, as needed, etc.*),
3. fewer Gherkin scenarios than acceptance criteria,
4. no failure/edge scenario among them,
5. a missing or empty `## Relevant Files` section.

**When `ready` is false the ticket does not advance.** Send it straight back to
the definition column with `gaps[]` appended as the rework list — the same
backward move as a reviewer's RETURN, counting against the same 3-attempt cap —
and do not spend a spec-review dispatch on it. The reviewer's judgement is the
layer *above* this floor, never a substitute for it.

`isTicketDefined` (the older, looser structural predicate) is unchanged and
still gates the definition-skip described under `defining` above. Readiness is
strictly stricter: everything ready is defined, but not everything defined is
ready.

### No ticket is ever created during a build run

**No agent and no column creates a ticket during `/orchestrate build`. Neither
do you.** The tickets that exist when a run starts are the tickets that exist
when it ends.

This is absolute, and it is what keeps the pipeline convergent. There is no
follow-up ticket, no deferred backlog item, no `review-of:` ticket, and no
observation that becomes work later — those concepts are **removed from this
workflow**, not merely bounded. Without that rule each generation of review
findings became tickets which were themselves reviewed, raising the next
generation, and three tickets became fifteen without ever converging.

A finding anywhere in the pipeline therefore has exactly two possible fates:

- **It fails the ticket it was found on, now.** A spec gap returns the ticket to
  `defining`; a red test or an unmet acceptance criterion returns it to the
  build column. Either way it is fixed inside the ticket that raised it, in this
  cycle.
- **It expires as an observation.** Recorded in the run summary, acted on by
  nobody, gone when the ticket reaches `done`.

Anything the user genuinely wants built becomes a ticket **the user creates**,
on a later run, deliberately. At the end of a run report the observations as one
short list so the user can decide — and create nothing yourself.

(The `review-of:` frontmatter key is still *read* by the board, which paints such
a card's type bar yellow, so follow-up tickets already on disk from older runs
keep rendering correctly. Nothing writes it any more.)
### Reaching done (terminal)

Once a ticket clears its **last agent-bearing column** in configured order —
for the starter board, the `testing` column going green — the orchestrator sets
its `status` to **`done`** directly, whole-file write, `updated` bumped. There
is no intervening post-processing step: TASK-206 removed the `post-processing`
column and the whole `kind: post-processing` "final events" concept from the
app entirely (lib, renderer, and on-disk config/tickets), so nothing runs
"against every ticket" before `done` — the last column's success **is** the
terminal transition.

With the review moved to the front of the board, nothing between `testing` and
`done` can block a ticket: a green test result is the terminal transition, and
no follow-up work is raised against a finished ticket because **nothing creates
tickets at all** (see **No ticket is ever created during a build run** above).
`done` is **never** reached while a backward move is still pending resolution
for that ticket — a spec-review RETURN or a testing fix loop must resolve
forward, or hit its 3-attempt cap, before `done` is possible.

Every transition in this section — the `failed-testing` write, the backward
rework write, the forward re-entry, and the terminal `done` write — is a
whole-file atomic write; `created` is preserved, `updated` is bumped, and the
per-activity cost log (`activities`) is appended per dispatch, exactly as
described in **State-consistency rules** below. No status outside the enum
(`todo` / `defining` / `in-progress` / `testing` / `failed-testing` / `done`,
plus any user column slug) is introduced anywhere in this section — the
backward rework move reuses existing statuses; it never invents a new one.

## Concurrency, claims, and isolation

The swarm builds tickets in parallel, in batches, but self-coordinates
**only** under these guarantees. The pure helpers in `lib/ticket-queue.js`
implement the decisions below and are unit-tested; **this module, and
`lib/ticket-lanes.js`, are unchanged by the column model** — the swarm's
claim/slot/isolation logic stays bound to the same swarm-owned statuses it
always has (`todo` / `defining` / `in-progress` / `testing` /
`failed-testing`), regardless of which agent a column's `agent` field
currently names.

- **Bounded concurrency (batch size).** At most **N** agents build at once, so
  each set/batch is at most N tickets (default N = 3, `DEFAULT_CONCURRENCY`;
  clamped to a hard ceiling of 8, `MAX_CONCURRENCY`). `selectNextBatch` fills
  only the free slots (`limit − (in-progress + testing + defining)`, the
  slot-occupancy count that includes `defining`), so it never starts a build
  when N tickets already occupy slots. Tickets past the bound wait in the
  queue and are picked up as slots free.
- **Dispatch a newly-created ticket into a free slot.** When a single ticket
  is created during a build, decide whether it can run **right now** with
  `canRunInParallel(tickets, newTicket, { limit, agentId })`. It reuses the
  same eligibility and slot math as `selectNextBatch` and returns `{ ok,
  reason, freeSlots }` — decision-only, it never claims or writes. On
  `ok: true`, claim (`claimTicket`) and build immediately; on `ok: false`
  (`no-ticket` / `claimed` / `already-active` / `not-claimable` / `no-slots`)
  leave it queued in `todo`.
- **At most one agent per ticket.** A ticket is claimed (`claimTicket`) by
  writing your build's id into its `agent` frontmatter field together with
  `status: in-progress`, in a single whole-file write, and only when the
  freshly re-read ticket is claimable and unclaimed. That write is the atomic
  claim; the first writer wins. No two swarm agents may work the same ticket.
- **Each build writes only its own ticket file.** A build never writes
  another ticket's file or any shared board state.
- **Whole-file, atomic writes preserved.** Every ticket write is a single
  full-file rewrite (never a partial append/in-place field edit), so a
  concurrent board poll never reads a half-written file — the board's
  keep-last-good-parse absorbs any mid-write read. This rule holds unchanged
  for every column's write, not just a build's.
- **Per-ticket git isolation.** Each build runs on its own branch/worktree
  derived from the ticket id (`ticketBranchName` / `ticketWorktreeDir`), so
  parallel builds never clobber each other's working tree. Serialize **only**
  at the points that touch shared git state — e.g. merging a finished build's
  branch back into the base branch, or a **user-column agent that writes to
  the shared tree** (it must be serialized exactly like a shared-git merge
  step, never run in parallel with another tree-writing dispatch) — doing
  those **one at a time**.
- **User-column statuses stay non-claimed, non-slot-counted, and serial.**
  `lib/ticket-queue.js`'s claim/slot bound is scoped to the swarm's own
  statuses only; a **user column's** status (`isUserStatus`, in
  `lib/ticket-lanes.js` and mirrored in `lib/ticket-queue.js`) is never
  claimed, never counted toward the concurrency bound, and its dispatch
  always runs **serially** — one ticket at a time — never batched in
  parallel like a `todo`/`failed-testing` claim.
- **Release on terminal state.** When a build reaches `done` (or is left in
  `failed-testing` after the cap), clear its `agent` claim (`releaseTicket`)
  so the slot frees for the next batch and, for `failed-testing`, the ticket
  can be re-picked later.

## State-consistency rules

- Only **you** (the orchestrator) edit ticket status/frontmatter. Subagents
  receive ticket content in their prompt and report results back **as a
  compact, distilled summary** — they do not touch status or claims, and you
  never inherit their raw working context (see **Distilled returns**).
- Claim before you build: write the `status: in-progress` + `agent`
  transition before starting the work it names, and never touch a ticket
  claimed by another agent.
- Never invent a status outside the valid enum: `todo`, `defining`,
  `in-progress`, `testing`, `done`, and `failed-testing` — five lanes plus the
  claimable fix-loop status. **No new status is introduced by the column
  model** — a user column's slug is a value `lib/team-config.js` validates and
  persists, but the swarm-owned lifecycle itself is unchanged. There is
  **no** `post-processing` status, lane, or ticket kind anywhere — it has
  been removed from the app entirely.
- Timestamps: preserve `created`, always bump `updated`.
- Per-activity cost log: after each column's agent dispatch completes, append
  one entry to that ticket's `activities` frontmatter field — a one-line JSON
  array, written with the standard whole-file write and `updated` bumped —
  recording the `activity` (`ba` / `code` / `test` / `review`, or any other
  activity string a user column's agent performs — the list is open-ended),
  the `model` dispatched, and its `startedAt`/`finishedAt`; include
  `tokensIn`/`tokensOut`/`costUsd` only when the run actually reported them,
  and `cacheReadTokens`/`cacheCreationTokens` only when telemetry correlated
  usage for that window — never fabricate a token or cost figure when data is
  unavailable (e.g. telemetry off, or no rows matched). This is additive: the
  existing `startedAt`/`finishedAt`/`tokens`/`costUsd` accounting and the
  `runs` log stay untouched.
