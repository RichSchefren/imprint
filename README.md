# Imprint

Imprint is a local-first, provenance-preserving memory of the judgments you
express while working with Claude Code. It stores the raw **Case**, **Verdict**,
**Call**, optional **Reason**, and available chosen/rejected alternatives before
any principle is derived. Later projections never replace that source evidence.

Imprint 3.1.1 is the authority, ontology, resilience, and public-operability
release built on the clean 3.0.0 architectural reset and 3.0.1 integrity
closure. The v3 line is not data-compatible by accident: imports are
quarantined, migrations are additive, and JSON-LD is the portable interchange
format.

## What ships

- An immutable per-node capture spool and single-writer SQLite compiler.
- Bitemporal, append-only ontology records with node and edge provenance.
- A versioned typed ontology for judgment, self-model, chosen direction,
  business reality, consent, confidence, calibration, and outcomes.
- Bounded, deterministic retrieval with configurable domain selection.
- A separate ingestion floor for operator-reviewed external material.
- Markdown and lossless JSON-LD projections.
- Claude Code hooks for session retrieval, domain selection, explicit feedback
  capture, and content-free health reporting.
- Portable installers, uninstallers, tests, checksums, and CI for macOS, Linux,
  and genuine Windows runners.

Core operation is offline and has no telemetry. The former digest and profile-
learning flags were removed because no runtime implemented them. Passive
Screenpipe observation is roadmap-only and is not included or claimed.

## Requirements

- Python 3.10 or newer, including Python 3.14, with `venv` and `pip`.
- Claude Code only if you want automatic hook integration. The CLI and store can
  be used without Claude Code.
- A local, non-cloud-synchronized data directory. Network drives and shared
  writable SQLite databases are unsupported.

## Install from a release artifact

Download and verify either release archive and `SHA256SUMS`. Extract the archive,
then run the installer inside it. Paths containing spaces are supported.

macOS or Linux:

```bash
bash install/install.sh
```

Windows PowerShell 7:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
& .\install\install.ps1
```

Both installers create an isolated virtual environment, write a portable config,
install an owned `imprint` launcher in the user's command path, register each
managed hook exactly once, and fail if the installed CLI cannot report version
`3.1.1`. Re-running the installer is safe and removes duplicate managed hooks
while preserving unrelated hooks. On POSIX, the installer adds one marked PATH
block to the active shell's login profile (`.zprofile`, `.bash_profile`, or
`.profile`); uninstall removes that exact owned block and leaves unrelated shell
configuration untouched. Windows uses the per-user `WindowsApps` directory,
which is already present in a normal PowerShell user PATH.

Advanced non-interactive options:

```bash
sh install/install.sh \
  --install-root "$HOME/Applications/Imprint App" \
  --data-root "$HOME/Imprint Data" \
  --launcher-dir "$HOME/.local/bin" \
  --operator primary
```

```powershell
& .\install\install.ps1 `
  -InstallRoot "$HOME\Applications\Imprint App" `
  -DataRoot "$HOME\Imprint Data" `
  -LauncherDir "$env:LOCALAPPDATA\Microsoft\WindowsApps" `
  -Operator primary
```

The configuration and environment-variable reference is in
[`docs/configuration.md`](docs/configuration.md).

## Verify the installation

The installer creates a small owned launcher named `imprint` (or `imprint.cmd`)
and points it at the executable inside the isolated environment:

- macOS/Linux: `~/.local/lib/imprint-local/venv/bin/imprint`
- Windows: `%LOCALAPPDATA%\ImprintApp\app\venv\Scripts\imprint.exe`

```bash
imprint version
imprint health
imprint health --deep
imprint whoami
imprint log --date 2026-07-16 --limit 100
imprint export --format jsonld --output imprint-export.jsonld
```

The default health check is bounded and reports expensive facts as
`not_checked`; `--deep` explicitly runs SQLite integrity, permissions, receipt,
and backup verification. A fresh store reports `backup_state=never_created`
without becoming degraded. Health output contains counts and state, never
captured content.

`whoami` prints the opaque configured operator identity. `log` lists at most 200
content-free canonical event-index rows for one UTC day and can filter by event
type or opaque event ID. Curation commands default `--by` to the `whoami`
identity; an explicit `--by` remains available for another governed actor.

## Core CLI workflows

```bash
imprint capture --event capture.json
imprint authority enroll --recovery-output /offline/imprint-authority-recovery.json
imprint authority recovery-create --output /offline/imprint-authority-recovery-next.json
imprint authority transport --output /offline/imprint-authority-transport.json
imprint authority trust-bootstrap --input /offline/imprint-authority-recovery.json
imprint authority recovery-restore \
  --input /offline/imprint-authority-recovery.json \
  --authority-transport /offline/imprint-authority-transport.json
imprint authority pair-request --output /offline/pair-request.json
imprint authority pair-authorize --input /offline/pair-request.json --output /offline/pair-package.json
imprint authority pair-finalize --input /offline/pair-package.json
imprint authority rotate
imprint authority checkpoint
imprint compile --once
imprint spool prune
imprint derive --submit proposal.json
imprint derive --capture capture.json
imprint derive --pending
imprint retrieve --session SESSION_ID --prompt "current task"
imprint retrieve --session SESSION_ID --authority-mode analytical --partition default_future --refresh
imprint ontology coverage
imprint review list
imprint review ratify NODE_ID --by OPERATOR_ID
imprint review authorize-successor PROPOSAL_ID --input TYPED_NODE.json --valid-from RFC3339 --reason "why" --by OPERATOR_ID
imprint review reject NODE_ID --by OPERATOR_ID --reason "not a real pattern"
imprint review defer NODE_ID --by OPERATOR_ID --reason "needs more evidence" --revisit-after RFC3339
imprint ontology add-node --input TYPED_NODE.json --valid-from RFC3339
imprint ontology add-relation --input TYPED_RELATION.json --valid-from RFC3339
imprint consent grant --input CONSENT_GRANT.json --valid-from RFC3339
imprint consent list
imprint consent revoke GRANT_URN --by OPERATOR_URN --reason "reason"
imprint observation add --input OBSERVATION.json --valid-from RFC3339
imprint outcome add --input OUTCOME.json --valid-from RFC3339
imprint domain add research --label "Research" --description "Source-grounded research" --evidence EVIDENCE_ID --by OPERATOR_ID
imprint domain select research --by OPERATOR_ID
imprint domain freeze research --by OPERATOR_ID
imprint transition contradict NODE_A NODE_B --reason "incompatible" --evidence EVIDENCE_ID --by OPERATOR_ID
imprint transition supersede REPLACEMENT_NODE PRIOR_NODE --reason "replaced" --evidence EVIDENCE_ID --by OPERATOR_ID
imprint verdict add-reason VERDICT_ID --reason "stated reason" --by OPERATOR_ID
imprint ingest scan --input candidates.json
imprint ingest keep ITEM_ID --why "why this belongs in the research floor"
imprint export --format jsonld --output imprint-export.jsonld
imprint export --format markdown --output imprint.md
imprint import --format jsonld --input imprint-export.jsonld --dry-run
imprint backup create
imprint backup verify /path/to/backup.sqlite3
imprint backup restore /path/to/backup.sqlite3 --confirm backup.sqlite3
imprint delete purge --scope EXACT_ID --preview
imprint migrate verify
```

`capture` queues an immutable event; only the configured compiler writes canon.
On a compiler-authorized installation, the Stop hook compiles its durable spool
before returning, so the captured correction is available to the next session
without a manual command. A non-compiler node remains spool-only. Claude's native
session identifier is mapped through an installation-local secret to a stable
opaque Imprint session URN; the native identifier is never written to the spool,
store, export, or retrieval receipt. Huge transcripts retain the last operator
feedback and bounded context, plus a content hash, byte counts, truncation flags,
and a visible degradation receipt rather than ingesting the entire transcript.
Imported material is quarantined until `keep` or `kill`. Review and deletion are
explicit operator actions. Run `--help` on any command for its closed arguments.
`supersede` is directional: the first node is the replacement and the second is
the prior head that leaves current retrieval. Both versions remain in history.
Proposal derivation creates reviewable candidates only; it never grants authority.
Typed ontology inputs use ontology schema `3.1.0`; they fail closed on unknown
fields, invalid authority, cross-operator relationships, and missing evidence.
Transcript, Screenpipe, financial, behavioral, and connector observations also
require a current source-specific `ConsentGrant`.

### Human approval for authority-changing commands

First trust must be enrolled from a native terminal. Imprint never accepts a
redirected secret ceremony:

```bash
imprint authority enroll
```

An authority-changing writer is deliberately a two-call operation. Run the
real command without a token first. It exits nonzero with
`E_AUTH_APPROVAL_REQUIRED` and an exact, persisted `approval_request`; no
semantic mutation or nonce consumption has occurred. Save only that embedded
JSON object as `approval-request.json`, inspect its purpose, transition,
subjects, sources, targets, result version IDs, scope, field paths, and digests,
then approve it at the native terminal:

```bash
imprint authority approve --input approval-request.json > approval-token.json
```

Retry the identical writer command with the returned token file:

```bash
imprint domain select research --by OPERATOR_ID \
  --approval-token approval-token.json
```

The token is short-lived and binds the exact command intent, prior state,
frozen execution fields, resulting record/version IDs, installation, ledger
head, operator, and one-time nonce. Changing the command arguments or prepared
state, replaying the token, or allowing it to expire fails closed. There is no
standalone `authority propose` command: the first call to the actual writer is
the only supported way to create an executable approval request.

## Uninstall safely

macOS or Linux:

```bash
bash install/uninstall.sh
```

Windows:

```powershell
& .\install\uninstall.ps1
```

Uninstall removes the application, only hooks carrying Imprint's ownership
marker, and only a launcher carrying Imprint's marker and expected installed
target. A missing, replaced, or modified launcher is left untouched. It preserves
the data root and, by default, the config. `--purge-config`
or `-PurgeConfig` removes config too; neither option deletes captured data.
Canonical deletion requires explicit scope preview and confirmation and is documented in
[`docs/privacy-and-recovery.md`](docs/privacy-and-recovery.md).

## Safety model

- Raw operator evidence is stored before optional model work.
- A missing reason stays `null`; Imprint never invents a WHY.
- Inferred patterns are not eligible authority until explicitly ratified.
- Imported knowledge remains in a lower-trust floor with source receipts.
- Only the configured compiler node mutates canonical state.
- Retrieval has a deterministic byte budget (32 KiB by default).
- Failures, rejects, quarantine events, and degraded modes remain visible.

Installed hook bridges bound every child process to 10 seconds. Stop capture is
fail-closed on invalid input, timeout, a missing executable, corrupt config, or
child failure because it must not claim uncaptured feedback. Session retrieval,
domain injection, and content-free health are fail-open: they return empty
context plus a visible `degraded` receipt so Claude Code can start without
mistaking the failed read for a successful one.

Read [`docs/architecture.md`](docs/architecture.md),
[`docs/ontology-contracts.md`](docs/ontology-contracts.md),
[`docs/privacy-and-recovery.md`](docs/privacy-and-recovery.md), and
[`docs/limitations-and-roadmap.md`](docs/limitations-and-roadmap.md) before using
Imprint with sensitive or regulated information.

Typed consent, observation, and outcome writes use dedicated fail-closed
commands documented in [`docs/ontology-contracts.md`](docs/ontology-contracts.md).

## Development and release verification

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev,release]'
.venv/bin/python -m pytest
.venv/bin/python tools/release/package.py
```

Artifact acceptance runs from extracted archives, not the checkout. CI includes
`windows-latest`; PowerShell parsing on macOS is not treated as Windows proof.

## License and security

Imprint is available under the [MIT License](LICENSE). Never attach a live bank,
database, spool, export, or config to a public issue. See [SECURITY.md](SECURITY.md).
