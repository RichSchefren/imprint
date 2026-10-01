# Changelog

## 3.2.0 — 2026-09-20

- Add an optional, fail-open Jev relevance selector; deterministic offline retrieval remains the default.
- Apply domain, authority, provenance and partition eligibility before sending candidates to Jev. Preserve audit provenance and accurate selection metadata for full-size selections.
- Select unseen records on prompt hooks, including prompts without a matching domain, and reset delivery tracking after host context resets.
- Rebuild offline installers for 3.2.0 and preserve supported 3.1.1/3.1.2 upgrade ownership.

## 3.1.2 — 2026-08-10

- Fix the Windows installer writing `config.json` with a UTF-8 BOM under Windows
  PowerShell 5.1, which failed the version-check gate as a corrupt config and
  rolled the whole install back (#1).
- Fix the Windows installer aborting an upgrade that has an existing config
  under Windows PowerShell 5.1, which has no `ConvertFrom-Json -AsHashtable`.
- Tolerate a leading BOM when loading config, so a config written by any other
  Windows tool is not reported as corrupt.
- Fix private-state ACL hardening failing on Windows PowerShell 5.1, which broke
  `imprint health` and every hook on a stock Windows 11 machine unless
  PowerShell 7 was installed. PowerShell 7 is no longer required anywhere (#2).
- Name the PowerShell host and the `IMPRINT_ACCEPTANCE_DEBUG` switch in the
  Windows ACL failure message instead of failing opaquely.
- Add `hook_timeout_seconds` config and the `IMPRINT_HOOK_TIMEOUT_SECONDS`
  environment override, bounded to 1–300, defaulting to 60 on Windows where cold
  start regularly exceeded the previously hard-coded 10-second watchdog. Hook
  timeout output now reports the action and the deadline that was applied (#4).
- Report `spool_stale` from pending spool inputs only. An acknowledged,
  hash-verified copy that retention policy requires keeping no longer degrades
  deep health. Adds `pending_spool_depth`, `oldest_pending_spool_age_seconds`,
  `acknowledged_retained_spool_depth`, and `spool_evidence`; health schema
  1.2.0 (#5).
- Add `compiler_state_label` (`idle`/`compiling`/`invalid`) and document that
  `compiler_state: absent` is an idle lock, not a missing service; document that
  `imprint log --date` is a UTC calendar date, with portable today examples (#6).
- Run the Windows install acceptance under Windows PowerShell 5.1 in CI with
  PowerShell 7 hidden, so stock-host regressions cannot ship again.

## 3.1.1 — 2026-07-18

- Removed private product-extension taxonomies from the public ontology surface.
- Replaced closed extension vocabularies with fail-closed, namespaced boundaries.
- Added recursive confidentiality scanning for source trees and nested release artifacts.
- Rebuilt public release history and artifacts from the sanitized source tree.

## 3.1.0 — 2026-07-17

- Add native human-authority enrollment, signed approval challenges, recovery,
  rotation, revocation, pairing, and durable trust checkpoints.
- Add versioned first-write ontology contracts for decisions, confidence,
  contradictions, outcomes, business entities, consent, and provenance.
- Add canonical node and edge write funnels with database-enforced authority and
  provenance floors.
- Add explicit safe SQLite recovery, live-WAL reader support, collision
  quarantine, bounded batch compilation, and O(1) retrieval generation checks.
- Add compact Case-aware retrieval, explicit audit output, compact/resume
  redelivery, analytical partitions, daily inspection, and local identity.
- Add precision-gated feedback capture and per-operator semantic deduplication.
- Preserve Stop capture fail-closed until durable spool publication is known,
  while keeping post-publication processing failures fail-open and visible.
- Add executable semantic migrations, authority-preserving JSON-LD portability,
  purge closure, signed proposal promotion, and producer-coverage reporting.
- Add offline, hash-pinned multi-platform installation inputs, deterministic
  release provenance, native platform acceptance, and protected publication.

## 3.0.1 — 2026-07-15

- Close JSON-LD import authority smuggling and preserve non-mutating dry-runs.
- Automatically compile explicit Stop-hook feedback on the authorized writer.
- Add owned cross-platform launchers and bounded installed hook bridges.
- Enforce strict configuration types before authority decisions.
- Enforce private local storage permissions and restricted Windows ACLs.
- Make health evidence inspect real queues, backups, permissions, and activity.
- Preserve opaque stable Claude session lineage without raw provider IDs.
- Make once-delivery retrieval crash-recoverable.
- Use compiler heartbeat and local process liveness for lease recovery.
- Refuse incompatible stores before DDL or ordinary writes.
- Preserve bounded feedback evidence from enormous transcripts.
- Refuse ambiguous WAL state and unsupported ontology versions before canonical writes.
- Validate backups before replacement and restore the prior live database on failed restore.
- Replay prepared retrieval after pre-output crashes and commit only after flushed delivery.
- Recover stale compiler locks conservatively and require exact canonical acknowledgements.
- Support verified in-place upgrades from 3.0.0 while preserving data and external state.
- Verify embedded release provenance, source revision, source digest, and archive equivalence.

## 3.0.0 — 2026-07-15

- Rebuilt Imprint around raw Case/Verdict evidence, mandatory provenance, and bitemporal history.
- Added a local SQLite canonical store, immutable per-node spool, bounded retrieval, JSON-LD export, ingestion floor, and explicit deletion contracts.
- Added portable installers, uninstaller, release validators, CI, and artifact acceptance.
- Kept passive observation and periodic summarization out of shipped claims.
