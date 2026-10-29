# Compiler lease fencing: design note

Status: proposal. No code changes yet.
Date: 2026-10-28
Related: branch `fix/windows-lease-recovery` (Windows hotfix for 3.1.2), Codex adversarial reviews of 8f1f058 and cab82ce (findings 1 and 2, deferred).

## Summary

The compiler lease (`compiler.lock/owner.json`) decides which process may compile. Nothing ties the store's writes to that lease. A compiler checks that it still owns the lease only at each 30-second heartbeat. If another process takes the lease between checks, the old compiler keeps writing until its next heartbeat fails.

This note proposes a fence counter in the store's `meta` table. Each new lease holder increments the counter. Each canonical write checks the counter inside the same SQLite transaction as the write, so a writer that lost its lease can't commit.

The work is one PR of roughly 300 to 500 lines, about half of them tests. It doesn't belong in the 3.1.2 hotfix.

## Problem

### How a compiler can lose its lease while it runs

After the Windows hotfix, a live compiler loses its lease only in these cases:

- **Manual recovery of a live writer.** An operator runs `imprint compile --recover-stale-lock <NONCE>` on a lease whose heartbeat is more than 300 seconds old. Recovery refuses a lease whose owner is alive on the same host. It can't check an owner on another host, or in a separate PID namespace such as a container or sandbox.
- **A stalled writer.** A compiler stops for more than 300 seconds (for example, a suspended laptop or a stopped VM), someone recovers its lease by hand, and the compiler then resumes.
- **The watchdog path.** The watchdog marks the lease abandoned and then calls `os._exit` at once. Auto-reclaim waits 10 seconds (`ABANDON_GRACE_SECONDS`). This window is closed in practice, but it relies on timing.

3.1.2 has the same gap, and it opens more often there, because the original watchdog leak left leases behind.

### What the store already protects

- `apply_capture_batch` commits each group of up to 100 captures under `BEGIN IMMEDIATE`, with savepoints. SQLite lets one writer commit at a time.
- `consumed_inputs` (`input_event_id` primary key, `payload_sha256`) makes capture replays idempotent. When two compilers apply the same input, one of them gets `duplicate`.
- File-side writes are deterministic:
  - `_write_acknowledgement` checks earlier content (`matches_prior`).
  - `_quarantine_receipt` decides by file content.
  - `prune_acknowledged_spools` removes only spool files that are acknowledged and past retention.

Two compilers on the same spool therefore converge on the same store. Fencing is still worth doing, for these reasons:

- `store.initialize()` and schema migrations aren't idempotent in the same way. Two processes that migrate at once is the worst case.
- Future write paths can assume a single writer without anyone noticing that the assumption is unenforced.
- Correctness today depends on idempotency in several places. A fence makes it depend on one check.

## Proposal

### 1. Fence counter

- Add a `compiler_fence` row to `meta`. Store the value as a decimal integer string, as `content_generation` does.
- When a compiler publishes its lease, it opens a `BEGIN IMMEDIATE` transaction, reads the fence, increments it, and commits.
- The compiler records the new value in `owner.json` as `fence` and keeps it in memory.
- If the row is missing, the first compiler inserts it with the value `1`.

Using `meta` avoids a new table. See "Open questions" for whether it still needs a store schema version bump.

### 2. Fenced database writes

- Add a helper, for example `_assert_fence(conn, expected)`, that reads `compiler_fence` and raises `SafetyError("compiler lease lost: fence ...")` on a mismatch.
- Call it right after `BEGIN IMMEDIATE` in each `apply_capture_batch` group, before any insert. SQLite holds the write lock from that point, so the check and the commit are atomic. A writer with a stale fence rolls back and commits nothing.
- Pass the fence into `apply_capture_batch` as an optional argument. Callers outside the compiler (tests, tools) pass nothing and stay unfenced. This keeps the change local to the compile path.
- Call the helper in the compile path's `initialize` and migration transactions.

### 3. Narrowed file-side writes

Files aren't transactional, so these can't be fenced atomically.

- Check the fence (one read in a short transaction) right before each acknowledgement, quarantine, and prune write.
- Rely on the existing idempotency for the window between the check and the write.
- Document that file-side writes are narrowed, not fenced.

### 4. Heartbeat

- The heartbeat also reads the fence. A mismatch raises the same "lease lost" error as a nonce mismatch does now.
- This catches a lost lease within 30 seconds even when no capture group runs.

### 5. Restore and import

These paths can move the fence backward, which would let a stale writer pass the check.

- **Backup restore** (`backup.restore_backup`) copies a whole database file into place. It doesn't take `compiler.lock` today. A compiler opens a new connection for each operation, so its next group writes into the restored file and reads the restored fence. If that value equals the compiler's own fence, the check passes.
- **Portable import** (`portability/jsonld.py`, `_insert_portable_ledger`) runs `DELETE FROM meta` and then inserts the source store's `meta` rows. It would copy the source store's fence, and it restores only `content_generation` afterward.

Proposed rules:

- Keep a fence high-water mark outside the database, in `compiler.lock/../fence-hwm` or a similar private file under the operator root. Each compiler writes its fence there when it takes the lease.
- After a restore or import, set `compiler_fence` to the high-water mark plus 1 in the same transaction that finishes the restore or import.
- Exclude `compiler_fence` from portable export, or ignore it on import.
- Separately, decide whether restore should take `compiler.lock` (or refuse while a live lease exists). That closes the restore-during-compile case more directly than the fence does.

### 6. Mixed versions

A 3.1.2 compiler ignores the fence. A store that an old install and a new install both write to stays unfenced for the old writer. Options:

- Document it in the release notes. This is the minimum.
- Bump the store schema version so 3.1.2 refuses to open a fenced store. This is stronger, but it forces the upgrade on every install that shares the store.

## Files

| File | Change |
|---|---|
| `src/imprint/compiler/spool.py` | Increment the fence when the lease is published, record it in `owner.json`, check it in the heartbeat and before file-side writes, write the high-water mark. |
| `src/imprint/store/service.py` | `_assert_fence`, the optional fence argument on `apply_capture_batch`, the fenced `initialize` path. |
| `src/imprint/store/schema.py` | Possibly an `INSERT OR IGNORE` seed row for `compiler_fence`. |
| `src/imprint/backup.py` | Raise the fence after restore. Possibly take or check `compiler.lock`. |
| `src/imprint/portability/jsonld.py` | Exclude or reset `compiler_fence` on export and import. |
| `src/imprint/health/` | Report the fence value and the high-water mark. Flag a fence below the mark. |
| `tests/adversarial/` | New tests. See the next section. |

## Tests

- Two compilers with a forced lease handover between capture groups. The old compiler's next group rolls back and commits nothing.
- A compiler that resumes after manual recovery. Its heartbeat or next group fails with "lease lost".
- A fence after backup restore, and after portable import. The fence ends above every value issued before.
- A migration racing a compile. Only the fence holder commits.
- File-side writes after a lost lease. The fence check stops them before the write.
- Mixed versions, if the schema version changes. 3.1.2 refuses the fenced store.
- The existing invariants still hold, including `test_fresh_heartbeat_protects_old_lease`.

## Open questions

1. **Schema version.** Does a new `meta` key need a `STORE_SCHEMA_VERSION` bump from "3.0.0"? `backup.py`, `cli.py`, `health`, and `portability/migrations.py` read specific keys by name. I found no code that rejects unknown keys. Portable export includes all `meta` rows, so the key would change export content unless it's excluded.
2. **Writers outside compile.** The authority service, feedback, and backup restore write to the store without taking `compiler.lock`. Fencing only compile matches today's design. Restore during a compile needs its own decision (see section 5).
3. **Release target.** If the change needs a schema bump, ship it in 3.2. `jev-selector-3.2` is the open release branch. If it doesn't, a 3.1.x patch is possible.

## Estimate

- About 2 to 4 days for one engineer.
- About half a day with Claude Code, plus a careful review and a Codex adversarial pass.
- The store code is the risky part. `service.py` is about 4,000 lines and enforces strict compatibility checks.
