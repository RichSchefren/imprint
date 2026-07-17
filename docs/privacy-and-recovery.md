# Privacy, Cost, and Recovery

## Data boundary

Imprint stores captured words, nearby case context, alternatives, provenance,
and derived records on the local machine. That material can reveal strategy,
preferences, clients, confidential work, or personal information. Treat the data
root, SQLite database, spool, projections, JSON-LD exports, and settings backups
as sensitive.

The core release sends no telemetry and makes no network request. It has no model
dependency. If a future or optional adapter is enabled, its provider receives the
content explicitly sent to it and may charge usage fees under that provider's
terms. No optional adapter is enabled by installation.

Explicit local judgment capture is the only consent-exempt source. Transcripts,
conversation imports, Screenpipe, financial records, behavioral telemetry,
business systems, customer results, and external connectors are denied by
default. A typed `ConsentGrant` must authorize the source, purpose, operation,
sensitivity, retention rule, and effective interval before an Observation or
Outcome can enter the canonical store. Revocation and expiry are evaluated at
write time; they are not configuration comments.

## Permissions and disk protection

Use a private OS account and full-disk encryption. Do not put the data root in a
public repository, support ticket, cloud-sync folder, or shared network drive.
The installer does not change broad directory permissions or grant another user
access. Your OS defaults still apply; inspect them if the machine is shared.

## Backup

Create and verify a transactionally consistent backup with:

```bash
imprint backup create
imprint backup verify /path/from/create.sqlite3
```

The command uses SQLite's backup interface and emits a tamper-evident receipt.
For a whole-directory disaster-recovery copy, stop active sessions and the
compiler, then copy the complete operator directory to encrypted storage.

For a portable logical snapshot:

```bash
imprint export --format jsonld --output imprint-export.jsonld
```

Protect exports like the live bank. Before upgrades, make a physical backup and
record its SHA-256. Additive migrations preserve historical versions, but a
backup is the recovery boundary for hardware loss or operator error.

## Recovery

An ordinary SQLite backup deliberately contains no authority private-key blob.
Create the separate signed, encrypted recovery package from a native terminal
and store it offline, apart from the machine and ordinary backups:

```bash
imprint authority enroll --recovery-output /offline/imprint-authority-recovery.json
```

Recovery can instead be explicitly declined at first enrollment. A later
`recovery-create` ceremony publishes a replacement bundle before committing its
ledger activation. If publication is interrupted, authority writes remain
blocked behind the retained journal until `authority recovery-reconcile` is
confirmed at a native terminal; the external artifact is never silently deleted.

The recovery passphrase must be different from the machine authority
passphrase. The long-lived package has a closed canonical manifest, an explicit
authority-ledger genesis hash, exact ledger and blob digests, an active-key
signature, and the immutable checkpoint history at creation. It does not expire,
but it cannot by itself establish current authority.

Before every authority-raising restore or transfer, an active installation must
create a separate physical transport containing the complete public ledger,
closed checkpoint history, and a checkpoint no more than 24 hours old:

```bash
imprint authority transport --output /offline/imprint-authority-transport.json
```

On a fresh installation with the same configured operator, restore and pair a
new, distinct machine key:

```bash
imprint authority trust-bootstrap --input /offline/imprint-authority-recovery.json
imprint authority recovery-restore \
  --input /offline/imprint-authority-recovery.json \
  --authority-transport /offline/imprint-authority-transport.json
```

For replacement after a lost machine, add
`--replace-install-id URN_OF_LOST_INSTALLATION`. Restore fails closed for a
foreign operator, wrong passphrase, altered package, stale checkpoint, lower or
forked ledger head, revoked recovery key, replay into an enrolled installation,
or a store-identity mismatch. If every active machine key and usable recovery
package is lost, Imprint cannot preserve authority; it does not invent a new
operator trust root.

An already active installation can authorize a second machine without exposing
either private key. The target creates a request from its destination-owned
recovery bootstrap; the active machine confirms and signs the exact new
installation binding; the target finalizes the returned package:

```bash
imprint authority trust-bootstrap --input /offline/imprint-authority-recovery.json
imprint authority pair-request --output /offline/pair-request.json
imprint authority pair-authorize --input /offline/pair-request.json --output /offline/pair-package.json
imprint authority pair-finalize --input /offline/pair-package.json
```

Rotate a healthy machine key and append revocation/compromise facts with:

```bash
imprint authority rotate
imprint authority revoke KEY_ID --reason "reason"
imprint authority compromise KEY_ID --reason "machine lost" \
  --recovery-bundle /offline/imprint-authority-recovery.json
imprint authority checkpoint
```

Rotation retires the prior key; retired, revoked, compromised, unpaired, and
unknown keys cannot raise authority. A compromise of the currently active key
requires the separate recovery key because a key cannot attest to its own safe
revocation. Compromise records are closed facts binding the affected
installation, effective time, optional earlier compromise boundary, evidence
digests, replacement, and required revocation. They install a persistent write
block until a retained proof is reviewed and an exact recovery-signed
`authority adjudicate` ceremony commits the human decision.

1. Stop all writers.
2. Preserve the damaged directory before attempting repair.
3. Restore the entire last known-good operator directory to a local path.
4. Point `data_root` at its parent and run `imprint health`.
5. Compare expected counts and hashes before resuming capture.

Never merge two SQLite files. Reconcile immutable spool inputs through one
compiler instead. Quarantined or corrupt inputs should remain preserved for
inspection; do not silently discard them.

Compiler acknowledgement does not delete source input. To prune this producer's
old committed inputs after the configured retention period, run `imprint spool
prune`. An input remains untouched if its acknowledgement, event identity, hash,
producer path, or retention age cannot be verified.

## Uninstall and deletion

Uninstall deliberately preserves captured data. Canonical deletion is a separate
two-step operation:

```bash
imprint delete purge --scope EXACT_NODE_OPERATOR_SESSION_OR_SOURCE_ID --preview
imprint delete purge --scope EXACT_NODE_OPERATOR_SESSION_OR_SOURCE_ID \
  --confirm EXACT_NODE_OPERATOR_SESSION_OR_SOURCE_ID
```

The second command is irreversible. It records only non-content counts, rebuilds
projections, scans the active root, and reports `purged_with_residue` with a
nonzero exit if deletion committed but content remains. Backups and exports
outside the active root are not discoverable and must be inventoried and deleted
separately. Tombstone is the normal reversible removal from current retrieval.

Revoking consent does not silently rewrite historical evidence. If a grant uses
`delete_on_revoke`, the associated source IDs must be purged through the same
explicit preview-and-confirm deletion workflow so backups, exports, and residue
can be reported honestly.
