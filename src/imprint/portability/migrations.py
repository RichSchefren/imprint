"""Additive, idempotent SQLite migration runner."""

from __future__ import annotations

import hashlib
import re
import json
import sqlite3
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from imprint.backup import verify_backup_for_store
from imprint.constants import ONTOLOGY_SCHEMA_VERSION, STORE_SCHEMA_VERSION
from imprint.errors import ConflictError, ValidationError
from imprint.durable_io import replace_private
from imprint.ontology.schema import canonical_bytes
from imprint.store import ImprintStore
from imprint.store.service import utc_now


LEGACY_BUSINESS_NODE_TYPES = frozenset({
    "Customer", "Segment", "Problem", "Desire", "Situation", "Claim",
    "Promise", "Expectation", "Mechanism", "RequiredBehavior", "Offer",
    "Price", "Channel", "Objection", "Proof", "Intervention",
    "SupportAction", "Purchase", "Usage", "Result", "Refund", "Retention",
    "Referral",
})


@dataclass(frozen=True)
class OntologyMigration:
    """A semantic compatibility step which never rewrites preserved prose."""

    migration_id: str
    from_version: str
    to_version: str
    legacy_classification: str = "legacy_untyped"
    auto_converts_legacy: bool = False
    storage_table_changes: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "migration_id": self.migration_id,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "legacy_classification": self.legacy_classification,
            "auto_converts_legacy": self.auto_converts_legacy,
            "storage_table_changes": self.storage_table_changes,
        }


ONTOLOGY_MIGRATION_CATALOG = (
    OntologyMigration(
        migration_id="ontology-3.0.0-to-3.1.0",
        from_version="3.0.0",
        to_version="3.1.0",
    ),
    OntologyMigration(
        migration_id="ontology-3.0.1-to-3.1.0",
        from_version="3.0.1",
        to_version="3.1.0",
    ),
)


def ontology_migration_catalog() -> list[dict[str, Any]]:
    """Return the frozen, built-in semantic compatibility catalog."""
    return [item.as_dict() for item in ONTOLOGY_MIGRATION_CATALOG]


def pre_mutation_compatibility_gate(store: ImprintStore) -> dict[str, Any]:
    """Inspect schema identity through immutable SQLite before any writable open."""
    if not store.path.exists():
        return {
            "compatible": False, "status": "missing_store", "mutation_outcome": "none",
            "store_schema_version": None, "ontology_schema_version": None,
        }
    before = store.path.stat()
    sidecars = [Path(str(store.path) + suffix) for suffix in ("-wal", "-shm", "-journal")]
    if any(path.exists() for path in sidecars):
        return {
            "compatible": False, "status": "active_or_ambiguous_store",
            "mutation_outcome": "none", "store_schema_version": None,
            "ontology_schema_version": None,
        }
    connection = sqlite3.connect(
        f"{store.path.resolve(strict=True).as_uri()}?mode=ro&immutable=1", uri=True,
    )
    try:
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone() is None:
            values: dict[str, str | None] = {}
        else:
            rows = connection.execute(
                "SELECT key,value FROM meta WHERE key IN ('store_schema_version','ontology_schema_version')"
            ).fetchall()
            values = {str(key): str(value) for key, value in rows}
    except sqlite3.DatabaseError as exc:
        raise ValidationError("store compatibility metadata is unreadable") from exc
    finally:
        connection.close()
    after = store.path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
    ):
        raise ValidationError("compatibility inspection observed a concurrent mutation")
    store_version = values.get("store_schema_version")
    ontology_version = values.get("ontology_schema_version")
    path = _ontology_path(ontology_version)
    if store_version != STORE_SCHEMA_VERSION:
        status = "missing_version" if store_version is None else "unsupported_store_version"
    elif ontology_version == ONTOLOGY_SCHEMA_VERSION:
        status = "current"
    elif path:
        status = "migration_available"
    else:
        status = "missing_version" if ontology_version is None else "unsupported_ontology_version"
    return {
        "compatible": status in {"current", "migration_available"},
        "status": status, "mutation_outcome": "none",
        "store_schema_version": store_version,
        "ontology_schema_version": ontology_version,
        "migration_path": [item.as_dict() for item in path],
    }


def _ontology_path(from_version: str | None) -> list[OntologyMigration]:
    if from_version is None or from_version == ONTOLOGY_SCHEMA_VERSION:
        return []
    current = from_version
    path: list[OntologyMigration] = []
    visited: set[str] = set()
    while current != ONTOLOGY_SCHEMA_VERSION and current not in visited:
        visited.add(current)
        step = next(
            (item for item in ONTOLOGY_MIGRATION_CATALOG if item.from_version == current),
            None,
        )
        if step is None:
            return []
        path.append(step)
        current = step.to_version
    return path if current == ONTOLOGY_SCHEMA_VERSION else []


def _read_ontology_version(store: ImprintStore) -> str | None:
    """Read without backfilling meta, so a legacy missing value stays visible."""
    if not store.path.exists():
        # Historical report/verify commands create their configured local store.
        # Mutation-free compatibility and dry-run paths use the explicit gate
        # below and never call this branch for a missing path.
        store.initialize()
    with store._migration_connection(
        store_versions=frozenset({STORE_SCHEMA_VERSION}), ontology_versions=None,
    ) as conn:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
        if table is None:
            return None
        row = conn.execute(
            "SELECT value FROM meta WHERE key='ontology_schema_version'"
        ).fetchone()
    return str(row[0]) if row else None


def verify_ontology_schema(store: ImprintStore) -> dict[str, Any]:
    """Verify the store's semantic version separately from its SQLite schema."""
    version = _read_ontology_version(store)
    path = _ontology_path(version)
    if version == ONTOLOGY_SCHEMA_VERSION:
        status = "current"
    elif version is None:
        status = "missing"
    elif path:
        status = "migration_available"
    else:
        status = "unsupported"
    return {
        "status": status,
        "compatible": status == "current",
        "store_ontology_schema_version": version,
        "expected_ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "migration_path": [item.as_dict() for item in path],
    }


def _legacy_semantic_records(store: ImprintStore) -> list[dict[str, Any]]:
    """Classify opaque legacy records without interpreting or rewriting them."""
    if not store.path.exists():
        return []
    with store._migration_connection(
        store_versions=frozenset({STORE_SCHEMA_VERSION}), ontology_versions=None,
    ) as conn:
        tables = {
            str(row[0]) for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        required = {"nodes", "node_versions", "events"}
        if not required.issubset(tables):
            return []
        rows = conn.execute(
            """
            SELECT n.node_id,n.node_type,n.created_event_id,e.event_type,
                   nv.version_id
              FROM nodes n
              JOIN events e ON e.event_id=n.created_event_id
              LEFT JOIN node_versions nv
                ON nv.node_id=n.node_id AND nv.system_to IS NULL
             ORDER BY n.node_type,n.node_id
            """
        ).fetchall()

    classified = []
    for row in rows:
        node_type = str(row["node_type"])
        event_type = str(row["event_type"])
        if node_type == "FeedbackProfile":
            reason = "opaque_feedback_profile"
        elif node_type in LEGACY_BUSINESS_NODE_TYPES and event_type != "semantic_node":
            reason = "opaque_business_record"
        else:
            continue
        classified.append({
            "node_id": row["node_id"],
            "version_id": row["version_id"],
            "node_type": node_type,
            "classification": "legacy_untyped",
            "reason": reason,
            "auto_conversion": "forbidden",
            "required_action": "preserve verbatim; create new typed assertions only through evidence-backed review",
        })
    return classified


def ontology_migration_report(store: ImprintStore) -> dict[str, Any]:
    """Report version compatibility and opaque legacy records; mutate nothing."""
    verification = verify_ontology_schema(store)
    legacy = _legacy_semantic_records(store)
    return {
        "status": verification["status"],
        "verification": verification,
        "catalog": ontology_migration_catalog(),
        "legacy_policy": {
            "classification": "legacy_untyped",
            "auto_convert_profile_prose": False,
            "auto_convert_business_prose": False,
            "preserve_original_bytes": True,
        },
        "legacy_untyped_count": len(legacy),
        "legacy_untyped_records": legacy,
    }


def _migration_code_digest() -> str:
    """Pin the actual adapter source, not merely its marketing version."""
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def semantic_migration_preview(store: ImprintStore) -> dict[str, Any]:
    """Return a deterministic, mutation-free v3.0.x projection receipt."""
    before_exists = store.path.exists()
    before_stat = store.path.stat() if before_exists else None
    if not before_exists:
        gate = pre_mutation_compatibility_gate(store)
        report = {
            "verification": {
                "store_ontology_schema_version": gate["ontology_schema_version"],
                "migration_path": gate.get("migration_path", []),
            },
            "legacy_untyped_records": [],
        }
    else:
        report = ontology_migration_report(store)
    source_digest = None
    if before_exists:
        with store._migration_connection(
            store_versions=frozenset({STORE_SCHEMA_VERSION}), ontology_versions=None,
        ) as conn:
            source_digest = _logical_digest(conn)
    preview = {
        "receipt_schema_version": "imprint.migration.preview/1.0.0",
        "mode": "dry-run",
        "mutation_outcome": "none",
        "from_version": report["verification"]["store_ontology_schema_version"],
        "to_version": ONTOLOGY_SCHEMA_VERSION,
        "migration_path": report["verification"]["migration_path"],
        "migration_code_sha256": _migration_code_digest(),
        "source_logical_sha256": source_digest,
        "legacy_records": report["legacy_untyped_records"],
        "rules": {
            "original_bytes_and_ids": "preserve",
            "missing_semantics": "legacy_business_semantics_unknown",
            "invent_actor_role_consent_origin_phase_or_time": False,
            "opaque_extensions": "audit-only-quarantine",
        },
    }
    preview["receipt_sha256"] = hashlib.sha256(canonical_bytes(preview)).hexdigest()
    # Prove the dry-run path did not create or modify the database.
    if not before_exists and store.path.exists():
        raise ValidationError("migration dry-run created a database")
    if before_stat is not None:
        after = store.path.stat()
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            before_stat.st_dev, before_stat.st_ino, before_stat.st_size, before_stat.st_mtime_ns,
        ):
            raise ValidationError("migration dry-run changed the database")
    return preview


def classify_legacy_business_payload(
    *, node_type: str, payload_json: str, source_version_id: str,
) -> dict[str, Any]:
    """Pure v3.0.x adapter: preserve source and explicitly mark unknown meaning."""
    try:
        payload = json.loads(payload_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValidationError("legacy payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValidationError("legacy payload must be an object")
    raw = payload_json.encode("utf-8")
    return {
        "source_version_id": source_version_id,
        "source_payload_utf8_sha256": hashlib.sha256(raw).hexdigest(),
        "source_payload_json": payload_json,
        "legacy_node_type": node_type,
        "classification": (
            "legacy_business_semantics_unknown"
            if node_type in LEGACY_BUSINESS_NODE_TYPES else "legacy_untyped"
        ),
        "typed_projection": None,
        "authority_tier": "imported_floor",
        "retrieval": "audit-only-quarantine",
        "unknown_fields": sorted(payload),
        "invented_fields": [],
    }


def apply_semantic_migration(
    store: ImprintStore, *, backup_path: Path,
    fault_injector: Any | None = None,
) -> dict[str, Any]:
    """Apply the additive semantic-version projection through a staged DB.

    The live database is never opened writable. A verified exact backup is
    copied to a same-directory candidate; only a fully committed, integrity-
    checked candidate is durably swapped into place. Any pre-publication
    failure therefore leaves the original physical file byte-for-byte intact.
    """
    gate = pre_mutation_compatibility_gate(store)
    if gate["status"] == "current":
        with store._migration_connection(
            store_versions=frozenset({STORE_SCHEMA_VERSION}), ontology_versions=None,
        ) as conn:
            row = conn.execute(
                "SELECT * FROM migrations WHERE migration_id LIKE 'ontology-%-to-3.1.0' ORDER BY applied_at DESC LIMIT 1"
            ).fetchone()
        return {
            "status": "already-applied", "mutation_outcome": "none",
            "migration_id": row["migration_id"] if row else None,
            "code_sha256": row["code_sha256"] if row else _migration_code_digest(),
            "result_sha256": row["result_sha256"] if row else None,
        }
    if gate["status"] != "migration_available" or len(gate["migration_path"]) != 1:
        raise ValidationError("semantic migration requires one supported v3.0.x path")
    verified = verify_backup_for_store(store, backup_path)
    if verified["ontology_schema_version"] != gate["ontology_schema_version"]:
        raise ValidationError("migration backup ontology version does not match source")
    source_conn = sqlite3.connect(
        f"{store.path.resolve(strict=True).as_uri()}?mode=ro&immutable=1", uri=True,
    )
    backup_conn = sqlite3.connect(
        f"{Path(verified['path']).resolve(strict=True).as_uri()}?mode=ro&immutable=1", uri=True,
    )
    try:
        source_digest = _logical_digest(source_conn)
        if _logical_digest(backup_conn) != source_digest:
            raise ValidationError("verified backup is not the exact migration source")
    finally:
        source_conn.close(); backup_conn.close()

    migration = gate["migration_path"][0]
    migration_id = migration["migration_id"]
    code_sha = _migration_code_digest()
    original_physical_sha = hashlib.sha256(store.path.read_bytes()).hexdigest()
    descriptor, candidate_name = tempfile.mkstemp(
        prefix=".semantic-migration-", suffix=".sqlite3", dir=store.path.parent,
    )
    Path(candidate_name).unlink(missing_ok=True)
    candidate = Path(candidate_name)
    try:
        shutil.copyfile(verified["path"], candidate)
        if fault_injector:
            fault_injector("candidate_copied")
        connection = sqlite3.connect(candidate)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT * FROM migrations WHERE migration_id=?", (migration_id,),
            ).fetchone()
            if prior is not None:
                if prior["code_sha256"] != code_sha:
                    raise ConflictError("migration ID was reused with different code")
                connection.rollback()
                return {
                    "status": "already-applied", "mutation_outcome": "none",
                    "migration_id": migration_id, "code_sha256": code_sha,
                    "result_sha256": prior["result_sha256"],
                }
            connection.execute(
                "UPDATE meta SET value=? WHERE key='ontology_schema_version'",
                (ONTOLOGY_SCHEMA_VERSION,),
            )
            result_sha = _logical_digest(connection)
            applied_at = utc_now()
            connection.execute(
                "INSERT INTO migrations VALUES(?,?,?,?,?,?,?)",
                (migration_id, migration["from_version"], migration["to_version"],
                 code_sha, applied_at, f"sha256:{verified['sha256']}", result_sha),
            )
            connection.commit()
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValidationError("semantic migration candidate integrity failed")
        finally:
            connection.close()
        if fault_injector:
            fault_injector("candidate_committed")
        if hashlib.sha256(store.path.read_bytes()).hexdigest() != original_physical_sha:
            raise ValidationError("live store changed during staged semantic migration")
        replace_private(store.path, candidate.read_bytes())
        store._compatibility_verified = False
        return {
            "status": "applied", "mutation_outcome": "committed",
            "migration_id": migration_id, "code_sha256": code_sha,
            "source_logical_sha256": source_digest, "result_sha256": result_sha,
            "backup_sha256": verified["sha256"], "applied_at": applied_at,
        }
    finally:
        try:
            import os
            os.close(descriptor)
        except OSError:
            pass
        candidate.unlink(missing_ok=True)


@dataclass(frozen=True)
class Migration:
    migration_id: str
    from_version: str
    to_version: str
    statements: tuple[str, ...]
    backup_receipt: str

    @property
    def code_sha256(self) -> str:
        return hashlib.sha256(canonical_bytes({
            "id": self.migration_id,
            "from": self.from_version,
            "to": self.to_version,
            "statements": self.statements,
        })).hexdigest()


class MigrationRunner:
    def __init__(self, store: ImprintStore):
        self.store = store
        self.store.initialize()
        # Targets applied by this explicit runner remain inspectable only within
        # this migration session. Ordinary store connections stay version-pinned.
        self._session_store_versions = {STORE_SCHEMA_VERSION}

    def apply(self, migration: Migration, *, approval_token=None) -> str:
        if not migration.migration_id.strip() or not migration.statements:
            raise ValidationError("migration ID and statements are required")
        additive = re.compile(
            r"^(?:CREATE\s+(?:UNIQUE\s+)?(?:TABLE|INDEX)\b|ALTER\s+TABLE\s+\S+\s+ADD\s+COLUMN\b)",
            re.IGNORECASE,
        )
        if any(not additive.match(statement.lstrip()) for statement in migration.statements):
            raise ValidationError("migration contains a non-additive statement")
        with self.store._migration_connection(
            store_versions=frozenset({
                *self._session_store_versions, migration.from_version, migration.to_version,
            }),
        ) as conn:
            conn.execute("BEGIN IMMEDIATE")
            prior = conn.execute("SELECT * FROM migrations WHERE migration_id=?", (migration.migration_id,)).fetchone()
            if prior:
                if prior["code_sha256"] != migration.code_sha256:
                    raise ConflictError("migration ID was reused with different code")
                self._session_store_versions.add(str(conn.execute(
                    "SELECT value FROM meta WHERE key='store_schema_version'"
                ).fetchone()[0]))
                return "already-applied"
            current = conn.execute("SELECT value FROM meta WHERE key='store_schema_version'").fetchone()[0]
            if current != migration.from_version:
                raise ConflictError(f"migration expects {migration.from_version}, store is {current}")
            backup_path = _backup_path(migration.backup_receipt)
            authority_options = {}
            authority_rows = int(conn.execute(
                "SELECT COUNT(*) FROM authority_ledger"
            ).fetchone()[0])
            if authority_rows:
                from imprint.authority.ledger import verify_authority_chain
                operator_id = getattr(self.store, "expected_operator_id", None)
                if not operator_id:
                    raise ValidationError("migration authority operator is required")
                local_chain = verify_authority_chain(
                    conn, expected_operator_id=operator_id,
                )
                authority_options = {
                    "expected_operator_id": operator_id,
                    "expected_store_identity": local_chain["store_identity"],
                    "pinned_authority_head": {
                        "sequence": local_chain["head_sequence"],
                        "event_sha256": local_chain["head_sha256"],
                    },
                }
            verified = verify_backup_for_store(
                self.store, backup_path, **authority_options,
            )
            if verified["store_schema_version"] != migration.from_version:
                raise ValidationError("verified backup schema does not match migration from_version")
            backup_conn = sqlite3.connect(backup_path)
            try:
                backup_digest = _logical_digest(backup_conn)
            finally:
                backup_conn.close()
            if backup_digest != _logical_digest(conn):
                raise ValidationError("verified backup is not an exact logical snapshot of this store")
            # Approval challenge/preparation rows are ephemeral replay-control
            # state and were intentionally excluded from the semantic/trust
            # snapshot comparison above. Signed provenance remains canonical:
            # consume only after equality is proven, in this same transaction.
            execution = self.store._consume_authority(
                conn, approval_token, command_name="migration.apply",
                purpose="apply canonical store migration",
                intent={
                    "migration_id": migration.migration_id,
                    "from_version": migration.from_version,
                    "to_version": migration.to_version,
                    "code_sha256": migration.code_sha256,
                    "backup_receipt": migration.backup_receipt,
                    "backup_semantic_sha256": backup_digest,
                },
                execution_fields={"applied_at": utc_now()},
                prior_state={"store_schema_version": current, "semantic_sha256": backup_digest},
                authority_transition="store_schema_migrated",
                subject_ids=(f"urn:imprint:migration:{migration.migration_id}",),
                scope=("store", "migration"),
            )
            canonical_receipt = f"sha256:{verified['sha256']}"
            for statement in migration.statements:
                conn.execute(statement)
            conn.execute("UPDATE meta SET value=? WHERE key='store_schema_version'", (migration.to_version,))
            schema_rows = [tuple(row) for row in conn.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type,name"
            ).fetchall()]
            result_hash = hashlib.sha256(canonical_bytes(schema_rows)).hexdigest()
            conn.execute(
                "INSERT INTO migrations VALUES(?,?,?,?,?,?,?)",
                (migration.migration_id, migration.from_version, migration.to_version,
                 migration.code_sha256, execution["applied_at"], canonical_receipt, result_hash),
            )
        self._session_store_versions.add(migration.to_version)
        return "applied"


def _backup_path(receipt_or_path: str) -> Path:
    if not isinstance(receipt_or_path, str) or not receipt_or_path.strip():
        raise ValidationError("migration requires a verified backup path or receipt path")
    supplied = Path(receipt_or_path).expanduser()
    if supplied.name.endswith(".receipt.json"):
        try:
            receipt = json.loads(supplied.resolve(strict=True).read_text(encoding="utf-8"))
            supplied = supplied.parent / receipt["file"]
        except (OSError, KeyError, json.JSONDecodeError) as exc:
            raise ValidationError("migration backup receipt path is invalid") from exc
    try:
        return supplied.resolve(strict=True)
    except OSError as exc:
        raise ValidationError("migration backup path does not exist") from exc


def _logical_digest(conn: sqlite3.Connection) -> str:
    # These two tables are short-lived replay-control state.  Excluding them
    # prevents preparing/approving the exact migration from invalidating the
    # backup it names. Authority keys, ledger, and signed provenance remain in
    # the digest and therefore cannot be silently ignored or rolled back.
    ephemeral = {"authority_challenges", "authority_prepared_mutations"}
    tables = [
        str(row[0]) for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall() if str(row[0]) not in ephemeral
    ]
    snapshot = []
    for table in tables:
        columns = [str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table}")').fetchall()]
        rows = []
        for row in conn.execute(f'SELECT * FROM "{table}"').fetchall():
            values = [value.hex() if isinstance(value, bytes) else value for value in row]
            rows.append(values)
        rows.sort(key=canonical_bytes)
        snapshot.append({"table": table, "columns": columns, "rows": rows})
    return hashlib.sha256(canonical_bytes(snapshot)).hexdigest()
