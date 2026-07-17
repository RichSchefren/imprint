"""Deterministic canonical writer. Models never receive this authority."""

from __future__ import annotations

import json
import hashlib
import re
import sqlite3
import unicodedata
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from imprint.constants import ONTOLOGY_SCHEMA_VERSION, PRODUCT_VERSION, STORE_SCHEMA_VERSION
from imprint.errors import ConflictError, SafetyError, ValidationError
from imprint.capture.schema import validate_capture_envelope
from imprint.ontology.contracts import validate_node_contract, validate_relation_contract
from imprint.ontology.references import validate_payload_references
from imprint.ontology.schema import canonical_bytes, make_urn, payload_sha256, require_urn
from imprint.permissions import secure_directory, secure_file, secure_files
from .schema import SCHEMA_SQL


DERIVED_NODE_TYPES = frozenset({
    "Principle", "Belief", "Value", "Rule", "Pattern", "Domain", "FeedbackProfile", "Proposal",
})

_V31_SCHEMA_TYPES = {
    "imprint.node.decision-episode/1.0.0": "DecisionEpisode",
    "imprint.node.actor/1.0.0": "Actor",
    "imprint.node.role-assignment/1.0.0": "RoleAssignment",
    "imprint.node.expected-outcome/1.0.0": "ExpectedOutcome",
    "imprint.node.confidence-assessment/1.0.0": "ConfidenceAssessment",
    "imprint.node.evidence-artifact/1.0.0": "EvidenceArtifact",
    "imprint.node.access-policy/1.0.0": "AccessPolicy",
    "imprint.node.deletion-event/1.0.0": "DeletionEvent",
    "imprint.node.market/1.0.0": "Market",
    "imprint.node.positioning/1.0.0": "Positioning",
    "imprint.node.term-set/1.0.0": "TermSet",
    "imprint.node.asset/1.0.0": "Asset",
    "imprint.node.campaign/1.0.0": "Campaign",
    "imprint.node.business-event/1.1.0": "BusinessEvent",
    "imprint.node.segment/1.0.0": "Segment",
    "imprint.node.situation/1.0.0": "Situation",
    "imprint.node.required-behavior/1.0.0": "RequiredBehavior",
    "imprint.node.campaign-performance-measurement/1.1.0": "CampaignPerformanceMeasurement",
    "imprint.node.performance-disposition/1.1.0": "PerformanceDisposition",
}
_BUSINESS_SCHEMA_PARTITIONS = {
    "imprint.node.market/1.0.0": "business_declared",
    "imprint.node.positioning/1.0.0": "business_declared",
    "imprint.node.term-set/1.0.0": "business_declared",
    "imprint.node.asset/1.0.0": "business_declared",
    "imprint.node.campaign/1.0.0": "business_declared",
    "imprint.node.business-event/1.1.0": "business_observed",
    "imprint.node.segment/1.0.0": "business_declared",
    "imprint.node.situation/1.0.0": "business_declared",
    "imprint.node.required-behavior/1.0.0": "business_declared",
    "imprint.node.campaign-performance-measurement/1.1.0": "business_observed",
    "imprint.node.performance-disposition/1.1.0": "business_declared",
}
_V31_ENVELOPE_FIELDS = frozenset({
    "record_id", "version_id", "payload_schema_id", "record_schema_version",
    "ontology_schema_version", "operator_id", "payload", "provenance",
    "sensitivity", "access_policy_version_id", "consent_version_id",
    "actor_id", "role_assignment_version_id", "valid_from", "valid_to",
    "scope_id", "extensions",
})
_V31_SENSITIVITY = frozenset({
    "unclassified", "standard", "sensitive", "highly_sensitive", "restricted",
})
_CONFIDENCE_FORBIDDEN = frozenset({
    "Actor", "RoleAssignment", "AccessPolicy", "ConsentGrant", "DeletionEvent",
    "EvidenceArtifact", "ConfidenceAssessment",
})
CONSENT_CLOCK_SKEW = timedelta(seconds=120)


# Python 3.10 exposes neither ``sqlite_errorcode`` nor all SQLite result-code
# constants. These values are stable SQLite API constants; prefer the stdlib
# names when available and retain exact 3.10 behavior otherwise.
_SQLITE_IDENTITY_CONFLICTS = frozenset({
    getattr(sqlite3, "SQLITE_CONSTRAINT_PRIMARYKEY", 1555),
    getattr(sqlite3, "SQLITE_CONSTRAINT_UNIQUE", 2067),
})
_SQLITE_LOCK_CONFLICTS = frozenset({
    getattr(sqlite3, "SQLITE_BUSY", 5),
    getattr(sqlite3, "SQLITE_LOCKED", 6),
})


def _sqlite_is_identity_conflict(exc: sqlite3.IntegrityError) -> bool:
    """Recognize identity collisions on every supported Python runtime.

    Python 3.10 does not expose ``sqlite_errorcode`` or the extended-result-code
    constants. SQLite's fixed UNIQUE diagnostic is therefore the narrow legacy
    fallback; other integrity failures must continue to abort the transaction.
    """
    code = getattr(exc, "sqlite_errorcode", None)
    if code is not None:
        return code in _SQLITE_IDENTITY_CONFLICTS
    return str(exc).startswith("UNIQUE constraint failed:")


def _sqlite_is_lock_conflict(exc: sqlite3.OperationalError) -> bool:
    """Recognize SQLite lock contention without requiring Python 3.11 APIs."""
    code = getattr(exc, "sqlite_errorcode", None)
    if code is not None:
        # Extended BUSY/LOCKED codes retain the primary result in the low byte.
        return code & 0xFF in _SQLITE_LOCK_CONFLICTS
    return str(exc) in {"database is locked", "database table is locked"}


def _secure_sqlite_state(path: Path) -> None:
    """Tighten the database and every extant SQLite private-state sidecar."""
    candidates = tuple(candidate for candidate in (
        path,
        Path(str(path) + "-wal"),
        Path(str(path) + "-shm"),
        Path(str(path) + "-journal"),
    ) if candidate.exists())
    secure_files(candidates)

def version_provenance(*, status: str, authority_tier: str, actor_class: str,
                       actor_id: str, mechanism: str, event_id: str,
                       model: str | None = None, prompt_recipe: str | None = None,
                       proposal_id: str | None = None, ratifier: str | None = None,
                       relation: str | None = None) -> dict[str, Any]:
    return {
        "provenance_schema_version": "1.0.0", "status": status,
        "authority_tier": authority_tier, "actor_class": actor_class,
        "actor_id": actor_id, "mechanism": mechanism,
        "software": {"name": "imprint-local", "version": PRODUCT_VERSION},
        "model": model, "prompt_recipe": prompt_recipe,
        "proposal_id": proposal_id, "ratifier": ratifier,
        "event_id": event_id, "relation": relation,
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _feedback_content_sha256(text: str) -> str:
    """Hash normalized operator wording without retaining another text copy."""
    normalized = " ".join(unicodedata.normalize("NFKC", text).casefold().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def validate_base_version_values(values: tuple[Any, ...]) -> None:
    """Validate origin, authority, and promotion proof before base-table SQL."""
    if len(values) != 14:
        raise ValidationError("base version row must contain exactly 14 fields")
    origin, tier, provenance_json = values[4], values[5], values[6]
    allowed = {
        "captured": {"observed_candidate", "captured_judgment", "ratified_knowledge"},
        "extracted": {"imported_floor", "observed_candidate", "ratified_knowledge"},
        "inferred": {"inferred_candidate", "observed_candidate", "ratified_knowledge"},
        "ratified": {"ratified_knowledge"},
    }
    if origin not in allowed or tier not in allowed[origin]:
        raise ValidationError("base version violates origin/authority lattice")
    try:
        provenance = json.loads(provenance_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValidationError("base version provenance must be canonical JSON") from exc
    if not isinstance(provenance, dict):
        raise ValidationError("base version provenance must be an object")
    recorded_origin = provenance.get("origin_status", provenance.get("status"))
    if recorded_origin != origin or provenance.get("authority_tier") != tier:
        raise ValidationError("base version provenance disagrees with origin/authority columns")
    if tier == "ratified_knowledge" and not (
        provenance.get("ratifier") or provenance.get("ratification_event_version_id")
    ):
        raise ValidationError("ratified base version requires signed-promotion proof")


def insert_node_version(conn: sqlite3.Connection, values: tuple[Any, ...]) -> None:
    validate_base_version_values(values)
    conn.execute("INSERT INTO node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values)


def insert_edge_version(conn: sqlite3.Connection, values: tuple[Any, ...]) -> None:
    validate_base_version_values(values)
    conn.execute("INSERT INTO edge_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values)


class ImprintStore:
    def __init__(self, path: Path | str, *, expected_operator_id: str | None = None,
                 expected_node_id: str | None = None):
        self.path = Path(path)
        self.expected_operator_id = expected_operator_id
        self.expected_node_id = expected_node_id
        self._compatibility_verified = False

    def _require_configured_operator(self, operator_id: str) -> None:
        if self.expected_operator_id is not None and operator_id != self.expected_operator_id:
            raise ValidationError("operator does not match configured identity")

    def _consume_authority(
        self, conn: sqlite3.Connection, approval_token: Mapping[str, Any] | None, *,
        purpose: str, intent: Mapping[str, Any], authority_transition: str,
        command_name: str | None = None,
        execution_fields: Mapping[str, Any] | None = None,
        prior_state: Mapping[str, Any] | None = None,
        subject_ids: tuple[str, ...] = (), source_ids: tuple[str, ...] = (),
        target_ids: tuple[str, ...] = (), proposal_ids: tuple[str, ...] = (),
        result_version_ids: tuple[str, ...] = (), scope: tuple[str, ...] = (),
        field_paths: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        """Consume a signed exact-intent token in the caller's write transaction."""
        if self.expected_operator_id is None:
            raise ValidationError("authority-raising mutation requires a configured operator")
        from imprint.authority import ApprovalToken, AuthorityService, ChallengeRequest
        from imprint.authority.challenge import canonical_bytes as authority_canonical_bytes, sha256_hex
        from imprint.authority.ledger import (
            load_prepared_mutation, mark_prepared_executed, prepare_mutation,
        )

        token = ApprovalToken.from_dict(approval_token) if approval_token is not None else None
        operation_id = token.challenge["operation_id"] if token else make_urn("operation")
        execution = dict(execution_fields or {})

        def generated_versions(
            value: Any, field: str = "", *, inside_version_container: bool = False,
        ) -> list[str]:
            found: list[str] = []
            is_version_field = inside_version_container or field.endswith("version_id") or field.endswith("version_ids")
            if isinstance(value, Mapping):
                for name, child in value.items():
                    found.extend(generated_versions(
                        child, str(name), inside_version_container=is_version_field,
                    ))
            elif isinstance(value, (list, tuple)):
                for child in value:
                    found.extend(generated_versions(
                        child, field, inside_version_container=is_version_field,
                    ))
            elif isinstance(value, str) and is_version_field:
                found.append(value)
            return found

        bound_result_versions = tuple(dict.fromkeys((*result_version_ids, *generated_versions(execution))))
        execution_sha256 = sha256_hex(authority_canonical_bytes(execution))
        request = ChallengeRequest(
            operation_id=operation_id, purpose=purpose,
            payload_sha256=payload_sha256(dict(intent)),
            prior_state_sha256=payload_sha256(dict(prior_state or {})),
            execution_fields_sha256=execution_sha256,
            authority_transition=authority_transition,
            subject_ids=subject_ids, source_ids=source_ids, target_ids=target_ids,
            proposal_ids=proposal_ids, result_version_ids=bound_result_versions,
            scope=scope, field_paths=field_paths,
        )
        command = command_name or purpose
        prior = dict(prior_state or {})
        if token is None:
            prepared = prepare_mutation(
                conn, command_name=command, request=request, intent=dict(intent),
                prior_state=prior, execution_fields=execution,
                operator_id=self.expected_operator_id,
            )
            # This transaction contains only the prepared intent. Commit it so
            # the caller can sign and retry; every semantic write follows this
            # guard and therefore has not occurred yet.
            conn.commit()
            raise ValidationError(
                "E_AUTH_APPROVAL_REQUIRED approval_request="
                + canonical_bytes(prepared["request"]).decode("utf-8")
            )
        prepared = load_prepared_mutation(
            conn, operation_id=operation_id, command_name=command,
            intent=dict(intent), prior_state=prior,
            operator_id=self.expected_operator_id,
        )
        stored = prepared["request"]
        expected = ChallengeRequest(
            operation_id=stored["operation_id"], purpose=stored["purpose"],
            payload_sha256=stored["payload_sha256"],
            prior_state_sha256=stored["prior_state_sha256"],
            execution_fields_sha256=stored["execution_fields_sha256"],
            authority_transition=stored["authority_transition"],
            subject_ids=tuple(stored["subject_ids"]), source_ids=tuple(stored["source_ids"]),
            target_ids=tuple(stored["target_ids"]), proposal_ids=tuple(stored["proposal_ids"]),
            result_version_ids=tuple(stored["result_version_ids"]),
            scope=tuple(stored["scope"]), field_paths=tuple(stored["field_paths"]),
        )
        provenance_id = AuthorityService(
            self.path.parent, self, operator_id=self.expected_operator_id,
        ).verify_and_consume(conn, token, expected=expected)
        mark_prepared_executed(
            conn, operation_id=operation_id, provenance_id=provenance_id,
        )
        return dict(prepared["execution_fields"])

    def initialize(self) -> None:
        existing = self.path.exists()
        secure_directory(self.path.parent)
        try:
            if existing:
                context = self.connect()
            else:
                @contextmanager
                def new_store_connection():
                    conn = sqlite3.connect(self.path, timeout=30)
                    try:
                        _secure_sqlite_state(self.path)
                        yield conn
                        conn.commit()
                    except Exception:
                        conn.rollback()
                        raise
                    finally:
                        conn.close()
                        _secure_sqlite_state(self.path)
                context = new_store_connection()
            with context as conn:
                conn.executescript(SCHEMA_SQL)
                conn.execute(
                    "INSERT OR IGNORE INTO meta(key,value) VALUES('store_schema_version',?)",
                    (STORE_SCHEMA_VERSION,),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO meta(key,value) VALUES('ontology_schema_version',?)",
                    (ONTOLOGY_SCHEMA_VERSION,),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO meta(key,value) VALUES('store_identity',?)",
                    (make_urn("store"),),
                )
                # Upgrade-safe backfill: existing Verdicts participate in
                # content dedup immediately after this schema is adopted.
                for row in conn.execute(
                    """SELECT n.operator_id,n.created_event_id,nv.payload_json,nv.valid_from
                       FROM nodes n JOIN node_versions nv USING(node_id)
                       WHERE n.node_type='Verdict' AND nv.system_to IS NULL
                       ORDER BY nv.system_from,n.node_id"""
                ):
                    try:
                        payload = json.loads(row[2])
                        text = payload["raw_operator_text"]
                    except (json.JSONDecodeError, KeyError, TypeError):
                        continue
                    if not isinstance(text, str) or not text.strip():
                        continue
                    conn.execute(
                        """INSERT OR IGNORE INTO captured_feedback_dedup
                           (operator_id,content_sha256,first_event_id,first_captured_at)
                           VALUES(?,?,?,?)""",
                        (row[0], _feedback_content_sha256(text), row[1], row[3]),
                    )
            _secure_sqlite_state(self.path)
            self._compatibility_verified = True
        except Exception:
            self._compatibility_verified = False
            raise

    def recover(self) -> dict[str, Any]:
        """Replay and checkpoint crash-resident SQLite state without deleting it.

        Recovery deliberately bypasses :meth:`connect`, whose normal fail-closed
        contract rejects sidecars.  SQLite remains the only component allowed to
        interpret or retire WAL state.  Exclusive locking distinguishes abandoned
        crash residue from a live reader/writer and prevents a checkpoint race.
        """
        if not self.path.exists():
            raise ValidationError("store does not exist")
        if self.path.is_symlink():
            raise ValidationError("store path must be a regular non-symlink file")
        try:
            resolved = self.path.resolve(strict=True)
            before = resolved.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValidationError("store is unreadable") from exc
        if not resolved.is_file():
            raise ValidationError("store path must be a regular non-symlink file")

        sidecars = tuple(
            Path(str(resolved) + suffix) for suffix in ("-wal", "-shm", "-journal")
        )
        for sidecar in sidecars:
            if sidecar.exists() and (sidecar.is_symlink() or not sidecar.is_file()):
                raise SafetyError("SQLite recovery sidecar is not a regular non-symlink file")
        wal = Path(str(resolved) + "-wal")
        wal_bytes_before = wal.stat(follow_symlinks=False).st_size if wal.exists() else 0
        _secure_sqlite_state(resolved)

        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(
                f"{resolved.as_uri()}?mode=rw", uri=True, timeout=0,
                isolation_level=None,
            )
            conn.execute("PRAGMA busy_timeout=0")
            conn.execute("PRAGMA locking_mode=EXCLUSIVE")
            try:
                conn.execute("BEGIN EXCLUSIVE")
            except sqlite3.OperationalError as exc:
                if _sqlite_is_lock_conflict(exc):
                    raise SafetyError(
                        "store recovery refused because a live SQLite connection holds the store"
                    ) from exc
                raise
            self._require_connection_compatible(conn)
            integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
            if integrity != "ok":
                raise ValidationError(f"store integrity check failed: {integrity}")
            conn.execute("COMMIT")
            busy, frames, checkpointed = conn.execute(
                "PRAGMA wal_checkpoint(TRUNCATE)"
            ).fetchone()
            if busy or checkpointed < frames:
                raise SafetyError(
                    "store recovery refused because live SQLite activity prevented a full checkpoint"
                )
            post_integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
            if post_integrity != "ok":
                raise ValidationError(f"store integrity check failed after recovery: {post_integrity}")
            # SQLite first proves every WAL frame checkpointed and switches the
            # database to DELETE mode. Only after this succeeds can leftover
            # zero-data coordination files be retired safely below.
            if str(conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0]).lower() != "delete":
                raise SafetyError("SQLite refused to retire recovered WAL state")
        except (SafetyError, ValidationError):
            raise
        except sqlite3.DatabaseError as exc:
            raise ValidationError("store recovery failed; SQLite state is corrupt or unreadable") from exc
        finally:
            if conn is not None:
                try:
                    if conn.in_transaction:
                        conn.rollback()
                finally:
                    conn.close()
            _secure_sqlite_state(resolved)

        # Some SQLite builds leave the shared-memory coordination file after a
        # successful DELETE-mode transition. It contains no canonical frames;
        # remove it only after the exclusive checkpoint proof above. A nonempty
        # WAL at this point is a failed recovery, never cleanup residue.
        retired_wal = Path(str(resolved) + "-wal")
        retired_shm = Path(str(resolved) + "-shm")
        if retired_wal.exists() and retired_wal.stat(follow_symlinks=False).st_size:
            raise SafetyError("store recovery left nonempty WAL state")
        for retired in (retired_wal, retired_shm):
            if retired.exists():
                if retired.is_symlink() or not retired.is_file():
                    raise SafetyError("recovered SQLite residue is not a regular file")
                retired.unlink()

        try:
            after = self.path.resolve(strict=True).stat(follow_symlinks=False)
        except OSError as exc:
            raise ValidationError("store path changed during recovery") from exc
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValidationError("store path changed during recovery")
        self._compatibility_verified = True
        return {
            "status": "recovered" if wal_bytes_before else "clean",
            "wal_bytes_before": wal_bytes_before,
            "checkpoint_busy": int(busy),
            "checkpoint_frames": int(frames),
            "checkpointed_frames": int(checkpointed),
            "integrity": post_integrity,
        }

    @staticmethod
    def _require_connection_compatible(
        conn: sqlite3.Connection, *,
        store_versions: frozenset[str] = frozenset({STORE_SCHEMA_VERSION}),
        ontology_versions: frozenset[str] | None = frozenset({ONTOLOGY_SCHEMA_VERSION}),
    ) -> None:
        """Validate the exact open database handle before any mutable PRAGMA or DDL."""
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
        if table is None:
            raise ValidationError("existing store is missing schema metadata")
        row = conn.execute(
            "SELECT value FROM meta WHERE key='store_schema_version'"
        ).fetchone()
        if row is None:
            raise ValidationError("existing store is missing store_schema_version")
        if not isinstance(row[0], str) or row[0] not in store_versions:
            raise ValidationError(
                f"incompatible store schema {row[0]!r}; expected one of {sorted(store_versions)}"
            )
        ontology = conn.execute(
            "SELECT value FROM meta WHERE key='ontology_schema_version'"
        ).fetchone()
        if ontology is None:
            raise ValidationError("existing store is missing ontology_schema_version")
        if (
            not isinstance(ontology[0], str)
            or (ontology_versions is not None and ontology[0] not in ontology_versions)
        ):
            raise ValidationError(
                f"incompatible ontology schema {ontology[0]!r}"
            )

    def _require_existing_store_compatible(
        self, *,
        store_versions: frozenset[str] = frozenset({STORE_SCHEMA_VERSION}),
        ontology_versions: frozenset[str] | None = frozenset({ONTOLOGY_SCHEMA_VERSION}),
    ) -> tuple[int, int]:
        """Inspect an existing database through SQLite's WAL-aware read path."""
        try:
            resolved = self.path.resolve(strict=True)
            if not resolved.is_file() or self.path.is_symlink():
                raise ValidationError("store path must be a regular non-symlink file")
            before = resolved.stat(follow_symlinks=False)
            wal = Path(str(resolved) + "-wal")
            shm = Path(str(resolved) + "-shm")
            if wal.exists() or shm.exists():
                clean_reader_residue = False
                try:
                    if (
                        wal.is_file() and not wal.is_symlink() and wal.stat().st_size == 0
                        and shm.is_file() and not shm.is_symlink()
                    ):
                        raw = shm.read_bytes()
                        header = raw[:48]
                        duplicate = raw[48:96]
                        version = int.from_bytes(header[:4], byteorder="little")
                        mx_frame = int.from_bytes(header[16:20], byteorder="little")
                        clean_reader_residue = (
                            len(raw) >= 32768 and len(raw) % 32768 == 0
                            and len(header) == 48 and header == duplicate
                            and version == 3007000 and header[12] in {0, 1}
                            and mx_frame == 0
                        )
                except OSError:
                    clean_reader_residue = False
                if not clean_reader_residue:
                    raise ValidationError(
                        "store has ambiguous or crash-resident WAL/SHM state; run explicit store recover"
                    )
            # Never use immutable=1 here: committed records may live in a
            # legitimate zero-frame reader residue. Non-empty/ambiguous state
            # is rejected above so only explicit recovery may replay it.
            uri = f"{resolved.as_uri()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=5)
            try:
                self._require_connection_compatible(
                    conn, store_versions=store_versions,
                    ontology_versions=ontology_versions,
                )
            finally:
                conn.close()
            after = resolved.stat(follow_symlinks=False)
            identity = (before.st_dev, before.st_ino)
            if identity != (after.st_dev, after.st_ino):
                raise ValidationError("store path changed during compatibility validation")
            return identity
        except ValidationError:
            raise
        except (OSError, sqlite3.DatabaseError) as exc:
            raise ValidationError("existing store is corrupt or unreadable") from exc

    @contextmanager
    def connect(self):
        if not self.path.exists():
            raise ValidationError("store must be initialized before use")
        identity = self._require_existing_store_compatible()
        try:
            resolved = self.path.resolve(strict=True)
            conn = sqlite3.connect(
                f"{resolved.as_uri()}?mode=rw", uri=True, timeout=30,
            )
            _secure_sqlite_state(resolved)
        except (OSError, sqlite3.DatabaseError) as exc:
            raise ValidationError("store changed before connection") from exc
        try:
            self._require_connection_compatible(conn)
            current = self.path.resolve(strict=True).stat(follow_symlinks=False)
            if identity != (current.st_dev, current.st_ino):
                raise ValidationError("store path changed before connection")
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
            committed_path = self.path.resolve(strict=True).stat(follow_symlinks=False)
            if identity != (committed_path.st_dev, committed_path.st_ino):
                raise ValidationError("store path changed before commit")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
            try:
                if self.path.exists():
                    current_path = self.path.resolve(strict=True)
                    current = current_path.stat(follow_symlinks=False)
                    if identity == (current.st_dev, current.st_ino):
                        _secure_sqlite_state(current_path)
            except OSError:
                # This is a best-effort post-close recheck. The transaction has
                # already committed (or its original exception is in flight),
                # so a disappearing path must not falsify that outcome.
                pass

    @contextmanager
    def _migration_connection(
        self, *, store_versions: frozenset[str],
        ontology_versions: frozenset[str] | None = frozenset({ONTOLOGY_SCHEMA_VERSION}),
    ):
        """Restricted compatibility exception for explicit migration code only.

        Canonical writers never call this path; their ordinary ``connect``
        remains pinned to the current store and ontology contracts.
        """
        if not store_versions or any(not isinstance(item, str) or not item for item in store_versions):
            raise ValidationError("migration store versions are invalid")
        identity = self._require_existing_store_compatible(
            store_versions=store_versions, ontology_versions=ontology_versions,
        )
        resolved = self.path.resolve(strict=True)
        conn = sqlite3.connect(f"{resolved.as_uri()}?mode=rw", uri=True, timeout=30)
        try:
            _secure_sqlite_state(resolved)
            self._require_connection_compatible(
                conn, store_versions=store_versions,
                ontology_versions=ontology_versions,
            )
            current = self.path.resolve(strict=True).stat(follow_symlinks=False)
            if identity != (current.st_dev, current.st_ino):
                raise ValidationError("store path changed before migration connection")
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
            committed_path = self.path.resolve(strict=True).stat(follow_symlinks=False)
            if identity != (committed_path.st_dev, committed_path.st_ino):
                raise ValidationError("store path changed before migration commit")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
            try:
                if self.path.exists():
                    current_path = self.path.resolve(strict=True)
                    current = current_path.stat(follow_symlinks=False)
                    if identity == (current.st_dev, current.st_ino):
                        _secure_sqlite_state(current_path)
            except OSError:
                pass

    @contextmanager
    def read_connection(self):
        """Open a genuine concurrent reader without ignoring committed WAL data."""
        if not self.path.exists():
            raise ValidationError("store must be initialized before use")
        try:
            resolved = self.path.resolve(strict=True)
            if not resolved.is_file() or self.path.is_symlink():
                raise ValidationError("store path must be a regular non-symlink file")
            before = resolved.stat(follow_symlinks=False)
            identity = (before.st_dev, before.st_ino)
            # Deliberately omit immutable=1: live committed state may reside in
            # the WAL while the single writer remains open.
            conn = sqlite3.connect(
                f"{resolved.as_uri()}?mode=ro", uri=True, timeout=5,
            )
            # A genuine WAL-mode reader can create or reopen the WAL/SHM
            # sidecars even though the database URI is read-only.  Apply the
            # exact leaf ACLs after SQLite has materialized that state, just as
            # the writer connection does.
            _secure_sqlite_state(resolved)
        except ValidationError:
            raise
        except (OSError, sqlite3.DatabaseError) as exc:
            raise ValidationError("store changed before read connection") from exc
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA foreign_keys=ON")
            self._require_connection_compatible(conn)
            current = self.path.resolve(strict=True).stat(follow_symlinks=False)
            if identity != (current.st_dev, current.st_ino):
                raise ValidationError("store path changed before read connection")
            yield conn
            after = self.path.resolve(strict=True).stat(follow_symlinks=False)
            if identity != (after.st_dev, after.st_ino):
                raise ValidationError("store path changed during read")
        except (OSError, sqlite3.DatabaseError) as exc:
            raise ValidationError("store changed or became unreadable during read") from exc
        finally:
            conn.close()
            try:
                if self.path.exists():
                    current_path = self.path.resolve(strict=True)
                    current = current_path.stat(follow_symlinks=False)
                    if identity == (current.st_dev, current.st_ino):
                        _secure_sqlite_state(current_path)
            except OSError:
                # Preserve the read result or its original exception if the
                # store disappears after the SQLite handle is closed.
                pass

    def integrity_check(self) -> str:
        with self.read_connection() as conn:
            return str(conn.execute("PRAGMA integrity_check").fetchone()[0])

    def retrieval_generation(self) -> tuple[str, int]:
        """Return O(1) cross-store identity for retrieval delivery receipts."""
        with self.read_connection() as conn:
            rows = dict(conn.execute(
                "SELECT key,value FROM meta WHERE key IN ('store_identity','content_generation')"
            ).fetchall())
        identity = rows.get("store_identity")
        generation = rows.get("content_generation")
        if not isinstance(identity, str) or not identity.startswith("urn:imprint:store:"):
            raise ValidationError("store identity metadata is missing or invalid")
        try:
            parsed_generation = int(generation)
        except (TypeError, ValueError) as exc:
            raise ValidationError("content generation metadata is missing or invalid") from exc
        if parsed_generation < 0 or str(parsed_generation) != generation:
            raise ValidationError("content generation metadata is missing or invalid")
        return identity, parsed_generation

    def apply_capture(self, envelope: dict[str, Any], *, source_path: str = "direct") -> str:
        """Apply one capture with the same connection-bound primitive used by batches."""
        try:
            with self.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                return self._apply_capture_on_connection(
                    conn, envelope, source_path=source_path,
                )
        except sqlite3.IntegrityError as exc:
            if _sqlite_is_identity_conflict(exc):
                raise ConflictError(
                    "capture conflicts with an existing canonical node, version, edge, or event identity"
                ) from exc
            raise

    def apply_capture_batch(
        self, items: list[tuple[dict[str, Any], str]], *, batch_size: int = 100,
    ) -> list[str | ValidationError | ConflictError]:
        """Apply captures through one connection, committing in bounded groups.

        Expected content conflicts are isolated with savepoints and returned to
        the compiler for quarantine. Infrastructure failures still abort the
        active group. Earlier committed groups remain exactly replayable via
        consumed-input idempotency if a later group fails.
        """
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or not 1 <= batch_size <= 1000:
            raise ValidationError("capture batch_size must be 1..1000")
        results: list[str | ValidationError | ConflictError] = []
        with self.connect() as conn:
            for start in range(0, len(items), batch_size):
                conn.execute("BEGIN IMMEDIATE")
                for offset, (envelope, source_path) in enumerate(items[start:start + batch_size]):
                    savepoint = f"capture_{start + offset}"
                    conn.execute(f"SAVEPOINT {savepoint}")
                    try:
                        result = self._apply_capture_on_connection(
                            conn, envelope, source_path=source_path,
                        )
                    except sqlite3.IntegrityError as exc:
                        conn.execute(f"ROLLBACK TO {savepoint}")
                        conn.execute(f"RELEASE {savepoint}")
                        if _sqlite_is_identity_conflict(exc):
                            results.append(ConflictError(
                                "capture conflicts with an existing canonical node, version, edge, or event identity"
                            ))
                            continue
                        raise
                    except (ValidationError, ConflictError) as exc:
                        conn.execute(f"ROLLBACK TO {savepoint}")
                        conn.execute(f"RELEASE {savepoint}")
                        results.append(exc)
                        continue
                    conn.execute(f"RELEASE {savepoint}")
                    results.append(result)
                # This is the durability boundary for the group. The compiler
                # writes acknowledgements only after this method returns.
                conn.commit()
        return results

    def _apply_capture_on_connection(
        self, conn: sqlite3.Connection, envelope: dict[str, Any], *, source_path: str,
    ) -> str:
        validate_capture_envelope(envelope)
        if self.expected_operator_id is not None and envelope["operator_id"] != self.expected_operator_id:
            raise ValidationError("capture operator does not match the configured canonical operator")
        if self.expected_node_id is not None and envelope["node_id"] != self.expected_node_id:
            raise ValidationError("capture node does not match the configured producer node")
        event_id = envelope["input_event_id"]
        event_hash = payload_sha256(envelope)
        content_hash = _feedback_content_sha256(envelope["verdict"]["raw_operator_text"])
        now = utc_now()
        prior = conn.execute(
                    "SELECT payload_sha256 FROM consumed_inputs WHERE input_event_id=?", (event_id,)
                ).fetchone()
        if prior:
            if prior[0] == event_hash:
                return "duplicate"
            raise ConflictError("same input_event_id has different bytes")
        if conn.execute(
                    """SELECT 1 FROM captured_feedback_dedup
                       WHERE operator_id=? AND content_sha256=?""",
                    (envelope["operator_id"], content_hash),
                ).fetchone():
            return "duplicate"
        conn.execute(
                    "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                    (event_id, "captured", envelope["operator_id"], now, envelope["captured_at"],
                     canonical_bytes(envelope).decode(), event_hash, None, "captured"),
                )
        case = envelope["case"]
        verdict = envelope["verdict"]
        call = verdict["call"]
        self._insert_node(conn, case["case_id"], "Case", case, envelope, event_id, now)
        self._insert_node(conn, verdict["verdict_id"], "Verdict", verdict, envelope, event_id, now)
        self._insert_node(conn, call["call_id"], "Call", call, envelope, event_id, now)
        self._insert_edge(conn, "verdict_about_case", verdict["verdict_id"], case["case_id"], envelope, event_id, now)
        self._insert_edge(conn, "made_call", verdict["verdict_id"], call["call_id"], envelope, event_id, now)
        for evidence in envelope["evidence"]:
            self._insert_node(conn, evidence["evidence_id"], "Evidence", evidence, envelope, event_id, now)
            self._insert_edge(conn, "supported_by", verdict["verdict_id"], evidence["evidence_id"], envelope, event_id, now)
            conn.execute(
                "INSERT INTO source_receipts VALUES(?,?,?,?,?)",
                (evidence["evidence_id"], evidence.get("kind", "operator_verbatim"),
                 evidence.get("source_locator", ""), evidence["content_sha256"], event_id),
            )
        alternatives = {item["alternative_id"]: item for item in envelope.get("alternatives", [])}
        for alt_id, alternative in alternatives.items():
            self._insert_node(conn, alt_id, "Alternative", alternative, envelope, event_id, now)
        for alt_id in verdict.get("chosen_alternative_ids", []):
            self._insert_edge(conn, "chose_alternative", verdict["verdict_id"], alt_id, envelope, event_id, now)
        for alt_id in verdict.get("rejected_alternative_ids", []):
            self._insert_edge(conn, "rejected_alternative", verdict["verdict_id"], alt_id, envelope, event_id, now)
        conn.execute(
            "INSERT INTO consumed_inputs VALUES(?,?,?,?)", (event_id, event_hash, now, source_path)
        )
        conn.execute(
            """INSERT INTO captured_feedback_dedup
               (operator_id,content_sha256,first_event_id,first_captured_at)
               VALUES(?,?,?,?)""",
            (envelope["operator_id"], content_hash, event_id, envelope["captured_at"]),
        )
        return "captured"

    @staticmethod
    def _validate_base_version_values(values: tuple[Any, ...]) -> None:
        validate_base_version_values(values)

    @classmethod
    def _insert_node_version(cls, conn: sqlite3.Connection, values: tuple[Any, ...]) -> None:
        insert_node_version(conn, values)

    @classmethod
    def _insert_edge_version(cls, conn: sqlite3.Connection, values: tuple[Any, ...]) -> None:
        insert_edge_version(conn, values)

    def _insert_node(self, conn, node_id, node_type, payload, envelope, event_id, now):
        conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", (node_id, node_type, envelope["operator_id"], event_id))
        version_id = make_urn("node-version")
        evidence_ids = [item["evidence_id"] for item in envelope.get("evidence", [])]
        self._insert_node_version(
            conn,
            (version_id, node_id, canonical_bytes(payload).decode(), payload_sha256(payload), "captured",
             "observed_candidate", canonical_bytes(version_provenance(
                 status="captured", authority_tier="observed_candidate", actor_class="software",
                 actor_id=envelope.get("captured_by", "imprint-recorder"), mechanism=envelope["capture_mechanism"], event_id=event_id,
             )).decode(), json.dumps(evidence_ids), envelope["captured_at"], None,
             now, None, event_id, None),
        )

    def _insert_edge(self, conn, edge_type, source_id, target_id, envelope, event_id, now):
        edge_id = make_urn("edge")
        payload = {"why": "witnessed in raw capture", "relation": edge_type}
        conn.execute(
            "INSERT INTO edges VALUES(?,?,?,?,?,?)",
            (edge_id, edge_type, source_id, target_id, envelope["operator_id"], event_id),
        )
        self._insert_edge_version(
            conn,
            (make_urn("edge-version"), edge_id, canonical_bytes(payload).decode(), payload_sha256(payload),
             "captured", "observed_candidate", canonical_bytes(version_provenance(
                 status="captured", authority_tier="observed_candidate", actor_class="software",
                 actor_id=envelope.get("captured_by", "imprint-recorder"), mechanism=envelope["capture_mechanism"], event_id=event_id,
                 relation=edge_type,
             )).decode(), json.dumps([x["evidence_id"] for x in envelope["evidence"]]),
             envelope["captured_at"], None, now, None, event_id, None),
        )

    @staticmethod
    def _v31_time(value: Any, field: str, *, nullable: bool = False) -> str | None:
        if value is None and nullable:
            return None
        if not isinstance(value, str):
            raise ValidationError(f"E_NODE_FIELD_TYPE at /{field}: RFC3339 timestamp required")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"E_NODE_FIELD_VALUE at /{field}: invalid RFC3339 timestamp") from exc
        if parsed.tzinfo is None or not value.endswith("Z") or parsed.utcoffset().total_seconds() != 0:
            raise ValidationError(f"E_NODE_FIELD_VALUE at /{field}: canonical RFC3339 UTC required")
        return value

    @staticmethod
    def _validate_v31_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
        """Validate the exact first-write envelope without performing lookups."""
        from imprint.ontology.validators import validate_core_payload, validate_provenance_v2_1

        if not isinstance(envelope, Mapping):
            raise ValidationError("E_NODE_FIELD_TYPE at /: node envelope must be an object")
        unknown = set(envelope) - _V31_ENVELOPE_FIELDS
        missing = _V31_ENVELOPE_FIELDS - set(envelope)
        if unknown:
            name = sorted(unknown)[0]
            raise ValidationError(f"E_NODE_FIELD_UNKNOWN at /{name}: unknown envelope field")
        if missing:
            name = sorted(missing)[0]
            raise ValidationError(f"E_NODE_FIELD_REQUIRED at /{name}: required envelope field missing")
        value = dict(envelope)
        schema_id = value["payload_schema_id"]
        if schema_id not in _V31_SCHEMA_TYPES:
            raise ValidationError("E_NODE_SCHEMA_UNKNOWN at /payload_schema_id: unknown node schema")
        if value["record_schema_version"] != "3.1.0":
            raise ValidationError("E_NODE_FIELD_VALUE at /record_schema_version: expected 3.1.0")
        if value["ontology_schema_version"] != "3.6.1":
            raise ValidationError("E_NODE_FIELD_VALUE at /ontology_schema_version: expected 3.6.1")
        for field in ("record_id", "version_id", "operator_id", "actor_id",
                      "role_assignment_version_id", "access_policy_version_id", "scope_id"):
            if not isinstance(value[field], str) or not value[field].strip() or ":" not in value[field]:
                raise ValidationError(f"E_NODE_REFERENCE_VERSION_REQUIRED at /{field}: exact URI required")
        if value["consent_version_id"] is not None and (
            not isinstance(value["consent_version_id"], str) or ":" not in value["consent_version_id"]
        ):
            raise ValidationError("E_CONSENT_VERSION_REQUIRED at /consent_version_id: exact version required")
        if value["sensitivity"] not in _V31_SENSITIVITY:
            raise ValidationError("E_NODE_FIELD_VALUE at /sensitivity: invalid sensitivity")
        if not isinstance(value["extensions"], Mapping) or any(
            ":" not in key for key in value["extensions"]
        ):
            raise ValidationError("E_NODE_FIELD_VALUE at /extensions: only namespaced extensions are allowed")
        valid_from = ImprintStore._v31_time(value["valid_from"], "valid_from")
        valid_to = ImprintStore._v31_time(value["valid_to"], "valid_to", nullable=True)
        if valid_to is not None and valid_to <= valid_from:
            raise ValidationError("E_TEMPORAL_INTERVAL_OVERLAP at /valid_to: interval must be half-open")
        if schema_id in _BUSINESS_SCHEMA_PARTITIONS:
            from imprint.ontology.business import validate_business_payload

            deferred_types = None
            if schema_id == "imprint.node.business-event/1.1.0":
                subject = value["payload"].get("subject_version_id") if isinstance(value["payload"], Mapping) else None
                deferred_types = {subject: "Customer"} if subject is not None else None
            value["payload"] = validate_business_payload(
                schema_id, value["payload"],
                partition=_BUSINESS_SCHEMA_PARTITIONS[schema_id],
                reference_types=deferred_types,
            )
        else:
            value["payload"] = validate_core_payload(schema_id, value["payload"])
        value["provenance"] = validate_provenance_v2_1(value["provenance"])
        if value["provenance"]["actor_id"] != value["actor_id"]:
            raise ValidationError("E_NODE_CONDITIONAL_RULE at /actor_id: envelope and provenance actor differ")
        if value["provenance"]["role_assignment_version_id"] != value["role_assignment_version_id"]:
            raise ValidationError("E_NODE_CONDITIONAL_RULE at /role_assignment_version_id: envelope and provenance role differ")
        return value

    @staticmethod
    def _v31_ref_type(
        conn: sqlite3.Connection, version_id: str,
        pending: Mapping[str, Mapping[str, Any]],
    ) -> tuple[str, str, Mapping[str, Any], str, str | None, str, str] | None:
        candidate = pending.get(version_id)
        if candidate is not None:
            return (
                _V31_SCHEMA_TYPES[candidate["payload_schema_id"]], candidate["operator_id"],
                candidate["payload"], candidate["valid_from"], candidate["valid_to"],
                candidate["provenance"]["authority_tier"], candidate["provenance"]["lifecycle_status"],
            )
        row = conn.execute(
            """SELECT n.node_type,n.operator_id,nv.payload_json,nv.valid_from,nv.valid_to,
                      nv.authority_tier,nv.provenance_json
               FROM node_versions nv JOIN nodes n USING(node_id)
               WHERE nv.version_id=?""", (version_id,),
        ).fetchone()
        if not row:
            relation = conn.execute(
                """SELECT operator_id,envelope_json,valid_from,valid_to
                   FROM semantic_relation_versions WHERE relation_version_id=?""",
                (version_id,),
            ).fetchone()
            if not relation:
                return None
            return (
                "RelationVersion", relation["operator_id"], json.loads(relation["envelope_json"]),
                relation["valid_from"], relation["valid_to"], "inferred_candidate", "active",
            )
        provenance = json.loads(row["provenance_json"])
        lifecycle = provenance.get("lifecycle_status", "active")
        return row["node_type"], row["operator_id"], json.loads(row["payload_json"]), row["valid_from"], row["valid_to"], row["authority_tier"], lifecycle

    @staticmethod
    def _require_v31_ref(
        conn: sqlite3.Connection, version_id: str, pending: Mapping[str, Mapping[str, Any]],
        *, operator_id: str, field: str, allowed: set[str], at: str | None = None,
    ) -> tuple[str, str, Mapping[str, Any], str, str | None, str, str]:
        found = ImprintStore._v31_ref_type(conn, version_id, pending)
        if found is None:
            raise ValidationError(f"E_NODE_REFERENCE_TYPE at /payload/{field}: exact version is missing")
        node_type, owner, payload, valid_from, valid_to, _, _ = found
        if owner != operator_id or node_type not in allowed:
            raise ValidationError(f"E_NODE_REFERENCE_TYPE at /payload/{field}: incompatible exact version")
        if at is not None and not (valid_from <= at and (valid_to is None or at < valid_to)):
            raise ValidationError(f"E_ROLE_SCOPE_DENIED at /payload/{field}: reference inactive at semantic time")
        return found

    @staticmethod
    def _parse_consent_time(value: Any, field: str) -> datetime:
        if not isinstance(value, str):
            raise ValidationError(f"E_CONSENT_VERSION_REQUIRED at /{field}: RFC3339 UTC required")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"E_CONSENT_VERSION_REQUIRED at /{field}: invalid RFC3339 time") from exc
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ValidationError(f"E_CONSENT_VERSION_REQUIRED at /{field}: UTC time required")
        return parsed.astimezone(timezone.utc)

    @classmethod
    def authorize_consent_version(
        cls, conn: sqlite3.Connection, consent_version_id: str, *,
        operator_id: str, source_class: str, purpose: str, operation: str,
        valid_at: str, system_at: str,
    ) -> str:
        """Authorize one exact grant at semantic and local transaction time.

        The caller cannot supply ``system_at`` from an import or payload; store
        writers pass a freshly generated local value. Both intervals are
        half-open, and a revoked or imported-floor grant always denies.
        """
        row = conn.execute(
            """SELECT nv.version_id,n.operator_id,nv.payload_json,
                      nv.provenance_status,nv.authority_tier,
                      nv.valid_from,nv.valid_to,nv.system_from,nv.system_to
               FROM node_versions nv JOIN nodes n USING(node_id)
               WHERE nv.version_id=? AND n.node_type='ConsentGrant'""",
            (consent_version_id,),
        ).fetchone()
        if row is None or row["operator_id"] != operator_id:
            raise ValidationError("E_CONSENT_VERSION_REQUIRED at /consent_version_id: exact same-operator grant required")
        if row["provenance_status"] not in {"captured", "ratified"} or row["authority_tier"] not in {
            "captured_judgment", "ratified_knowledge",
        }:
            raise ValidationError("E_CONSENT_VERSION_REQUIRED at /consent_version_id: imported or unratified grant denied")
        payload = json.loads(row["payload_json"])
        valid = cls._parse_consent_time(valid_at, "valid_at")
        system = cls._parse_consent_time(system_at, "system_at")
        if valid > system + CONSENT_CLOCK_SKEW:
            raise ValidationError("E_CONSENT_VERSION_REQUIRED at /valid_at: future time exceeds 120-second skew")

        valid_start = cls._parse_consent_time(payload.get("effective_from", row["valid_from"]), "effective_from")
        valid_end_raw = payload.get("effective_to", row["valid_to"])
        valid_end = cls._parse_consent_time(valid_end_raw, "effective_to") if valid_end_raw is not None else None
        system_start = cls._parse_consent_time(row["system_from"], "system_from")
        system_end = cls._parse_consent_time(row["system_to"], "system_to") if row["system_to"] is not None else None
        revoked_raw = payload.get("revoked_at")
        revoked = cls._parse_consent_time(revoked_raw, "revoked_at") if revoked_raw is not None else None

        retention = payload.get("retention", {})
        if retention.get("mode") == "days":
            days = retention.get("days")
            if isinstance(days, bool) or not isinstance(days, int) or days < 1:
                raise ValidationError("E_CONSENT_VERSION_REQUIRED at /retention/days: positive integer required")
            retention_end = valid_start + timedelta(days=days)
            valid_end = min(valid_end, retention_end) if valid_end is not None else retention_end

        allowed = (
            payload.get("operator_id") == operator_id
            and payload.get("source_class") == source_class
            and purpose in payload.get("purposes", [])
            and operation in payload.get("allowed_operations", [])
            and valid >= valid_start
            and (valid_end is None or valid < valid_end)
            and system >= system_start
            and (system_end is None or system < system_end)
            and (revoked is None or (valid < revoked and system < revoked))
        )
        if not allowed:
            error = "E_CONSENT_REVOKED" if revoked is not None and (valid >= revoked or system >= revoked) else "E_CONSENT_VERSION_REQUIRED"
            raise ValidationError(f"{error} at /consent_version_id: grant denies valid/system instant")
        return str(row["version_id"])

    def _validate_v31_references(
        self, conn: sqlite3.Connection, value: Mapping[str, Any],
        pending: Mapping[str, Mapping[str, Any]], artifact_bytes: Mapping[str, bytes],
        *, system_at: str | None = None,
    ) -> None:
        version_id = value["version_id"]
        operator_id = value["operator_id"]
        node_type = _V31_SCHEMA_TYPES[value["payload_schema_id"]]
        payload = value["payload"]
        valid_at = value["valid_from"]

        governing_role = self._require_v31_ref(
            conn, value["role_assignment_version_id"], pending, operator_id=operator_id,
            field="role_assignment_version_id", allowed={"RoleAssignment"}, at=valid_at,
        )
        if (governing_role[5] not in {"captured_judgment", "ratified_knowledge"}
                or governing_role[6] != "active"
                or "store" not in governing_role[2].get("allowed_operations", [])
                or value["scope_id"] not in governing_role[2].get("scope_ids", [])):
            raise ValidationError("E_ROLE_SCOPE_DENIED at /role_assignment_version_id: active scoped store authority required")
        governing_policy = self._require_v31_ref(
            conn, value["access_policy_version_id"], pending, operator_id=operator_id,
            field="access_policy_version_id", allowed={"AccessPolicy"}, at=valid_at,
        )
        if ("store" not in governing_policy[2].get("operations", [])
                or value["role_assignment_version_id"] not in governing_policy[2].get("principal_role_assignment_version_ids", [])):
            raise ValidationError("E_ACCESS_POLICY_VERSION_REQUIRED at /access_policy_version_id: policy denies store")
        if value["consent_version_id"] is not None:
            consent = self._require_v31_ref(
                conn, value["consent_version_id"], pending, operator_id=operator_id,
                field="consent_version_id", allowed={"ConsentGrant"}, at=valid_at,
            )
            # Legacy 3.0.x grants remain readable but are not silently assigned
            # v3.1 consent semantics. Exact 3.1 grants enforce both intervals.
            if "source_class" in consent[2]:
                source_class = payload.get("source_class", "operator_explicit")
                purpose = (
                    "outcome_learning" if node_type in {"Outcome", "ExpectedOutcome"}
                    else "business_analysis" if node_type in {"Observation", "EvidenceArtifact"}
                    else "self_modeling"
                )
                self.authorize_consent_version(
                    conn, value["consent_version_id"], operator_id=operator_id,
                    source_class=source_class, purpose=purpose, operation="store",
                    valid_at=valid_at, system_at=system_at or utc_now(),
                )
        actor = conn.execute(
            "SELECT node_type,operator_id FROM nodes WHERE node_id=?", (value["actor_id"],),
        ).fetchone()
        pending_actor = next(
            (item for item in pending.values() if item.get("record_id") == value["actor_id"]),
            None,
        )
        if pending_actor is not None:
            actor_type, actor_owner = _V31_SCHEMA_TYPES[pending_actor["payload_schema_id"]], pending_actor["operator_id"]
        elif actor:
            actor_type, actor_owner = actor["node_type"], actor["operator_id"]
        else:
            actor_type, actor_owner = None, None
        if actor_type != "Actor" or actor_owner != operator_id:
            raise ValidationError("E_NODE_REFERENCE_TYPE at /actor_id: exact same-operator Actor required")

        evidence_ids = value["provenance"]["evidence_version_ids"]
        for evidence_id in evidence_ids:
            if node_type == "EvidenceArtifact" and evidence_id == version_id:
                continue
            self._require_v31_ref(
                conn, evidence_id, pending, operator_id=operator_id,
                field="provenance/evidence_version_ids", allowed={"EvidenceArtifact"},
            )

        if node_type == "DecisionEpisode":
            self._require_v31_ref(conn, payload["case_version_id"], pending, operator_id=operator_id, field="case_version_id", allowed={"Case"})
            self._require_v31_ref(conn, payload["verdict_version_id"], pending, operator_id=operator_id, field="verdict_version_id", allowed={"Verdict"})
            role = self._require_v31_ref(conn, payload["operator_role_assignment_version_id"], pending, operator_id=operator_id, field="operator_role_assignment_version_id", allowed={"RoleAssignment"}, at=payload["captured_at"])
            if (role[2].get("role_type") not in {"operator_of_record", "decision_maker"}
                    or "store" not in role[2].get("allowed_operations", [])
                    or role[5] not in {"captured_judgment", "ratified_knowledge"}
                    or role[6] != "active"):
                raise ValidationError("E_ROLE_SCOPE_DENIED at /payload/operator_role_assignment_version_id: role cannot record episode")
            for field, allowed in (
                ("participant_role_assignment_version_ids", {"RoleAssignment"}),
                ("artifact_version_ids", {"EvidenceArtifact"}),
                ("expected_outcome_version_ids", {"ExpectedOutcome"}),
            ):
                values = payload.get(field, [])
                if not isinstance(values, list) or len(values) != len(set(values)):
                    raise ValidationError(f"E_NODE_FIELD_CARDINALITY at /payload/{field}: ordered unique array required")
                for item in values:
                    self._require_v31_ref(conn, item, pending, operator_id=operator_id, field=field, allowed=allowed)
        elif node_type == "ExpectedOutcome":
            confidence_id = payload.get("confidence_assessment_version_id")
            if confidence_id is not None:
                assessment = self._require_v31_ref(conn, confidence_id, pending, operator_id=operator_id, field="confidence_assessment_version_id", allowed={"ConfidenceAssessment"})
                if assessment[2]["subject_version_id"] != version_id:
                    raise ValidationError("E_NODE_REFERENCE_TYPE at /payload/confidence_assessment_version_id: assessment targets another version")
        elif node_type == "ConfidenceAssessment":
            subject = self._require_v31_ref(conn, payload["subject_version_id"], pending, operator_id=operator_id, field="subject_version_id", allowed=set(_V31_SCHEMA_TYPES.values()) | {"Case", "Verdict", "Outcome", "Observation", "Pattern", "RelationVersion"})
            if subject[0] in _CONFIDENCE_FORBIDDEN:
                raise ValidationError("E_NODE_CONDITIONAL_RULE at /payload/subject_version_id: confidence forbidden for target")
            self._require_v31_ref(conn, payload["assessor_actor_version_id"], pending, operator_id=operator_id, field="assessor_actor_version_id", allowed={"Actor"})
            basis = payload.get("basis_evidence_version_ids", [])
            if not isinstance(basis, list) or len(basis) != len(set(basis)):
                raise ValidationError("E_NODE_FIELD_CARDINALITY at /payload/basis_evidence_version_ids: unique array required")
            for item in basis:
                self._require_v31_ref(conn, item, pending, operator_id=operator_id, field="basis_evidence_version_ids", allowed={"EvidenceArtifact"})
        elif node_type == "EvidenceArtifact":
            self._require_v31_ref(conn, payload["custody_actor_version_id"], pending, operator_id=operator_id, field="custody_actor_version_id", allowed={"Actor"})
            self._require_v31_ref(conn, payload["access_policy_version_id"], pending, operator_id=operator_id, field="access_policy_version_id", allowed={"AccessPolicy"})
            self._require_v31_ref(conn, payload["consent_version_id"], pending, operator_id=operator_id, field="consent_version_id", allowed={"ConsentGrant"})
            derived = payload["derived_from_version_ids"]
            if not isinstance(derived, list) or len(derived) != len(set(derived)):
                raise ValidationError("E_NODE_FIELD_CARDINALITY at /payload/derived_from_version_ids: ordered unique array required")
            for item in derived:
                self._require_v31_ref(conn, item, pending, operator_id=operator_id, field="derived_from_version_ids", allowed={"EvidenceArtifact"})
            content = artifact_bytes.get(version_id)
            if payload["content_state"] != "purged":
                if not isinstance(content, bytes):
                    raise ValidationError("E_ARTIFACT_DIGEST_MISMATCH at /artifact_bytes: exact bytes required")
                if len(content) != payload["byte_count"] or hashlib.sha256(content).hexdigest() != payload["original_sha256"]:
                    raise ValidationError("E_ARTIFACT_DIGEST_MISMATCH at /artifact_bytes: digest or byte count mismatch")

        if value["payload_schema_id"] in _BUSINESS_SCHEMA_PARTITIONS:
            self._validate_business_references(conn, value, pending)

    def _validate_business_references(
        self, conn: sqlite3.Connection, value: Mapping[str, Any],
        pending: Mapping[str, Mapping[str, Any]],
    ) -> None:
        """Resolve every printed business payload reference before first write."""
        from imprint.ontology.business import validate_business_payload

        schema_id = value["payload_schema_id"]
        payload = value["payload"]
        operator_id = value["operator_id"]
        version_id = value["version_id"]

        def one(field: str, allowed: set[str]) -> tuple[str, str, Mapping[str, Any], str, str | None, str, str] | None:
            ref = payload.get(field)
            if ref is None:
                return None
            return self._require_v31_ref(
                conn, ref, pending, operator_id=operator_id, field=field, allowed=allowed,
            )

        def many(field: str, allowed: set[str]) -> None:
            refs = payload.get(field, [])
            if not isinstance(refs, list) or len(refs) != len(set(refs)):
                raise ValidationError(f"E_BUSINESS_FIELD_CARDINALITY at /payload/{field}: unique array required")
            for ref in refs:
                self._require_v31_ref(
                    conn, ref, pending, operator_id=operator_id, field=field, allowed=allowed,
                )

        def exact_event(field: str) -> None:
            ref = payload.get(field)
            if ref is None:
                return
            found = self._v31_ref_type(conn, ref, pending)
            if found is not None:
                if found[0] != "RatificationEvent" or found[1] != operator_id:
                    raise ValidationError(f"E_BUSINESS_REFERENCE_TYPE at /payload/{field}: exact RatificationEvent required")
                return
            event = conn.execute(
                "SELECT operator_id,event_type FROM events WHERE event_id=?", (ref,),
            ).fetchone()
            if not event or event["operator_id"] != operator_id or "ratif" not in event["event_type"]:
                raise ValidationError(f"E_BUSINESS_REFERENCE_TYPE at /payload/{field}: exact ratification event required")

        confidence_id = payload.get("confidence_assessment_version_id")
        if confidence_id is not None:
            assessment = one("confidence_assessment_version_id", {"ConfidenceAssessment"})
            if assessment is None or assessment[2].get("subject_version_id") != version_id:
                raise ValidationError(
                    "E_BUSINESS_REFERENCE_TYPE at /payload/confidence_assessment_version_id: "
                    "assessment must target this exact business version"
                )

        if schema_id.endswith("market/1.0.0"):
            many("channel_ids", {"Channel"})
        elif schema_id.endswith("positioning/1.0.0"):
            many("alternative_version_ids", set(_V31_SCHEMA_TYPES.values()) | {"Offer", "Claim", "Promise"})
            many("proof_version_ids", {"Proof"})
            exact_event("ratification_event_version_id")
        elif schema_id.endswith("term-set/1.0.0"):
            exact_event("ratification_event_version_id")
        elif schema_id.endswith("asset/1.0.0"):
            one("artifact_version_id", {"EvidenceArtifact"})
            one("approved_by_role_assignment_version_id", {"RoleAssignment"})
        elif schema_id.endswith("campaign/1.0.0"):
            one("owner_role_assignment_version_id", {"RoleAssignment"})
        elif schema_id.endswith("business-event/1.1.0"):
            one("observer_actor_version_id", {"Actor"})
            one("source_artifact_version_id", {"EvidenceArtifact"})
            reference_types: dict[str, str] = {}
            subject_id = payload.get("subject_version_id")
            if subject_id is not None:
                subject = self._require_v31_ref(
                    conn, subject_id, pending, operator_id=operator_id,
                    field="subject_version_id", allowed={"Customer", "Actor"},
                )
                reference_types[subject_id] = (
                    "Actor:external_subject"
                    if subject[0] == "Actor" and subject[2].get("actor_type") == "external_subject"
                    else subject[0]
                )
            validate_business_payload(
                schema_id, payload, partition="business_observed", reference_types=reference_types,
            )
        elif schema_id.endswith("required-behavior/1.0.0"):
            exact_event("ratification_event_version_id")
        elif schema_id.endswith("campaign-performance-measurement/1.1.0"):
            one("observer_actor_version_id", {"Actor"})
            many("source_artifact_version_ids", {"EvidenceArtifact"})
            one("baseline_measurement_version_id", {"CampaignPerformanceMeasurement"})
            one("comparator_measurement_version_id", {"CampaignPerformanceMeasurement"})
        elif schema_id.endswith("performance-disposition/1.1.0"):
            one("measurement_version_id", {"CampaignPerformanceMeasurement"})
            one("outcome_version_id", {"Outcome"})
            one("decided_by_actor_version_id", {"Actor"})
            role = one("decided_by_role_assignment_version_id", {"RoleAssignment"})
            if role is None or role[5] not in {"captured_judgment", "ratified_knowledge"} or role[6] != "active":
                raise ValidationError(
                    "E_RELATION_ROLE_DENIED at /payload/decided_by_role_assignment_version_id: active judgment role required"
                )
            many("evidence_version_ids", {"EvidenceArtifact"})

        provenance = value["provenance"]
        origin = provenance["origin_status"]
        tier = provenance["authority_tier"]
        lifecycle = provenance["lifecycle_status"]
        if tier not in {"captured_judgment", "ratified_knowledge"}:
            ceiling = {
                "captured": "observed_candidate",
                "extracted": "imported_floor",
                "inferred": "inferred_candidate",
            }[origin]
            if tier != ceiling:
                raise ValidationError(
                    f"E_BUSINESS_AUTHORITY_CEILING at /provenance/authority_tier: {origin} requires {ceiling} before signed promotion"
                )
        if schema_id.endswith(("positioning/1.0.0", "term-set/1.0.0", "required-behavior/1.0.0")):
            if tier != "ratified_knowledge" or lifecycle != "active":
                raise ValidationError(
                    "E_BUSINESS_AUTHORITY_CEILING at /provenance/authority_tier: declared-and-ratified schema required"
                )
        if schema_id.endswith("performance-disposition/1.1.0") and lifecycle == "active":
            if tier not in {"captured_judgment", "ratified_knowledge"}:
                raise ValidationError(
                    "E_BUSINESS_AUTHORITY_CEILING at /provenance/authority_tier: active disposition requires signed judgment"
                )

    def append_ontology_bundle(
        self, envelopes: Iterable[Mapping[str, Any]], *,
        artifact_bytes: Mapping[str, bytes] | None = None,
        approval_token: Mapping[str, Any] | None = None,
    ) -> tuple[str, ...]:
        """Atomically append exact 3.6.1 first-write nodes and assessments.

        Caller-supplied record/version IDs make the signed mutation stable across
        prepare/approve/execute.  System time remains store-created.
        """
        values = [self._validate_v31_envelope(item) for item in envelopes]
        if not values:
            raise ValidationError("E_NODE_FIELD_CARDINALITY at /: bundle cannot be empty")
        versions = [item["version_id"] for item in values]
        records = [item["record_id"] for item in values]
        if len(versions) != len(set(versions)) or len(records) != len(set(records)):
            raise ValidationError("E_NODE_FIELD_CARDINALITY at /: first-write IDs must be unique")
        pending = {item["version_id"]: item for item in values}
        artifact_bytes = dict(artifact_bytes or {})
        operators = {item["operator_id"] for item in values}
        if len(operators) != 1:
            raise ValidationError("E_NODE_REFERENCE_TYPE at /operator_id: mixed-operator bundle forbidden")
        operator_id = next(iter(operators))
        self._require_configured_operator(operator_id)
        generated = {
            "system_time": utc_now(),
            "event_ids": {item["version_id"]: make_urn("event") for item in values},
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            placeholders = ",".join("?" for _ in records)
            if conn.execute(f"SELECT 1 FROM nodes WHERE node_id IN ({placeholders}) LIMIT 1", records).fetchone():
                raise ConflictError("first-write record already exists")
            if conn.execute(
                f"SELECT 1 FROM node_versions WHERE version_id IN ({','.join('?' for _ in versions)}) LIMIT 1", versions,
            ).fetchone():
                raise ConflictError("first-write version already exists")
            for item in values:
                self._validate_v31_references(
                    conn, item, pending, artifact_bytes, system_at=utc_now(),
                )

            assessment_by_subject: dict[str, list[Mapping[str, Any]]] = {}
            assessment_tuples: set[tuple[str, str, str, str]] = set()
            for item in values:
                if _V31_SCHEMA_TYPES[item["payload_schema_id"]] == "ConfidenceAssessment":
                    assessment_by_subject.setdefault(item["payload"]["subject_version_id"], []).append(item)
                    confidence = item["payload"]
                    identity = (
                        confidence["subject_version_id"], confidence["assessor_actor_version_id"],
                        confidence["method"], confidence["scale"],
                    )
                    if identity in assessment_tuples:
                        raise ValidationError("E_NODE_FIELD_CARDINALITY at /confidence: duplicate current scorer/method/scale head")
                    assessment_tuples.add(identity)
            for item in values:
                node_type = _V31_SCHEMA_TYPES[item["payload_schema_id"]]
                provenance = item["provenance"]
                must_assess = (
                    node_type == "ExpectedOutcome"
                    or (provenance["origin_status"] in {"inferred", "extracted"}
                        and node_type not in _CONFIDENCE_FORBIDDEN)
                )
                if must_assess and not assessment_by_subject.get(item["version_id"]):
                    raise ValidationError("E_NODE_CONDITIONAL_RULE at /confidence: required initial assessment must commit atomically")
                if node_type in _CONFIDENCE_FORBIDDEN and assessment_by_subject.get(item["version_id"]):
                    raise ValidationError("E_NODE_CONDITIONAL_RULE at /confidence: target must not carry confidence")

            intent = {
                "contract_id": "imprint.ontology.binding/3.6.1", "envelopes": values,
                "artifact_sha256": {
                    version_id: hashlib.sha256(content).hexdigest()
                    for version_id, content in sorted(artifact_bytes.items())
                },
            }
            if any(item["provenance"]["authority_tier"] in {"captured_judgment", "ratified_knowledge"} for item in values):
                execution = self._consume_authority(
                    conn, approval_token, command_name="ontology.first_write_bundle",
                    purpose="store ontology first-write bundle",
                    intent=intent, authority_transition="ontology_first_write",
                    execution_fields=generated,
                    subject_ids=tuple(records),
                    source_ids=tuple(sorted({e for item in values for e in item["provenance"]["evidence_version_ids"]})),
                    result_version_ids=tuple(versions), scope=("ontology", "3.6.1"),
                )
            else:
                if approval_token is not None:
                    raise ValidationError("approval token cannot authorize a non-authoritative ontology bundle")
                execution = generated
            now = execution["system_time"]
            event_ids = execution["event_ids"]

            for item in values:
                version_id = item["version_id"]
                event_id = event_ids[version_id]
                node_type = _V31_SCHEMA_TYPES[item["payload_schema_id"]]
                event_payload = {**item, "system_from": now, "system_to": None}
                conn.execute(
                    "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                    (event_id, "ontology_first_write", operator_id, now, item["valid_from"],
                     canonical_bytes(event_payload).decode(), payload_sha256(event_payload), None,
                     item["provenance"]["origin_status"]),
                )
                conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", (item["record_id"], node_type, operator_id, event_id))
                self._insert_node_version(
                    conn,
                    (version_id, item["record_id"], canonical_bytes(item["payload"]).decode(), payload_sha256(item["payload"]),
                     item["provenance"]["origin_status"], item["provenance"]["authority_tier"],
                     canonical_bytes(item["provenance"]).decode(), json.dumps(item["provenance"]["evidence_version_ids"]),
                     item["valid_from"], item["valid_to"], now, None, event_id, None),
                )
                conn.execute(
                    "INSERT INTO semantic_node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (version_id, item["record_id"], item["payload_schema_id"], item["record_schema_version"],
                     item["ontology_schema_version"], canonical_bytes(item["provenance"]).decode(), item["sensitivity"],
                     item["access_policy_version_id"], item["consent_version_id"], item["actor_id"],
                     item["role_assignment_version_id"], item["scope_id"], None,
                     canonical_bytes(event_payload).decode(), payload_sha256(event_payload)),
                )
                if item["payload_schema_id"] in _BUSINESS_SCHEMA_PARTITIONS:
                    conn.execute(
                        "INSERT INTO semantic_business_node_versions VALUES(?,?)",
                        (version_id, _BUSINESS_SCHEMA_PARTITIONS[item["payload_schema_id"]]),
                    )
                if node_type == "EvidenceArtifact" and item["payload"]["content_state"] != "purged":
                    content = artifact_bytes[version_id]
                    conn.execute(
                        "INSERT INTO semantic_artifact_bytes VALUES(?,?,?,?)",
                        (version_id, content, hashlib.sha256(content).hexdigest(), len(content)),
                    )
                if node_type == "ConfidenceAssessment":
                    payload = item["payload"]
                    conn.execute(
                        """INSERT INTO semantic_confidence_heads VALUES(?,?,?,?,?)
                           ON CONFLICT(subject_version_id,assessor_actor_version_id,method,scale)
                           DO UPDATE SET assessment_version_id=excluded.assessment_version_id""",
                        (payload["subject_version_id"], payload["assessor_actor_version_id"],
                         payload["method"], payload["scale"], version_id),
                    )
        return tuple(versions)

    def append_ontology_node(
        self, envelope: Mapping[str, Any], *, artifact_bytes: bytes | None = None,
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        blobs = {envelope.get("version_id", ""): artifact_bytes} if artifact_bytes is not None else {}
        return self.append_ontology_bundle([envelope], artifact_bytes=blobs, approval_token=approval_token)[0]

    def read_business_node(self, version_id: str) -> dict[str, Any]:
        """Return one exact stored business envelope with its locked partition."""
        with self.read_connection() as conn:
            row = conn.execute(
                """SELECT sv.envelope_json,bv.partition_id
                   FROM semantic_business_node_versions bv
                   JOIN semantic_node_versions sv USING(version_id)
                   WHERE bv.version_id=?""",
                (version_id,),
            ).fetchone()
        if row is None:
            raise ValidationError("E_BUSINESS_REFERENCE_TYPE at /version_id: business version not found")
        return {"partition": row["partition_id"], "envelope": json.loads(row["envelope_json"])}

    def iter_business_nodes(self) -> list[dict[str, Any]]:
        """Deterministic exact-version business-node read surface for portability."""
        with self.read_connection() as conn:
            rows = conn.execute(
                """SELECT sv.envelope_json,bv.partition_id
                   FROM semantic_business_node_versions bv
                   JOIN semantic_node_versions sv USING(version_id)
                   ORDER BY bv.partition_id,bv.version_id"""
            ).fetchall()
        return [
            {"partition": row["partition_id"], "envelope": json.loads(row["envelope_json"])}
            for row in rows
        ]

    def append_business_relation(
        self, envelope: Mapping[str, Any], *,
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Validate and atomically append one locked typed business relation."""
        from imprint.ontology.business import (
            BUSINESS_QUALIFIER_SCHEMA_IDS, BUSINESS_RELATION_SPECS,
            validate_business_relation,
        )
        from imprint.ontology.validators import validate_provenance_v2_1

        required = {
            "relation_id", "relation_version_id", "predicate_id", "predicate_version",
            "source_version_id", "target_version_id", "operator_id", "actor_id",
            "role_assignment_version_id", "provenance", "evidence_version_ids", "why",
            "sensitivity", "access_policy_version_id", "consent_version_id", "valid_from",
            "valid_to", "qualifier_schema_id", "qualifier", "extensions",
        }
        if not isinstance(envelope, Mapping):
            raise ValidationError("E_RELATION_GOVERNANCE_REQUIRED at /: exact relation envelope required")
        unknown = set(envelope) - required
        missing = required - set(envelope)
        if unknown:
            raise ValidationError(f"E_RELATION_GOVERNANCE_REQUIRED at /{sorted(unknown)[0]}: unknown field")
        if missing:
            raise ValidationError(f"E_RELATION_GOVERNANCE_REQUIRED at /{sorted(missing)[0]}: required field")
        value = dict(envelope)
        predicate = value["predicate_id"]
        if predicate not in BUSINESS_RELATION_SPECS:
            raise ValidationError("E_BUSINESS_RELATION_UNKNOWN at /predicate_id: unknown predicate")
        if value["predicate_version"] != 1:
            raise ValidationError("E_BUSINESS_RELATION_UNKNOWN at /predicate_version: expected 1")
        for field in (
            "relation_id", "relation_version_id", "source_version_id", "target_version_id",
            "operator_id", "actor_id", "role_assignment_version_id", "access_policy_version_id",
        ):
            if not isinstance(value[field], str) or ":" not in value[field]:
                raise ValidationError(f"E_NODE_REFERENCE_VERSION_REQUIRED at /{field}: exact URI required")
        if value["consent_version_id"] is None or not isinstance(value["consent_version_id"], str) or ":" not in value["consent_version_id"]:
            raise ValidationError("E_CONSENT_VERSION_REQUIRED at /consent_version_id: exact relation-owned consent required")
        if not isinstance(value["extensions"], Mapping) or any(":" not in key for key in value["extensions"]):
            raise ValidationError("E_RELATION_GOVERNANCE_REQUIRED at /extensions: namespaced extensions only")
        if value["sensitivity"] not in _V31_SENSITIVITY:
            raise ValidationError("E_RELATION_SENSITIVITY_FLOOR at /sensitivity: invalid sensitivity")
        self._v31_time(value["valid_from"], "valid_from")
        valid_to = self._v31_time(value["valid_to"], "valid_to", nullable=True)
        if valid_to is not None and valid_to <= value["valid_from"]:
            raise ValidationError("E_TEMPORAL_INTERVAL_OVERLAP at /valid_to: interval must be half-open")
        if not isinstance(value["why"], str) or not value["why"].strip():
            raise ValidationError("E_RELATION_GOVERNANCE_REQUIRED at /why: rationale required")
        provenance = validate_provenance_v2_1(value["provenance"])
        if (not isinstance(value["evidence_version_ids"], list)
                or not value["evidence_version_ids"]
                or len(value["evidence_version_ids"]) != len(set(value["evidence_version_ids"]))
                or value["evidence_version_ids"] != provenance["evidence_version_ids"]):
            raise ValidationError("E_RELATION_GOVERNANCE_REQUIRED at /evidence_version_ids: exact unique provenance evidence required")
        expected_qualifier = BUSINESS_QUALIFIER_SCHEMA_IDS[BUSINESS_RELATION_SPECS[predicate][2]]
        if value["qualifier_schema_id"] != expected_qualifier:
            raise ValidationError("E_RELATION_QUALIFIER_SCHEMA_UNKNOWN at /qualifier_schema_id: predicate qualifier mismatch")
        self._require_configured_operator(value["operator_id"])
        generated = {"event_id": make_urn("event"), "system_time": utc_now()}

        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute(
                "SELECT 1 FROM semantic_relation_versions WHERE relation_version_id=?",
                (value["relation_version_id"],),
            ).fetchone():
                raise ConflictError("relation version already exists")
            source = self._v31_ref_type(conn, value["source_version_id"], {})
            target = self._v31_ref_type(conn, value["target_version_id"], {})
            if source is None or target is None or source[1] != value["operator_id"] or target[1] != value["operator_id"]:
                raise ValidationError("E_BUSINESS_RELATION_ENDPOINT_TYPE at /target_version_id: exact same-operator endpoints required")

            def partition(version_id: str, node_type: str) -> str | None:
                row = conn.execute(
                    "SELECT partition_id FROM semantic_business_node_versions WHERE version_id=?",
                    (version_id,),
                ).fetchone()
                if row:
                    return row["partition_id"]
                if node_type in {"BusinessEvent", "CampaignPerformanceMeasurement", "Outcome"}:
                    return "business_observed"
                if node_type in {"PerformanceDisposition", "Market", "Positioning", "TermSet", "Asset", "Campaign", "Segment", "Situation", "RequiredBehavior", "Offer", "Claim", "Promise", "Mechanism"}:
                    return "business_declared"
                return None

            source_partition = partition(value["source_version_id"], source[0])
            target_partition = partition(value["target_version_id"], target[0])
            checked = validate_business_relation(
                predicate, source[0], target[0], value["qualifier"],
                source_payload=dict(source[2]), target_version_id=value["target_version_id"],
                source_partition=source_partition, target_partition=target_partition,
            )
            qualifier = checked["qualifier"]

            def qref(ref: str, field: str, allowed: set[str]) -> tuple[str, str, Mapping[str, Any], str, str | None, str, str]:
                return self._require_v31_ref(
                    conn, ref, {}, operator_id=value["operator_id"], field=field, allowed=allowed,
                )

            for field in ("evidence_version_ids", "source_artifact_version_ids"):
                for ref in qualifier.get(field, []):
                    qref(ref, field, {"EvidenceArtifact"})
            for ref in value["evidence_version_ids"]:
                qref(ref, "evidence_version_ids", {"EvidenceArtifact"})
            if qualifier.get("observer_actor_version_id") is not None:
                qref(qualifier["observer_actor_version_id"], "observer_actor_version_id", {"Actor"})
            for field in ("baseline_version_id", "comparator_version_id"):
                if qualifier.get(field) is not None:
                    qref(qualifier[field], field, {"CampaignPerformanceMeasurement"})
            if qualifier.get("mechanism_version_id") is not None:
                qref(qualifier["mechanism_version_id"], "mechanism_version_id", {"Mechanism"})
            if qualifier.get("confidence_assessment_version_id") is not None:
                assessment = qref(
                    qualifier["confidence_assessment_version_id"],
                    "confidence_assessment_version_id", {"ConfidenceAssessment"},
                )
                if assessment[2].get("subject_version_id") != value["relation_version_id"]:
                    raise ValidationError(
                        "E_RELATION_QUALIFIER_REFERENCE at /qualifier/confidence_assessment_version_id: assessment targets another version"
                    )

            actor = conn.execute(
                "SELECT node_type,operator_id FROM nodes WHERE node_id=?", (value["actor_id"],),
            ).fetchone()
            if not actor or actor["node_type"] != "Actor" or actor["operator_id"] != value["operator_id"]:
                raise ValidationError("E_RELATION_ROLE_DENIED at /actor_id: same-operator Actor required")
            role = qref(value["role_assignment_version_id"], "role_assignment_version_id", {"RoleAssignment"})
            if (role[5] not in {"captured_judgment", "ratified_knowledge"} or role[6] != "active"
                    or "store" not in role[2].get("allowed_operations", [])):
                raise ValidationError("E_RELATION_ROLE_DENIED at /role_assignment_version_id: active store role required")
            policy = qref(value["access_policy_version_id"], "access_policy_version_id", {"AccessPolicy"})
            if ("store" not in policy[2].get("operations", [])
                    or value["role_assignment_version_id"] not in policy[2].get("principal_role_assignment_version_ids", [])):
                raise ValidationError("E_RELATION_GOVERNANCE_REQUIRED at /access_policy_version_id: relation-owned store policy required")
            qref(value["consent_version_id"], "consent_version_id", {"ConsentGrant"})

            sensitivity_rank = {name: rank for rank, name in enumerate((
                "unclassified", "standard", "sensitive", "highly_sensitive", "restricted",
            ))}
            governed_versions = [value["source_version_id"], value["target_version_id"], *value["evidence_version_ids"]]
            floors = conn.execute(
                f"SELECT sensitivity FROM semantic_node_versions WHERE version_id IN ({','.join('?' for _ in governed_versions)})",
                governed_versions,
            ).fetchall()
            floor = max((sensitivity_rank[row["sensitivity"]] for row in floors), default=0)
            if sensitivity_rank[value["sensitivity"]] < floor:
                raise ValidationError("E_RELATION_SENSITIVITY_FLOOR at /sensitivity: relation lowers governed sensitivity")

            tier = provenance["authority_tier"]
            origin = provenance["origin_status"]
            minimum = checked["authority_minimum"]
            if minimum == "R" and tier != "ratified_knowledge":
                raise ValidationError("E_RELATION_ROLE_DENIED at /provenance/authority_tier: ratified authority required")
            if minimum == "J" and tier not in {"captured_judgment", "ratified_knowledge"}:
                raise ValidationError("E_RELATION_ROLE_DENIED at /provenance/authority_tier: judgment authority required")
            if tier not in {"captured_judgment", "ratified_knowledge"}:
                ceiling = {"captured": "observed_candidate", "extracted": "imported_floor", "inferred": "inferred_candidate"}[origin]
                if tier != ceiling:
                    raise ValidationError("E_BUSINESS_AUTHORITY_CEILING at /provenance/authority_tier: candidate/import ceiling exceeded")

            intent = {**value, "provenance": provenance, "qualifier": qualifier}
            if tier in {"captured_judgment", "ratified_knowledge"}:
                execution = self._consume_authority(
                    conn, approval_token, command_name="ontology.business_relation.first_write",
                    purpose="store typed business relation", intent=intent,
                    execution_fields=generated, authority_transition="business_relation_first_write",
                    subject_ids=(value["source_version_id"],), target_ids=(value["target_version_id"],),
                    source_ids=tuple(value["evidence_version_ids"]),
                    result_version_ids=(value["relation_version_id"],),
                    scope=("business_relation", predicate, checked["policy"]),
                )
            else:
                if approval_token is not None:
                    raise ValidationError("approval token cannot authorize a candidate/import business relation")
                execution = generated
            event_id, now = execution["event_id"], execution["system_time"]
            event_payload = {**intent, "system_from": now, "system_to": None}
            source_node = conn.execute(
                "SELECT node_id FROM node_versions WHERE version_id=?", (value["source_version_id"],),
            ).fetchone()[0]
            target_node = conn.execute(
                "SELECT node_id FROM node_versions WHERE version_id=?", (value["target_version_id"],),
            ).fetchone()[0]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "business_relation_first_write", value["operator_id"], now, value["valid_from"],
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload), None, origin),
            )
            conn.execute(
                "INSERT INTO edges VALUES(?,?,?,?,?,?)",
                (value["relation_id"], predicate, source_node, target_node, value["operator_id"], event_id),
            )
            relation_payload = {
                "qualifier_schema_id": value["qualifier_schema_id"], "qualifier": qualifier,
                "why": value["why"], "policy": checked["policy"], "authority_minimum": minimum,
            }
            self._insert_edge_version(
                conn,
                (value["relation_version_id"], value["relation_id"], canonical_bytes(relation_payload).decode(),
                 payload_sha256(relation_payload), origin, tier, canonical_bytes(provenance).decode(),
                 json.dumps(value["evidence_version_ids"]), value["valid_from"], value["valid_to"],
                 now, None, event_id, None),
            )
            conn.execute(
                "INSERT INTO semantic_relation_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (value["relation_version_id"], value["relation_id"], predicate, 1,
                 value["source_version_id"], value["target_version_id"], value["operator_id"],
                 value["qualifier_schema_id"], canonical_bytes(qualifier).decode(),
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload), value["valid_from"],
                 value["valid_to"], now, None, None),
            )
            conn.execute(
                "INSERT INTO semantic_business_relation_versions VALUES(?,?,?)",
                (value["relation_version_id"], checked["policy"], minimum),
            )
        return value["relation_version_id"]

    def read_business_relation(self, relation_version_id: str) -> dict[str, Any]:
        """Return one exact relation envelope with locked policy metadata."""
        with self.read_connection() as conn:
            row = conn.execute(
                """SELECT sr.envelope_json,br.policy_code,br.authority_minimum
                   FROM semantic_business_relation_versions br
                   JOIN semantic_relation_versions sr USING(relation_version_id)
                   WHERE br.relation_version_id=?""",
                (relation_version_id,),
            ).fetchone()
        if row is None:
            raise ValidationError("E_BUSINESS_REFERENCE_TYPE at /relation_version_id: relation not found")
        return {
            "policy": row["policy_code"], "authority_minimum": row["authority_minimum"],
            "envelope": json.loads(row["envelope_json"]),
        }

    def iter_business_relations(self) -> list[dict[str, Any]]:
        """Deterministic exact-version business-relation read surface."""
        with self.read_connection() as conn:
            rows = conn.execute(
                """SELECT sr.envelope_json,br.policy_code,br.authority_minimum
                   FROM semantic_business_relation_versions br
                   JOIN semantic_relation_versions sr USING(relation_version_id)
                   ORDER BY br.relation_version_id"""
            ).fetchall()
        return [
            {"policy": row["policy_code"], "authority_minimum": row["authority_minimum"],
             "envelope": json.loads(row["envelope_json"])}
            for row in rows
        ]

    def append_ontology_contradiction(
        self, envelope: Mapping[str, Any], *,
        confidence_assessment: Mapping[str, Any] | None = None,
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Append one exact-version ``contradicts@1`` RelationVersion."""
        from imprint.ontology.validators import validate_provenance_v2_1, validate_relation_identity

        required = {
            "relation_id", "relation_version_id", "predicate_id", "predicate_version",
            "source_version_id", "target_version_id", "operator_id", "actor_id",
            "role_assignment_version_id", "provenance", "evidence_version_ids", "why",
            "sensitivity", "access_policy_version_id", "consent_version_id", "valid_from",
            "valid_to", "qualifier_schema_id", "qualifier", "extensions",
        }
        if not isinstance(envelope, Mapping) or set(envelope) != required:
            raise ValidationError("E_RELATION_GOVERNANCE_REQUIRED at /: exact relation envelope required")
        value = dict(envelope)
        if value["predicate_id"] != "contradicts" or value["predicate_version"] != 1:
            raise ValidationError("E_RELATION_PREDICATE_UNKNOWN at /predicate_id: only contradicts@1 accepted here")
        validate_relation_identity(value["predicate_id"], value["qualifier_schema_id"])
        if value["qualifier_schema_id"] != "q.contradiction@1":
            raise ValidationError("E_RELATION_QUALIFIER_SCHEMA_UNKNOWN at /qualifier_schema_id: q.contradiction@1 required")
        qualifier = value["qualifier"]
        q_required = {"resolution_state", "scope_ids", "detected_by", "resolution_event_version_id"}
        if not isinstance(qualifier, Mapping):
            raise ValidationError("E_RELATION_QUALIFIER_TYPE at /qualifier: object required")
        if set(qualifier) - q_required:
            raise ValidationError("E_RELATION_QUALIFIER_UNKNOWN at /qualifier: closed qualifier")
        if q_required - set(qualifier):
            raise ValidationError("E_RELATION_QUALIFIER_CARDINALITY at /qualifier: required field missing")
        if qualifier["resolution_state"] not in {"open", "accepted_new", "retained_old", "scoped_both", "retracted"}:
            raise ValidationError("E_RELATION_QUALIFIER_VALUE at /qualifier/resolution_state: invalid state")
        if not isinstance(qualifier["scope_ids"], list) or not qualifier["scope_ids"] or len(qualifier["scope_ids"]) != len(set(qualifier["scope_ids"])):
            raise ValidationError("E_RELATION_QUALIFIER_CARDINALITY at /qualifier/scope_ids: non-empty unique array required")
        if (qualifier["resolution_state"] == "open") != (qualifier["resolution_event_version_id"] is None):
            raise ValidationError("E_RELATION_QUALIFIER_CONDITIONAL at /qualifier/resolution_event_version_id: required iff resolved")
        provenance = validate_provenance_v2_1(value["provenance"])
        assessment = self._validate_v31_envelope(confidence_assessment) if confidence_assessment is not None else None
        if assessment is None:
            raise ValidationError("E_NODE_CONDITIONAL_RULE at /confidence: contradiction requires an atomic assessment")
        if (_V31_SCHEMA_TYPES[assessment["payload_schema_id"]] != "ConfidenceAssessment"
                or assessment["payload"]["subject_version_id"] != value["relation_version_id"]
                or assessment["operator_id"] != value["operator_id"]):
            raise ValidationError("E_NODE_REFERENCE_TYPE at /confidence: assessment must target this relation version")
        if value["evidence_version_ids"] != provenance["evidence_version_ids"] or not value["evidence_version_ids"]:
            raise ValidationError("E_RELATION_GOVERNANCE_REQUIRED at /evidence_version_ids: exact provenance evidence required")
        if not isinstance(value["why"], str) or not value["why"].strip():
            raise ValidationError("E_RELATION_GOVERNANCE_REQUIRED at /why: rationale required")
        if value["sensitivity"] not in _V31_SENSITIVITY:
            raise ValidationError("E_RELATION_SENSITIVITY_FLOOR at /sensitivity: invalid sensitivity")
        self._v31_time(value["valid_from"], "valid_from")
        self._v31_time(value["valid_to"], "valid_to", nullable=True)
        self._require_configured_operator(value["operator_id"])
        generated = {
            "event_id": make_urn("event"),
            "assessment_event_id": make_urn("event"),
            "system_time": utc_now(),
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM semantic_relation_versions WHERE relation_version_id=?", (value["relation_version_id"],)).fetchone():
                raise ConflictError("relation version already exists")
            endpoints = []
            for field in ("source_version_id", "target_version_id"):
                found = self._v31_ref_type(conn, value[field], {})
                if not found or found[1] != value["operator_id"]:
                    raise ValidationError(f"E_RELATION_ENDPOINT_TYPE at /{field}: exact same-operator version required")
                endpoints.append(found)
            source_type, target_type = endpoints[0][0], endpoints[1][0]
            allowed = (
                source_type == target_type and source_type in {"Verdict", "Claim"}
            ) or (source_type == "Outcome" and target_type in {"Belief", "Claim", "Intervention", "Mechanism", "Offer", "Principle", "Promise", "Rule", "SelfModelAssertion", "Verdict"})
            if not allowed:
                raise ValidationError("E_RELATION_ENDPOINT_TYPE at /target_version_id: invalid contradicts signature")
            for evidence_id in value["evidence_version_ids"]:
                self._require_v31_ref(conn, evidence_id, {}, operator_id=value["operator_id"], field="evidence_version_ids", allowed={"EvidenceArtifact"})
            governing_role = self._require_v31_ref(conn, value["role_assignment_version_id"], {}, operator_id=value["operator_id"], field="role_assignment_version_id", allowed={"RoleAssignment"}, at=value["valid_from"])
            if governing_role[5] not in {"captured_judgment", "ratified_knowledge"} or governing_role[6] != "active" or "store" not in governing_role[2].get("allowed_operations", []):
                raise ValidationError("E_RELATION_ROLE_DENIED at /role_assignment_version_id: active store role required")
            policy = self._require_v31_ref(conn, value["access_policy_version_id"], {}, operator_id=value["operator_id"], field="access_policy_version_id", allowed={"AccessPolicy"}, at=value["valid_from"])
            if "store" not in policy[2].get("operations", []):
                raise ValidationError("E_RELATION_GOVERNANCE_REQUIRED at /access_policy_version_id: store policy required")
            authority_required = any(
                tier in {"captured_judgment", "ratified_knowledge"}
                for tier in (provenance["authority_tier"], assessment["provenance"]["authority_tier"])
            )
            if authority_required:
                execution = self._consume_authority(
                    conn, approval_token, command_name="ontology.contradiction",
                    purpose="store contradiction relation", intent={**value, "confidence_assessment": assessment},
                    execution_fields=generated,
                    authority_transition="contradiction_created", subject_ids=(value["source_version_id"],),
                    target_ids=(value["target_version_id"],), source_ids=tuple(value["evidence_version_ids"]),
                    result_version_ids=(value["relation_version_id"],), scope=tuple(qualifier["scope_ids"]),
                )
            else:
                if approval_token is not None:
                    raise ValidationError("approval token cannot authorize a non-authoritative contradiction")
                execution = generated
            event_id = execution["event_id"]
            assessment_event_id = execution["assessment_event_id"]
            now = execution["system_time"]
            event_payload = {**value, "provenance": provenance, "system_from": now, "system_to": None}
            source_node = conn.execute("SELECT node_id FROM node_versions WHERE version_id=?", (value["source_version_id"],)).fetchone()[0]
            target_node = conn.execute("SELECT node_id FROM node_versions WHERE version_id=?", (value["target_version_id"],)).fetchone()[0]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "ontology_contradiction", value["operator_id"], now, value["valid_from"],
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload), None, provenance["origin_status"]),
            )
            conn.execute("INSERT INTO edges VALUES(?,?,?,?,?,?)", (value["relation_id"], "contradicts", source_node, target_node, value["operator_id"], event_id))
            relation_payload = {"qualifier_schema_id": value["qualifier_schema_id"], "qualifier": dict(qualifier), "why": value["why"]}
            self._insert_edge_version(
                conn,
                (value["relation_version_id"], value["relation_id"], canonical_bytes(relation_payload).decode(), payload_sha256(relation_payload),
                 provenance["origin_status"], provenance["authority_tier"], canonical_bytes(provenance).decode(),
                 json.dumps(value["evidence_version_ids"]), value["valid_from"], value["valid_to"], now, None, event_id, None),
            )
            conn.execute(
                "INSERT INTO semantic_relation_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (value["relation_version_id"], value["relation_id"], "contradicts", 1,
                 value["source_version_id"], value["target_version_id"], value["operator_id"],
                 value["qualifier_schema_id"], canonical_bytes(dict(qualifier)).decode(),
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload), value["valid_from"],
                 value["valid_to"], now, None, None),
            )
            self._validate_v31_references(conn, assessment, {assessment["version_id"]: assessment}, {})
            assessment_event = {**assessment, "system_from": now, "system_to": None}
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (assessment_event_id, "ontology_contradiction_confidence", value["operator_id"], now,
                 assessment["valid_from"], canonical_bytes(assessment_event).decode(), payload_sha256(assessment_event),
                 event_id, assessment["provenance"]["origin_status"]),
            )
            conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", (assessment["record_id"], "ConfidenceAssessment", value["operator_id"], assessment_event_id))
            self._insert_node_version(
                conn,
                (assessment["version_id"], assessment["record_id"], canonical_bytes(assessment["payload"]).decode(),
                 payload_sha256(assessment["payload"]), assessment["provenance"]["origin_status"], assessment["provenance"]["authority_tier"],
                 canonical_bytes(assessment["provenance"]).decode(), json.dumps(assessment["provenance"]["evidence_version_ids"]),
                 assessment["valid_from"], assessment["valid_to"], now, None, assessment_event_id, None),
            )
            conn.execute(
                "INSERT INTO semantic_node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (assessment["version_id"], assessment["record_id"], assessment["payload_schema_id"], assessment["record_schema_version"],
                 assessment["ontology_schema_version"], canonical_bytes(assessment["provenance"]).decode(), assessment["sensitivity"],
                 assessment["access_policy_version_id"], assessment["consent_version_id"], assessment["actor_id"],
                 assessment["role_assignment_version_id"], assessment["scope_id"], None,
                 canonical_bytes(assessment_event).decode(), payload_sha256(assessment_event)),
            )
            confidence_payload = assessment["payload"]
            conn.execute(
                "INSERT INTO semantic_confidence_heads VALUES(?,?,?,?,?)",
                (value["relation_version_id"], confidence_payload["assessor_actor_version_id"],
                 confidence_payload["method"], confidence_payload["scale"], assessment["version_id"]),
            )
        return value["relation_version_id"]

    def correct_ontology_version(
        self, *, record_id: str, scope_id: str, effective_from: str,
        corrected_payload: Mapping[str, Any], correction_event_id: str,
        carry_forward_version_id: str, corrected_version_id: str,
        evidence_version_ids: Iterable[str], actor_id: str,
        role_assignment_version_id: str,
        confidence_assessment: Mapping[str, Any] | None = None,
        approval_token: Mapping[str, Any] | None = None,
    ) -> tuple[str, str]:
        """Apply the binding contract's R1 -> C1 + R2/R3 late correction."""
        from imprint.ontology.validators import validate_core_payload

        self._v31_time(effective_from, "effective_from")
        evidence = tuple(dict.fromkeys(evidence_version_ids))
        if not evidence:
            raise ValidationError("E_CUSTODY_CHAIN_INCOMPLETE at /evidence_version_ids: evidence required")
        if carry_forward_version_id == corrected_version_id:
            raise ValidationError("E_NODE_FIELD_CARDINALITY at /version_id: successor versions must differ")
        generated = {
            "event_id": make_urn("event"),
            "assessment_event_id": make_urn("event") if confidence_assessment is not None else None,
            "system_time": utc_now(),
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """SELECT n.operator_id,n.node_type,nv.*,sv.*
                   FROM semantic_node_versions sv JOIN node_versions nv USING(version_id)
                   JOIN nodes n ON n.node_id=nv.node_id
                   WHERE sv.record_id=? AND sv.scope_id=? AND nv.system_to IS NULL
                     AND nv.valid_from<=? AND (nv.valid_to IS NULL OR ?<nv.valid_to)""",
                (record_id, scope_id, effective_from, effective_from),
            ).fetchall()
            if len(rows) != 1 or rows[0]["contested_set_id"] is not None:
                raise ValidationError("E_TEMPORAL_INTERVAL_OVERLAP at /effective_from: one uncontested current version required")
            current = rows[0]
            if not current["valid_from"] < effective_from or (current["valid_to"] is not None and effective_from >= current["valid_to"]):
                raise ValidationError("E_TEMPORAL_INTERVAL_OVERLAP at /effective_from: correction must split current interval")
            self._require_configured_operator(current["operator_id"])
            actor = conn.execute(
                "SELECT node_type,operator_id FROM nodes WHERE node_id=?", (actor_id,),
            ).fetchone()
            if not actor or actor["node_type"] != "Actor" or actor["operator_id"] != current["operator_id"]:
                raise ValidationError("E_RELATION_ROLE_DENIED at /actor_id: same-operator Actor required")
            role = self._v31_ref_type(conn, role_assignment_version_id, {})
            if not role or role[0] != "RoleAssignment" or role[1] != current["operator_id"]:
                raise ValidationError("E_RELATION_ROLE_DENIED at /role_assignment_version_id: active role required")
            for item in evidence:
                self._require_v31_ref(conn, item, {}, operator_id=current["operator_id"], field="evidence_version_ids", allowed={"EvidenceArtifact"})
            replacement = validate_core_payload(current["payload_schema_id"], corrected_payload)
            prior_payload = json.loads(current["payload_json"])
            prior_provenance_v2_1 = json.loads(current["provenance_v2_1_json"])
            node_type = current["node_type"]
            must_assess = (
                node_type == "ExpectedOutcome"
                or (prior_provenance_v2_1["origin_status"] in {"inferred", "extracted"}
                    and node_type not in _CONFIDENCE_FORBIDDEN)
            )
            assessment = self._validate_v31_envelope(confidence_assessment) if confidence_assessment is not None else None
            if must_assess and assessment is None:
                raise ValidationError("E_NODE_CONDITIONAL_RULE at /confidence: corrected version requires a new atomic assessment")
            if assessment is not None:
                if _V31_SCHEMA_TYPES[assessment["payload_schema_id"]] != "ConfidenceAssessment":
                    raise ValidationError("E_NODE_REFERENCE_TYPE at /confidence: ConfidenceAssessment required")
                if assessment["payload"]["subject_version_id"] != corrected_version_id:
                    raise ValidationError("E_NODE_REFERENCE_TYPE at /confidence/subject_version_id: must target corrected exact version")
                if assessment["operator_id"] != current["operator_id"] or assessment["record_id"] == record_id:
                    raise ValidationError("E_NODE_REFERENCE_TYPE at /confidence: distinct same-operator assessment required")
            intent = {
                "record_id": record_id, "scope_id": scope_id, "effective_from": effective_from,
                "prior_version_id": current["version_id"], "correction_event_id": correction_event_id,
                "carry_forward_version_id": carry_forward_version_id, "corrected_version_id": corrected_version_id,
                "corrected_payload": replacement, "evidence_version_ids": list(evidence),
                "actor_id": actor_id, "role_assignment_version_id": role_assignment_version_id,
                "confidence_assessment": assessment,
            }
            execution = self._consume_authority(
                conn, approval_token, command_name="ontology.correct_version",
                purpose="apply bitemporal semantic correction", intent=intent,
                execution_fields=generated,
                prior_state={"version_id": current["version_id"], "payload_sha256": current["payload_sha256"]},
                authority_transition="semantic_correction", subject_ids=(record_id,),
                source_ids=evidence, result_version_ids=(carry_forward_version_id, corrected_version_id),
                scope=(scope_id,),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "ontology_correction", current["operator_id"], now, effective_from,
                 canonical_bytes(intent).decode(), payload_sha256(intent), current["event_id"], current["provenance_status"]),
            )
            conn.execute("UPDATE node_versions SET system_to=? WHERE version_id=?", (now, current["version_id"]))
            provenance_json = current["provenance_json"]
            provenance_v2_1_json = current["provenance_v2_1_json"]
            common = (
                record_id, current["provenance_status"], current["authority_tier"], provenance_json,
                json.dumps(list(evidence)), now, None, event_id, current["version_id"],
            )
            self._insert_node_version(
                conn,
                (carry_forward_version_id, record_id, canonical_bytes(prior_payload).decode(), payload_sha256(prior_payload),
                 common[1], common[2], common[3], common[4], current["valid_from"], effective_from,
                 common[5], common[6], common[7], common[8]),
            )
            self._insert_node_version(
                conn,
                (corrected_version_id, record_id, canonical_bytes(replacement).decode(), payload_sha256(replacement),
                 common[1], common[2], common[3], common[4], effective_from, current["valid_to"],
                 common[5], common[6], common[7], common[8]),
            )
            for successor_id, payload, start, end in (
                (carry_forward_version_id, prior_payload, current["valid_from"], effective_from),
                (corrected_version_id, replacement, effective_from, current["valid_to"]),
            ):
                successor_envelope = {
                    "record_id": record_id, "version_id": successor_id,
                    "payload_schema_id": current["payload_schema_id"],
                    "record_schema_version": current["record_schema_version"],
                    "ontology_schema_version": current["ontology_schema_version"],
                    "operator_id": current["operator_id"], "payload": payload,
                    "provenance": json.loads(provenance_v2_1_json), "sensitivity": current["sensitivity"],
                    "access_policy_version_id": current["access_policy_version_id"],
                    "consent_version_id": current["consent_version_id"], "actor_id": actor_id,
                    "role_assignment_version_id": role_assignment_version_id, "valid_from": start,
                    "valid_to": end, "scope_id": scope_id, "extensions": {},
                    "system_from": now, "system_to": None,
                }
                conn.execute(
                    "INSERT INTO semantic_node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (successor_id, record_id, current["payload_schema_id"], current["record_schema_version"],
                     current["ontology_schema_version"], provenance_v2_1_json, current["sensitivity"],
                     current["access_policy_version_id"], current["consent_version_id"], actor_id,
                     role_assignment_version_id, scope_id, None, canonical_bytes(successor_envelope).decode(),
                     payload_sha256(successor_envelope)),
                )
            diff = {"before_sha256": current["payload_sha256"], "after_sha256": payload_sha256(replacement)}
            conn.execute(
                "INSERT INTO semantic_correction_events VALUES(?,?,?,?,?,?,?,?,?,?)",
                (correction_event_id, record_id, scope_id, current["version_id"], carry_forward_version_id,
                 corrected_version_id, effective_from, json.dumps(list(evidence)), canonical_bytes(diff).decode(), event_id),
            )
            if assessment is not None:
                pending_subject = {
                    **assessment,
                    "record_id": record_id,
                    "version_id": corrected_version_id,
                    "payload_schema_id": current["payload_schema_id"],
                    "payload": replacement,
                    "valid_from": effective_from,
                    "valid_to": current["valid_to"],
                }
                self._validate_v31_references(
                    conn, assessment,
                    {corrected_version_id: pending_subject, assessment["version_id"]: assessment}, {},
                )
                assessment_event_id = execution["assessment_event_id"]
                assessment_event = {**assessment, "system_from": now, "system_to": None}
                conn.execute(
                    "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                    (assessment_event_id, "ontology_confidence_renewal", current["operator_id"], now,
                     assessment["valid_from"], canonical_bytes(assessment_event).decode(),
                     payload_sha256(assessment_event), event_id, assessment["provenance"]["origin_status"]),
                )
                conn.execute(
                    "INSERT INTO nodes VALUES(?,?,?,?)",
                    (assessment["record_id"], "ConfidenceAssessment", current["operator_id"], assessment_event_id),
                )
                self._insert_node_version(
                    conn,
                    (assessment["version_id"], assessment["record_id"], canonical_bytes(assessment["payload"]).decode(),
                     payload_sha256(assessment["payload"]), assessment["provenance"]["origin_status"],
                     assessment["provenance"]["authority_tier"], canonical_bytes(assessment["provenance"]).decode(),
                     json.dumps(assessment["provenance"]["evidence_version_ids"]), assessment["valid_from"],
                     assessment["valid_to"], now, None, assessment_event_id, None),
                )
                conn.execute(
                    "INSERT INTO semantic_node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (assessment["version_id"], assessment["record_id"], assessment["payload_schema_id"],
                     assessment["record_schema_version"], assessment["ontology_schema_version"],
                     canonical_bytes(assessment["provenance"]).decode(), assessment["sensitivity"],
                     assessment["access_policy_version_id"], assessment["consent_version_id"], assessment["actor_id"],
                     assessment["role_assignment_version_id"], assessment["scope_id"], None,
                     canonical_bytes(assessment_event).decode(), payload_sha256(assessment_event)),
                )
                confidence_payload = assessment["payload"]
                conn.execute(
                    """INSERT INTO semantic_confidence_heads VALUES(?,?,?,?,?)
                       ON CONFLICT(subject_version_id,assessor_actor_version_id,method,scale)
                       DO UPDATE SET assessment_version_id=excluded.assessment_version_id""",
                    (confidence_payload["subject_version_id"], confidence_payload["assessor_actor_version_id"],
                     confidence_payload["method"], confidence_payload["scale"], assessment["version_id"]),
                )
        return carry_forward_version_id, corrected_version_id

    def ontology_as_of(
        self, record_id: str, scope_id: str, *, valid_at: str, system_at: str,
    ) -> dict[str, Any]:
        """Resolve one bitemporal coordinate, returning no silent contest winner."""
        self._v31_time(valid_at, "valid_at")
        self._v31_time(system_at, "system_at")
        with self.connect() as conn:
            rows = conn.execute(
                """SELECT nv.*,sv.payload_schema_id,sv.scope_id,sv.contested_set_id
                   FROM semantic_node_versions sv JOIN node_versions nv USING(version_id)
                   WHERE sv.record_id=? AND sv.scope_id=?
                     AND nv.valid_from<=? AND (nv.valid_to IS NULL OR ?<nv.valid_to)
                     AND nv.system_from<=? AND (nv.system_to IS NULL OR ?<nv.system_to)
                   ORDER BY nv.version_id""",
                (record_id, scope_id, valid_at, valid_at, system_at, system_at),
            ).fetchall()
        if not rows:
            return {"record_id": record_id, "scope_id": scope_id, "state": "absent", "versions": []}
        contested = {row["contested_set_id"] for row in rows}
        if len(rows) > 1 and (None in contested or len(contested) != 1):
            raise ValidationError("E_TEMPORAL_INTERVAL_OVERLAP at /: unauthorized operative overlap")
        versions = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            versions.append(item)
        return {
            "record_id": record_id, "scope_id": scope_id,
            "state": "contested" if len(versions) > 1 else "resolved",
            "winner": None if len(versions) > 1 else versions[0]["version_id"],
            "versions": versions,
        }

    def contest_ontology_version(
        self, *, record_id: str, scope_id: str, contested_set_id: str,
        contest_event_id: str, preserved_version_id: str, competing_version_id: str,
        competing_payload: Mapping[str, Any], evidence_version_ids: Iterable[str],
        actor_id: str, role_assignment_version_id: str,
        confidence_assessments: Iterable[Mapping[str, Any]] = (),
        approval_token: Mapping[str, Any] | None = None,
    ) -> tuple[str, str]:
        """Append an explicit competing set and return both members, never a winner."""
        from imprint.ontology.validators import validate_core_payload

        if not all(isinstance(item, str) and ":" in item for item in (
            record_id, scope_id, contested_set_id, contest_event_id,
            preserved_version_id, competing_version_id,
        )):
            raise ValidationError("E_NODE_REFERENCE_VERSION_REQUIRED at /: exact contest IDs required")
        if preserved_version_id == competing_version_id:
            raise ValidationError("E_NODE_FIELD_CARDINALITY at /version_id: competing versions must differ")
        evidence = tuple(dict.fromkeys(evidence_version_ids))
        if not evidence:
            raise ValidationError("E_CUSTODY_CHAIN_INCOMPLETE at /evidence_version_ids: evidence required")
        assessments = tuple(self._validate_v31_envelope(item) for item in confidence_assessments)
        generated = {
            "event_id": make_urn("event"), "system_time": utc_now(),
            "assessment_event_ids": [make_urn("event") for _ in assessments],
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """SELECT n.operator_id,n.node_type,nv.*,sv.*
                   FROM semantic_node_versions sv JOIN node_versions nv USING(version_id)
                   JOIN nodes n ON n.node_id=nv.node_id
                   WHERE sv.record_id=? AND sv.scope_id=? AND nv.system_to IS NULL""",
                (record_id, scope_id),
            ).fetchall()
            if len(rows) != 1 or rows[0]["contested_set_id"] is not None:
                raise ValidationError("E_TEMPORAL_INTERVAL_OVERLAP at /: one uncontested current version required")
            current = rows[0]
            self._require_configured_operator(current["operator_id"])
            actor = conn.execute("SELECT node_type,operator_id FROM nodes WHERE node_id=?", (actor_id,)).fetchone()
            if not actor or actor["node_type"] != "Actor" or actor["operator_id"] != current["operator_id"]:
                raise ValidationError("E_RELATION_ROLE_DENIED at /actor_id: same-operator Actor required")
            role = self._v31_ref_type(conn, role_assignment_version_id, {})
            if (not role or role[0] != "RoleAssignment" or role[1] != current["operator_id"]
                    or role[5] not in {"captured_judgment", "ratified_knowledge"}
                    or role[6] != "active" or "store" not in role[2].get("allowed_operations", [])):
                raise ValidationError("E_RELATION_ROLE_DENIED at /role_assignment_version_id: active role required")
            for item in evidence:
                self._require_v31_ref(conn, item, {}, operator_id=current["operator_id"], field="evidence_version_ids", allowed={"EvidenceArtifact"})
            replacement = validate_core_payload(current["payload_schema_id"], competing_payload)
            prior_payload = json.loads(current["payload_json"])
            provenance_v2_1 = json.loads(current["provenance_v2_1_json"])
            must_assess = (
                current["node_type"] == "ExpectedOutcome"
                or (provenance_v2_1["origin_status"] in {"inferred", "extracted"}
                    and current["node_type"] not in _CONFIDENCE_FORBIDDEN)
            )
            by_subject: dict[str, list[Mapping[str, Any]]] = {}
            for assessment in assessments:
                if (_V31_SCHEMA_TYPES[assessment["payload_schema_id"]] != "ConfidenceAssessment"
                        or assessment["operator_id"] != current["operator_id"]):
                    raise ValidationError("E_NODE_REFERENCE_TYPE at /confidence_assessments: same-operator assessment required")
                by_subject.setdefault(assessment["payload"]["subject_version_id"], []).append(assessment)
            if must_assess and (
                not by_subject.get(preserved_version_id) or not by_subject.get(competing_version_id)
                or set(by_subject) != {preserved_version_id, competing_version_id}
            ):
                raise ValidationError("E_NODE_CONDITIONAL_RULE at /confidence_assessments: each contested successor requires assessment")
            intent = {
                "record_id": record_id, "scope_id": scope_id, "contested_set_id": contested_set_id,
                "contest_event_id": contest_event_id, "prior_version_id": current["version_id"],
                "preserved_version_id": preserved_version_id, "competing_version_id": competing_version_id,
                "competing_payload": replacement, "evidence_version_ids": list(evidence),
                "actor_id": actor_id, "role_assignment_version_id": role_assignment_version_id,
                "confidence_assessments": list(assessments),
            }
            execution = self._consume_authority(
                conn, approval_token, command_name="ontology.contest_version",
                purpose="append contested semantic versions", intent=intent,
                execution_fields=generated,
                prior_state={"version_id": current["version_id"], "payload_sha256": current["payload_sha256"]},
                authority_transition="semantic_contested", subject_ids=(record_id,), source_ids=evidence,
                result_version_ids=(preserved_version_id, competing_version_id), scope=(scope_id,),
            )
            event_id, now = execution["event_id"], execution["system_time"]
            assessment_event_ids = execution["assessment_event_ids"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "ontology_contested", current["operator_id"], now, current["valid_from"],
                 canonical_bytes(intent).decode(), payload_sha256(intent), current["event_id"], current["provenance_status"]),
            )
            conn.execute("UPDATE node_versions SET system_to=? WHERE version_id=?", (now, current["version_id"]))
            for successor_id, payload in ((preserved_version_id, prior_payload), (competing_version_id, replacement)):
                self._insert_node_version(
                    conn,
                    (successor_id, record_id, canonical_bytes(payload).decode(), payload_sha256(payload),
                     current["provenance_status"], current["authority_tier"], current["provenance_json"],
                     json.dumps(list(evidence)), current["valid_from"], current["valid_to"], now, None,
                     event_id, current["version_id"]),
                )
                successor_envelope = {
                    "record_id": record_id, "version_id": successor_id,
                    "payload_schema_id": current["payload_schema_id"],
                    "record_schema_version": current["record_schema_version"],
                    "ontology_schema_version": current["ontology_schema_version"],
                    "operator_id": current["operator_id"], "payload": payload,
                    "provenance": provenance_v2_1, "sensitivity": current["sensitivity"],
                    "access_policy_version_id": current["access_policy_version_id"],
                    "consent_version_id": current["consent_version_id"], "actor_id": actor_id,
                    "role_assignment_version_id": role_assignment_version_id, "valid_from": current["valid_from"],
                    "valid_to": current["valid_to"], "scope_id": scope_id, "extensions": {},
                    "system_from": now, "system_to": None, "contested_set_id": contested_set_id,
                }
                conn.execute(
                    "INSERT INTO semantic_node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (successor_id, record_id, current["payload_schema_id"], current["record_schema_version"],
                     current["ontology_schema_version"], current["provenance_v2_1_json"], current["sensitivity"],
                     current["access_policy_version_id"], current["consent_version_id"], actor_id,
                     role_assignment_version_id, scope_id, contested_set_id,
                     canonical_bytes(successor_envelope).decode(), payload_sha256(successor_envelope)),
                )
            conn.execute(
                "INSERT INTO semantic_contest_events VALUES(?,?,?,?,?,?,?,?,?)",
                (contest_event_id, contested_set_id, record_id, scope_id, current["version_id"],
                 preserved_version_id, competing_version_id, json.dumps(list(evidence)), event_id),
            )
            pending = {
                preserved_version_id: {"record_id": record_id, "payload_schema_id": current["payload_schema_id"], "operator_id": current["operator_id"], "payload": prior_payload, "valid_from": current["valid_from"], "valid_to": current["valid_to"], "provenance": provenance_v2_1},
                competing_version_id: {"record_id": record_id, "payload_schema_id": current["payload_schema_id"], "operator_id": current["operator_id"], "payload": replacement, "valid_from": current["valid_from"], "valid_to": current["valid_to"], "provenance": provenance_v2_1},
            }
            for assessment, assessment_event_id in zip(assessments, assessment_event_ids, strict=True):
                self._validate_v31_references(conn, assessment, {**pending, assessment["version_id"]: assessment}, {})
                assessment_event = {**assessment, "system_from": now, "system_to": None}
                conn.execute(
                    "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                    (assessment_event_id, "ontology_contest_confidence", current["operator_id"], now,
                     assessment["valid_from"], canonical_bytes(assessment_event).decode(), payload_sha256(assessment_event),
                     event_id, assessment["provenance"]["origin_status"]),
                )
                conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", (assessment["record_id"], "ConfidenceAssessment", current["operator_id"], assessment_event_id))
                self._insert_node_version(
                    conn,
                    (assessment["version_id"], assessment["record_id"], canonical_bytes(assessment["payload"]).decode(),
                     payload_sha256(assessment["payload"]), assessment["provenance"]["origin_status"], assessment["provenance"]["authority_tier"],
                     canonical_bytes(assessment["provenance"]).decode(), json.dumps(assessment["provenance"]["evidence_version_ids"]),
                     assessment["valid_from"], assessment["valid_to"], now, None, assessment_event_id, None),
                )
                conn.execute(
                    "INSERT INTO semantic_node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (assessment["version_id"], assessment["record_id"], assessment["payload_schema_id"], assessment["record_schema_version"],
                     assessment["ontology_schema_version"], canonical_bytes(assessment["provenance"]).decode(), assessment["sensitivity"],
                     assessment["access_policy_version_id"], assessment["consent_version_id"], assessment["actor_id"],
                     assessment["role_assignment_version_id"], assessment["scope_id"], None,
                     canonical_bytes(assessment_event).decode(), payload_sha256(assessment_event)),
                )
                confidence = assessment["payload"]
                conn.execute(
                    "INSERT INTO semantic_confidence_heads VALUES(?,?,?,?,?)",
                    (confidence["subject_version_id"], confidence["assessor_actor_version_id"],
                     confidence["method"], confidence["scale"], assessment["version_id"]),
                )
        return preserved_version_id, competing_version_id

    def current_nodes(self, types: Iterable[str] | None = None) -> list[dict[str, Any]]:
        params: list[Any] = []
        where = "WHERE nv.system_to IS NULL"
        if types:
            values = list(types)
            where += f" AND n.node_type IN ({','.join('?' for _ in values)})"
            params.extend(values)
        query = f"""
          SELECT n.node_id,n.node_type,n.operator_id,nv.version_id,nv.payload_json,nv.payload_sha256,
                 nv.provenance_status,nv.authority_tier,nv.provenance_json,nv.evidence_json,nv.valid_from,nv.valid_to,
                 nv.system_from,nv.system_to,nv.event_id
          FROM nodes n JOIN node_versions nv USING(node_id) {where}
          ORDER BY n.node_type,n.node_id
        """
        with self.read_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            item["provenance"] = json.loads(item.pop("provenance_json"))
            item["evidence"] = json.loads(item.pop("evidence_json"))
            result.append(item)
        return result

    @staticmethod
    def _domain_node_id(operator_id: str, domain_id: str) -> str:
        value = uuid.uuid5(uuid.NAMESPACE_URL, f"imprint-domain:{operator_id}:{domain_id}")
        return f"urn:imprint:domain:{value}"

    @staticmethod
    def _require_actor(actor_id: str) -> str:
        if not isinstance(actor_id, str) or not actor_id.strip():
            raise ValidationError("actor identity is required")
        return actor_id.strip()

    @staticmethod
    def _require_evidence(conn, evidence_ids: Iterable[str]) -> list[str]:
        values = list(dict.fromkeys(evidence_ids))
        if not values:
            raise ValidationError("at least one canonical evidence reference is required")
        for evidence_id in values:
            known = conn.execute(
                "SELECT 1 FROM nodes WHERE node_id=? AND node_type='Evidence'", (evidence_id,)
            ).fetchone()
            known = known or conn.execute(
                "SELECT 1 FROM source_receipts WHERE source_id=?", (evidence_id,)
            ).fetchone()
            if not known:
                raise ValidationError("evidence must exist in canonical Evidence or source receipts")
        return values

    def add_domain(
        self, *, domain_id: str, public_label: str, description: str,
        evidence_ids: list[str], operator_id: str, actor_id: str,
        valid_from: str | None = None, approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Create one canonical, operator-declared Domain with a stable local ID."""
        if self.expected_operator_id is not None and operator_id != self.expected_operator_id:
            raise ValidationError("domain operator does not match configured identity")
        if not isinstance(domain_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", domain_id):
            raise ValidationError("domain_id must be a safe lowercase identifier")
        if not public_label.strip() or not description.strip():
            raise ValidationError("domain public_label and description are required")
        actor_id = self._require_actor(actor_id)
        if actor_id != operator_id:
            raise ValidationError("domain authority actor must be the configured operator")
        node_id = self._domain_node_id(operator_id, domain_id)
        generated = {
            "event_id": make_urn("event"), "version_id": make_urn("node-version"),
            "system_time": utc_now(),
        }
        valid_from = valid_from or generated["system_time"]
        generated["valid_from"] = valid_from
        payload = {
            "domain_id": domain_id, "public_label": public_label.strip(),
            "description": description.strip(), "selected": False, "frozen": False,
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            evidence_ids = self._require_evidence(conn, evidence_ids)
            if conn.execute("SELECT 1 FROM nodes WHERE node_id=?", (node_id,)).fetchone():
                raise ConflictError("domain already exists")
            event_payload = {"node_id": node_id, "payload": payload, "evidence_ids": evidence_ids, "actor_id": actor_id}
            execution = self._consume_authority(
                conn, approval_token, command_name="domain.add", purpose="add canonical domain",
                intent=event_payload, authority_transition="none_to_captured_judgment",
                execution_fields=generated,
                subject_ids=(node_id,), source_ids=tuple(evidence_ids), scope=("domain",),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            valid_from = execution["valid_from"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "domain_added", operator_id, now, valid_from,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload), None, "captured"),
            )
            conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", (node_id, "Domain", operator_id, event_id))
            self._insert_node_version(
                conn,
                (execution["version_id"], node_id, canonical_bytes(payload).decode(), payload_sha256(payload),
                 "captured", "captured_judgment", canonical_bytes(version_provenance(
                     status="captured", authority_tier="captured_judgment", actor_class="operator",
                     actor_id=actor_id, mechanism="explicit_domain_add", event_id=event_id,
                 )).decode(), json.dumps(evidence_ids), valid_from, None, now, None, event_id, None),
            )
        return node_id

    def list_domains(self) -> list[dict[str, Any]]:
        return self.current_nodes(["Domain"])

    def _change_domain_state(
        self, domain_id: str, *, actor_id: str, action: str,
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        actor_id = self._require_actor(actor_id)
        if action not in {"select", "freeze"}:
            raise ValidationError("unsupported domain state transition")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute("""
              SELECT n.node_id,n.operator_id,nv.* FROM nodes n JOIN node_versions nv USING(node_id)
              WHERE n.node_type='Domain' AND nv.system_to IS NULL ORDER BY n.node_id
            """).fetchall()
            selected = None
            for row in rows:
                payload = json.loads(row["payload_json"])
                if payload.get("domain_id") == domain_id:
                    selected = row
                    break
            if selected is None:
                raise ValidationError("canonical Domain does not exist")
            self._require_configured_operator(selected["operator_id"])
            if actor_id != selected["operator_id"]:
                raise ValidationError("domain authority actor must be the configured operator")
            selected_payload = json.loads(selected["payload_json"])
            if action == "freeze" and selected_payload.get("frozen") is True:
                raise ConflictError("domain is already frozen")
            event_payload = {"domain_id": domain_id, "node_id": selected["node_id"], "actor_id": actor_id, "action": action}
            affected = rows if action == "select" else [selected]
            changed_rows = []
            for row in affected:
                prior_payload = json.loads(row["payload_json"])
                next_payload = dict(prior_payload)
                next_payload["selected" if action == "select" else "frozen"] = (
                    row["node_id"] == selected["node_id"] if action == "select" else True
                )
                if next_payload != prior_payload:
                    changed_rows.append(row["node_id"])
            generated = {
                "event_id": make_urn("event"), "system_time": utc_now(),
                "version_ids": {node: make_urn("node-version") for node in changed_rows},
            }
            execution = self._consume_authority(
                conn, approval_token, command_name=f"domain.{action}", purpose=f"{action} canonical domain",
                intent=event_payload, prior_state=json.loads(selected["payload_json"]),
                execution_fields=generated,
                authority_transition=f"domain_{action}", subject_ids=(selected["node_id"],),
                scope=("domain",), field_paths=(f"/{'selected' if action == 'select' else 'frozen'}",),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, {"select": "domain_selected", "freeze": "domain_frozen"}[action],
                 selected["operator_id"], now, now,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload), selected["event_id"], "captured"),
            )
            for row in affected:
                payload = json.loads(row["payload_json"])
                new_payload = dict(payload)
                if action == "select":
                    new_payload["selected"] = row["node_id"] == selected["node_id"]
                else:
                    new_payload["frozen"] = True
                if new_payload == payload:
                    continue
                conn.execute("UPDATE node_versions SET system_to=? WHERE version_id=?", (now, row["version_id"]))
                self._insert_node_version(
                    conn,
                    (execution["version_ids"][row["node_id"]], row["node_id"], canonical_bytes(new_payload).decode(),
                     payload_sha256(new_payload), "captured", "captured_judgment",
                     canonical_bytes(version_provenance(
                         status="captured", authority_tier="captured_judgment", actor_class="operator",
                         actor_id=actor_id, mechanism=f"explicit_domain_{action}", event_id=event_id,
                     )).decode(), row["evidence_json"], row["valid_from"], row["valid_to"],
                     now, None, event_id, row["version_id"]),
                )
        return event_id

    def select_domain(self, domain_id: str, *, actor_id: str, approval_token=None) -> str:
        return self._change_domain_state(domain_id, actor_id=actor_id, action="select", approval_token=approval_token)

    def freeze_domain(self, domain_id: str, *, actor_id: str, approval_token=None) -> str:
        return self._change_domain_state(domain_id, actor_id=actor_id, action="freeze", approval_token=approval_token)

    def add_transition(
        self, relation: str, source_id: str, target_id: str, *, reason: str,
        evidence_ids: list[str], actor_id: str, approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Append an explicit contradiction or supersession without erasing history."""
        if relation not in {"contradicts", "supersedes"}:
            raise ValidationError("relation must be contradicts or supersedes")
        if source_id == target_id:
            raise ValidationError("transition endpoints must be different")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationError("transition reason is required")
        actor_id = self._require_actor(actor_id)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            evidence_ids = self._require_evidence(conn, evidence_ids)
            endpoints = conn.execute("""
              SELECT n.node_id,n.node_type,n.operator_id,nv.version_id,nv.event_id
              FROM nodes n JOIN node_versions nv USING(node_id)
              WHERE n.node_id IN (?,?) AND nv.system_to IS NULL
            """, (source_id, target_id)).fetchall()
            by_id = {row["node_id"]: row for row in endpoints}
            if set(by_id) != {source_id, target_id}:
                raise ValidationError("both transition endpoints must be current canonical nodes")
            if relation == "supersedes" and by_id[source_id]["node_type"] != by_id[target_id]["node_type"]:
                raise ValidationError("supersession endpoints must have the same node type")
            operator_id = by_id[source_id]["operator_id"]
            if by_id[target_id]["operator_id"] != operator_id:
                raise ValidationError("transition endpoints must belong to the same operator")
            if self.expected_operator_id is not None and operator_id != self.expected_operator_id:
                raise ValidationError("transition operator does not match configured identity")
            if actor_id != operator_id:
                raise ValidationError("transition authority actor must be the configured operator")
            payload = {
                "relation": relation, "source_id": source_id, "target_id": target_id,
                "reason": reason.strip(), "evidence_ids": evidence_ids, "actor_id": actor_id,
            }
            generated = {
                "event_id": make_urn("event"), "edge_id": make_urn("edge"),
                "edge_version_id": make_urn("edge-version"), "system_time": utc_now(),
            }
            execution = self._consume_authority(
                conn, approval_token, command_name=f"transition.{relation}",
                purpose=f"record {relation} transition", intent=payload,
                execution_fields=generated,
                prior_state={"source_version_id": by_id[source_id]["version_id"], "target_version_id": by_id[target_id]["version_id"]},
                authority_transition=relation, subject_ids=(source_id,), target_ids=(target_id,),
                source_ids=tuple(evidence_ids), scope=("transition",),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, relation, operator_id, now, now, canonical_bytes(payload).decode(),
                 payload_sha256(payload), by_id[source_id]["event_id"], "captured"),
            )
            edge_id = execution["edge_id"]
            edge_payload = {"relation": relation, "reason": reason.strip()}
            conn.execute("INSERT INTO edges VALUES(?,?,?,?,?,?)", (edge_id, relation, source_id, target_id, operator_id, event_id))
            self._insert_edge_version(
                conn,
                (execution["edge_version_id"], edge_id, canonical_bytes(edge_payload).decode(),
                 payload_sha256(edge_payload), "captured", "captured_judgment",
                 canonical_bytes(version_provenance(
                     status="captured", authority_tier="captured_judgment", actor_class="operator",
                     actor_id=actor_id, mechanism="explicit_transition", event_id=event_id, relation=relation,
                 )).decode(), json.dumps(evidence_ids), now, None, now, None, event_id, None),
            )
            if relation == "supersedes":
                conn.execute(
                    "UPDATE node_versions SET valid_to=?,system_to=? WHERE version_id=?",
                    (now, now, by_id[target_id]["version_id"]),
                )
                conn.execute("""
                  UPDATE edge_versions SET system_to=? WHERE edge_id IN (
                    SELECT edge_id FROM edges WHERE (source_id=? OR target_id=?) AND edge_id<>?
                  ) AND system_to IS NULL
                """, (now, target_id, target_id, edge_id))
        return edge_id

    def append_derived_node(
        self,
        *,
        node_type: str,
        payload: dict[str, Any],
        provenance_status: str,
        authority_tier: str,
        evidence_ids: list[str],
        operator_id: str,
        valid_from: str,
        proposed_by: str,
        model: str | None = None,
        prompt_recipe: str | None = None,
    ) -> str:
        """Append an extracted or inferred object after deterministic validation."""
        if self.expected_operator_id is not None and operator_id != self.expected_operator_id:
            raise ValidationError("derived operator does not match configured identity")
        if provenance_status not in {"extracted", "inferred"}:
            raise ValidationError("derived append accepts only extracted or inferred")
        if provenance_status == "extracted" and not evidence_ids:
            raise ValidationError("extracted objects require evidence")
        if node_type == "Pattern" and len(set(evidence_ids)) < 2:
            raise ValidationError("Pattern requires evidence from at least two cases")
        if node_type not in DERIVED_NODE_TYPES:
            raise ValidationError("unsupported derived ontology node type")
        allowed_tiers = {"inferred": {"inferred_candidate", "observed_candidate"}, "extracted": {"imported_floor", "observed_candidate"}}
        if authority_tier not in allowed_tiers[provenance_status]:
            raise ValidationError("authority tier is incompatible with provenance status")
        if not proposed_by or not proposed_by.strip():
            raise ValidationError("proposed_by is required")
        try:
            parsed_valid_from = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValidationError("valid_from must be an RFC3339 timestamp") from exc
        if parsed_valid_from.tzinfo is None:
            raise ValidationError("valid_from must include timezone")
        node_id = make_urn(node_type.lower())
        event_id = make_urn("event")
        now = utc_now()
        event_payload = {
            "node_id": node_id,
            "node_type": node_type,
            "payload": payload,
            "evidence_ids": evidence_ids,
            "proposed_by": proposed_by,
            "authority_tier": authority_tier,
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for evidence_id in set(evidence_ids):
                known = conn.execute("SELECT 1 FROM nodes WHERE node_id=? AND node_type='Evidence'", (evidence_id,)).fetchone()
                known = known or conn.execute("SELECT 1 FROM source_receipts WHERE source_id=?", (evidence_id,)).fetchone()
                if not known:
                    raise ValidationError("derived evidence must exist in canonical Evidence or source receipts")
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, provenance_status, operator_id, now, valid_from,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload), None,
                 provenance_status),
            )
            conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", (node_id, node_type, operator_id, event_id))
            self._insert_node_version(
                conn,
                (make_urn("node-version"), node_id, canonical_bytes(payload).decode(), payload_sha256(payload),
                 provenance_status, authority_tier, canonical_bytes(version_provenance(
                     status=provenance_status, authority_tier=authority_tier,
                     actor_class="model" if model else "software", actor_id=proposed_by,
                     mechanism="validated_proposal", event_id=event_id, model=model,
                     prompt_recipe=prompt_recipe, proposal_id=event_id,
                 )).decode(), json.dumps(evidence_ids), valid_from, None,
                 now, None, event_id, None),
            )
        return node_id

    def append_semantic_node(
        self, contract: dict[str, Any], *, valid_from: str,
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Persist one fully typed semantic contract through the canonical writer."""
        value = validate_node_contract(contract)
        try:
            parsed_valid_from = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValidationError("valid_from must be an RFC3339 timestamp") from exc
        if parsed_valid_from.tzinfo is None:
            raise ValidationError("valid_from must include timezone")
        operator_id = value["operator_id"]
        if self.expected_operator_id is not None and operator_id != self.expected_operator_id:
            raise ValidationError("semantic node operator does not match configured identity")
        node_id = value["node_id"]
        node_type = value["node_type"]
        payload = value["payload"]
        provenance = value["provenance"]
        evidence_ids = provenance["evidence_ids"]
        generated = {
            "event_id": make_urn("event"), "version_id": make_urn("node-version"),
            "system_time": utc_now(),
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM nodes WHERE node_id=?", (node_id,)).fetchone():
                raise ConflictError("semantic node already exists")
            if evidence_ids:
                self._require_evidence(conn, evidence_ids)

            def node_lookup(identifier: str) -> tuple[str, str] | None:
                row = conn.execute(
                    "SELECT node_type,operator_id FROM nodes WHERE node_id=?",
                    (identifier,),
                ).fetchone()
                if row:
                    return row["node_type"], row["operator_id"]
                receipt = conn.execute(
                    """SELECT e.operator_id FROM source_receipts sr
                       JOIN events e USING(event_id) WHERE sr.source_id=?""",
                    (identifier,),
                ).fetchone()
                return ("Evidence", receipt["operator_id"]) if receipt else None

            def version_lookup(identifier: str) -> tuple[str, str] | None:
                row = conn.execute(
                    """SELECT nv.node_id,n.operator_id FROM node_versions nv
                       JOIN nodes n USING(node_id) WHERE nv.version_id=?""",
                    (identifier,),
                ).fetchone()
                return (row["node_id"], row["operator_id"]) if row else None

            validate_payload_references(
                node_type,
                payload,
                operator_id=operator_id,
                provenance_evidence_ids=evidence_ids,
                node_lookup=node_lookup,
                version_lookup=version_lookup,
            )
            consent_grant_id = payload.get("consent_grant_id") if isinstance(payload, dict) else None
            if consent_grant_id is not None:
                grant_row = conn.execute("""
                  SELECT n.operator_id,nv.version_id,nv.payload_json FROM nodes n JOIN node_versions nv USING(node_id)
                  WHERE n.node_id=? AND n.node_type='ConsentGrant' AND nv.system_to IS NULL
                """, (consent_grant_id,)).fetchone()
                if not grant_row or grant_row["operator_id"] != operator_id:
                    raise ValidationError("semantic observation requires a current same-operator ConsentGrant")
                purpose = "outcome_learning" if node_type == "Outcome" else "behavioral_observation"
                self.authorize_consent_version(
                    conn, grant_row["version_id"], operator_id=operator_id,
                    source_class=payload["source_class"], purpose=purpose,
                    operation="store", valid_at=valid_from, system_at=utc_now(),
                )
            event_payload = {
                "ontology_schema_version": value["record_schema_version"],
                "node_id": node_id,
                "node_type": node_type,
                "payload": payload,
                "provenance": provenance,
            }
            if provenance["authority_tier"] in {"captured_judgment", "ratified_knowledge"}:
                execution = self._consume_authority(
                    conn, approval_token, command_name=f"semantic_node.{node_type}",
                    purpose=f"store authoritative {node_type}",
                    intent=event_payload, authority_transition=f"none_to_{provenance['authority_tier']}",
                    execution_fields=generated,
                    subject_ids=(node_id,), source_ids=tuple(evidence_ids),
                    scope=("semantic_node", node_type),
                )
            else:
                if approval_token is not None:
                    raise ValidationError("approval token cannot authorize a non-authoritative semantic node")
                execution = generated
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, f"semantic_{provenance['status']}", operator_id, now, valid_from,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload), None,
                 provenance["status"]),
            )
            conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", (node_id, node_type, operator_id, event_id))
            self._insert_node_version(
                conn,
                (execution["version_id"], node_id, canonical_bytes(payload).decode(), payload_sha256(payload),
                 provenance["status"], provenance["authority_tier"],
                 canonical_bytes(version_provenance(
                     status=provenance["status"], authority_tier=provenance["authority_tier"],
                     actor_class=provenance["actor_class"], actor_id=provenance["actor_id"],
                     mechanism=provenance["mechanism"], event_id=event_id,
                     model=provenance["model"], ratifier=provenance["ratifier_id"],
                 )).decode(), json.dumps(evidence_ids), valid_from, None,
                 now, None, event_id, None),
            )
        return node_id

    def append_semantic_relation(
        self, contract: dict[str, Any], *, valid_from: str,
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Persist one closed, evidence-linked relation between typed nodes."""
        value = validate_relation_contract(contract)
        try:
            parsed_valid_from = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValidationError("valid_from must be an RFC3339 timestamp") from exc
        if parsed_valid_from.tzinfo is None:
            raise ValidationError("valid_from must include timezone")
        operator_id = value["operator_id"]
        self._require_configured_operator(operator_id)
        provenance = value["provenance"]
        evidence_ids = provenance["evidence_ids"]
        relation_id = value["relation_id"]
        generated = {
            "event_id": make_urn("event"), "version_id": make_urn("edge-version"),
            "system_time": utc_now(),
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            evidence_ids = self._require_evidence(conn, evidence_ids)
            endpoints = conn.execute(
                "SELECT node_id,node_type,operator_id FROM nodes WHERE node_id IN (?,?)",
                (value["source_id"], value["target_id"]),
            ).fetchall()
            by_id = {row["node_id"]: row for row in endpoints}
            if set(by_id) != {value["source_id"], value["target_id"]}:
                raise ValidationError("semantic relation endpoints must exist")
            if by_id[value["source_id"]]["node_type"] != value["source_type"] or by_id[value["target_id"]]["node_type"] != value["target_type"]:
                raise ValidationError("semantic relation endpoint types do not match canonical nodes")
            if {row["operator_id"] for row in endpoints} != {operator_id}:
                raise ValidationError("cross-operator semantic relation is forbidden")
            payload = {
                "ontology_schema_version": value["record_schema_version"],
                "relation": value["relation_type"],
                "evidence_mode": value["evidence_mode"],
                "why": value["why"],
            }
            event_payload = {**value, "provenance": provenance}
            if provenance["authority_tier"] in {"captured_judgment", "ratified_knowledge"}:
                execution = self._consume_authority(
                    conn, approval_token, command_name=f"semantic_relation.{value['relation_type']}",
                    purpose=f"store authoritative {value['relation_type']} relation",
                    intent=event_payload, authority_transition=f"none_to_{provenance['authority_tier']}",
                    execution_fields=generated,
                    subject_ids=(value["source_id"],), target_ids=(value["target_id"],),
                    source_ids=tuple(evidence_ids), scope=("semantic_relation", value["relation_type"]),
                )
            else:
                if approval_token is not None:
                    raise ValidationError("approval token cannot authorize a non-authoritative semantic relation")
                execution = generated
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "semantic_relation", operator_id, now, valid_from,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload), None,
                 provenance["status"]),
            )
            conn.execute(
                "INSERT INTO edges VALUES(?,?,?,?,?,?)",
                (relation_id, value["relation_type"], value["source_id"], value["target_id"], operator_id, event_id),
            )
            self._insert_edge_version(
                conn,
                (execution["version_id"], relation_id, canonical_bytes(payload).decode(), payload_sha256(payload),
                 provenance["status"], provenance["authority_tier"],
                 canonical_bytes(version_provenance(
                     status=provenance["status"], authority_tier=provenance["authority_tier"],
                     actor_class=provenance["actor_class"], actor_id=provenance["actor_id"],
                     mechanism=provenance["mechanism"], event_id=event_id,
                     model=provenance["model"], ratifier=provenance["ratifier_id"],
                     relation=value["relation_type"],
                 )).decode(), json.dumps(evidence_ids), valid_from, None,
                 now, None, event_id, None),
            )
        return relation_id

    def revoke_consent(
        self, grant_id: str, *, operator_id: str, reason: str,
        revoked_at: str | None = None, approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Append a durable ConsentGrant revocation; never rewrite the grant."""
        require_urn(operator_id, "operator", "operator_id")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationError("consent revocation reason is required")
        generated = {
            "event_id": make_urn("event"), "version_id": make_urn("node-version"),
            "system_time": utc_now(),
        }
        revoked_at = revoked_at or generated["system_time"]
        generated["revoked_at"] = revoked_at
        try:
            parsed = datetime.fromisoformat(revoked_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValidationError("revoked_at must be an RFC3339 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValidationError("revoked_at must include timezone")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("""
              SELECT n.operator_id,n.node_type,nv.* FROM nodes n JOIN node_versions nv USING(node_id)
              WHERE n.node_id=? AND nv.system_to IS NULL
            """, (grant_id,)).fetchone()
            if not current or current["node_type"] != "ConsentGrant":
                raise ValidationError("current ConsentGrant does not exist")
            if current["operator_id"] != operator_id:
                raise ValidationError("only the grant operator may revoke consent")
            payload = json.loads(current["payload_json"])
            if payload.get("revoked_at") is not None:
                raise ConflictError("ConsentGrant is already revoked")
            payload["revoked_at"] = revoked_at
            payload["revocation_reason"] = reason.strip()
            from imprint.ontology.operator import validate_operator_payload
            payload = validate_operator_payload("ConsentGrant", payload)
            event_payload = {
                "grant_id": grant_id, "revoked_at": revoked_at,
                "revoked_by": operator_id, "reason": reason.strip(),
                "prior_version_id": current["version_id"],
            }
            execution = self._consume_authority(
                conn, approval_token, command_name="consent.revoke",
                purpose="revoke consent grant", intent=event_payload,
                execution_fields=generated,
                prior_state=json.loads(current["payload_json"]), authority_transition="consent_revoked",
                subject_ids=(grant_id,), scope=("consent",), field_paths=("/revoked_at", "/revocation_reason"),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            revoked_at = execution["revoked_at"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "consent_revoked", operator_id, now, revoked_at,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload),
                 current["event_id"], "captured"),
            )
            conn.execute("UPDATE node_versions SET system_to=? WHERE version_id=?", (now, current["version_id"]))
            self._insert_node_version(
                conn,
                (execution["version_id"], grant_id, canonical_bytes(payload).decode(), payload_sha256(payload),
                 "captured", "captured_judgment", canonical_bytes(version_provenance(
                     status="captured", authority_tier="captured_judgment", actor_class="operator",
                     actor_id=operator_id, mechanism="explicit_consent_revocation", event_id=event_id,
                 )).decode(), current["evidence_json"], current["valid_from"], revoked_at,
                 now, None, event_id, current["version_id"]),
            )
        return event_id

    def append_proposal(self, proposal: dict[str, Any]) -> str:
        """Materialize one validated proposal as a reviewable, non-authoritative node.

        Proposal identity is supplied by the closed proposal envelope. Replaying the
        same bytes is a no-op; reusing an identity for different bytes is a conflict.
        All referenced captured facts are checked inside the writer transaction.
        """
        from imprint.derive.proposals import validate_proposal

        value = validate_proposal(proposal)
        proposal_id = value["proposal_id"]
        source_event_id = value["source_input_event_id"]
        references = value["references"]
        evidence_ids = list(dict.fromkeys(references["evidence_ids"]))
        content_hash = payload_sha256(value)
        now = utc_now()
        event_id = make_urn("event")
        provenance = value["provenance"]
        status = provenance["status"]
        tier = provenance["authority_tier"]
        allowed_tiers = {
            "inferred": {"inferred_candidate", "observed_candidate"},
            "extracted": {"inferred_candidate", "observed_candidate"},
        }
        if tier not in allowed_tiers[status]:
            raise ValidationError("proposal authority tier is incompatible with provenance status")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            prior = conn.execute(
                """SELECT nv.payload_sha256 FROM nodes n JOIN node_versions nv USING(node_id)
                   WHERE n.node_id=? AND n.node_type='Proposal' ORDER BY nv.system_from LIMIT 1""",
                (proposal_id,),
            ).fetchone()
            if prior:
                if prior[0] == content_hash:
                    return "duplicate"
                raise ConflictError("same proposal_id has different bytes")
            source = conn.execute(
                "SELECT operator_id,valid_time,event_type,payload_json FROM events WHERE event_id=?",
                (source_event_id,),
            ).fetchone()
            if not source or source["event_type"] != "captured":
                raise ValidationError("proposal source_input_event_id is not a captured canonical event")
            source_payload = json.loads(source["payload_json"])
            if self.expected_operator_id is not None and source["operator_id"] != self.expected_operator_id:
                raise ValidationError("proposal source does not match the configured canonical operator")
            if self.expected_node_id is not None and source_payload.get("node_id") != self.expected_node_id:
                raise ValidationError("proposal source does not match the configured producer node")
            for kind, ref_id in (("Case", references["case_id"]), ("Verdict", references["verdict_id"])):
                known = conn.execute(
                    "SELECT 1 FROM nodes WHERE node_id=? AND node_type=? AND created_event_id=?",
                    (ref_id, kind, source_event_id),
                ).fetchone()
                if not known:
                    raise ValidationError(f"proposal {kind.lower()} reference does not belong to its source event")
            for evidence_id in evidence_ids:
                known = conn.execute(
                    """SELECT 1 FROM nodes n JOIN source_receipts sr ON sr.source_id=n.node_id
                       WHERE n.node_id=? AND n.node_type='Evidence'
                         AND n.created_event_id=? AND sr.event_id=?""",
                    (evidence_id, source_event_id, source_event_id),
                ).fetchone()
                if not known:
                    raise ValidationError("proposal evidence reference does not belong to its source event")
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "proposal_submitted", source["operator_id"], now, source["valid_time"],
                 canonical_bytes(value).decode(), content_hash, source_event_id, status),
            )
            conn.execute(
                "INSERT INTO nodes VALUES(?,?,?,?)",
                (proposal_id, "Proposal", source["operator_id"], event_id),
            )
            self._insert_node_version(
                conn,
                (make_urn("node-version"), proposal_id, canonical_bytes(value).decode(), content_hash,
                 status, tier, canonical_bytes(version_provenance(
                     status=status, authority_tier=tier,
                     actor_class="model" if provenance["model"] else "software",
                     actor_id=provenance["proposer"], mechanism="validated_proposal_spool",
                     event_id=event_id, model=provenance["model"],
                     prompt_recipe=provenance["prompt_recipe_hash"], proposal_id=proposal_id,
                 )).decode(), json.dumps(evidence_ids), source["valid_time"], None,
                 now, None, event_id, None),
            )
        return "applied"

    def authorize_proposal_successor(
        self, proposal_id: str, *, successor_contract: dict[str, Any],
        operator_id: str, valid_from: str, reason: str,
        approval_token: Mapping[str, Any] | None = None,
    ) -> dict[str, str]:
        """Atomically create typed authority after, never in place of, a Proposal."""
        require_urn(proposal_id, "proposal")
        require_urn(operator_id, "operator", "operator_id")
        self._require_configured_operator(operator_id)
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationError("proposal successor reason is required")
        value = validate_node_contract(successor_contract)
        provenance = value["provenance"]
        if (
            provenance["status"] != "ratified"
            or provenance["authority_tier"] != "ratified_knowledge"
            or provenance["actor_class"] != "operator"
            or provenance["actor_id"] != operator_id
            or provenance["ratifier_id"] != operator_id
            or value["operator_id"] != operator_id
        ):
            raise ValidationError(
                "proposal successor must be exact operator-authored ratified knowledge"
            )
        try:
            parsed = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValidationError("valid_from must be an RFC3339 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValidationError("valid_from must include timezone")

        successor_id = value["node_id"]
        successor_type = value["node_type"]
        payload = value["payload"]
        evidence_ids = list(provenance["evidence_ids"])
        generated = {
            "event_id": make_urn("event"),
            "node_version_id": make_urn("node-version"),
            "relation_id": make_urn("relation"),
            "edge_version_id": make_urn("edge-version"),
            "system_time": utc_now(),
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            proposal = conn.execute("""
              SELECT n.operator_id,n.created_event_id,nv.version_id,nv.payload_json,
                     nv.payload_sha256,nv.evidence_json,nv.valid_from
              FROM nodes n JOIN node_versions nv USING(node_id)
              WHERE n.node_id=? AND n.node_type='Proposal' AND nv.system_to IS NULL
            """, (proposal_id,)).fetchone()
            if not proposal:
                raise ValidationError("current Proposal does not exist")
            if proposal["operator_id"] != operator_id:
                raise ValidationError("Proposal successor authority belongs to another operator")
            proposal_value = json.loads(proposal["payload_json"])
            proposal_evidence = list(proposal_value["references"]["evidence_ids"])
            if not set(proposal_evidence).issubset(evidence_ids):
                raise ValidationError("successor must retain every Proposal evidence reference")

            existing = conn.execute("""
              SELECT e.edge_id,e.target_id,e.created_event_id AS event_id,
                     ev.payload_json,ev.evidence_json,
                     n.node_type,n.operator_id,nv.payload_sha256,nv.provenance_status,
                     nv.authority_tier,nv.evidence_json AS node_evidence_json
              FROM edges e JOIN edge_versions ev USING(edge_id)
              JOIN nodes n ON n.node_id=e.target_id
              JOIN node_versions nv ON nv.node_id=n.node_id
              WHERE e.edge_type='proposal_succeeded_by' AND e.source_id=?
                AND ev.system_to IS NULL AND nv.system_to IS NULL
            """, (proposal_id,)).fetchone()
            if existing:
                relation_payload = json.loads(existing["payload_json"])
                same = (
                    existing["target_id"] == successor_id
                    and existing["node_type"] == successor_type
                    and existing["operator_id"] == operator_id
                    and existing["payload_sha256"] == payload_sha256(payload)
                    and existing["provenance_status"] == "ratified"
                    and existing["authority_tier"] == "ratified_knowledge"
                    and json.loads(existing["node_evidence_json"]) == evidence_ids
                    and json.loads(existing["evidence_json"]) == evidence_ids
                    and relation_payload == {
                        "relation": "proposal_succeeded_by",
                        "why": reason.strip(),
                        "successor_type": successor_type,
                    }
                )
                if same:
                    return {
                        "status": "duplicate", "proposal_id": proposal_id,
                        "successor_id": successor_id,
                        "relation_id": existing["edge_id"],
                        "event_id": existing["event_id"],
                    }
                raise ConflictError("Proposal already has a different authorized successor")
            if conn.execute("SELECT 1 FROM nodes WHERE node_id=?", (successor_id,)).fetchone():
                raise ConflictError("successor node_id already exists")
            evidence_ids = self._require_evidence(conn, evidence_ids)

            def node_lookup(identifier: str) -> tuple[str, str] | None:
                row = conn.execute(
                    "SELECT node_type,operator_id FROM nodes WHERE node_id=?", (identifier,),
                ).fetchone()
                if row:
                    return row["node_type"], row["operator_id"]
                receipt = conn.execute("""
                  SELECT e.operator_id FROM source_receipts sr JOIN events e USING(event_id)
                  WHERE sr.source_id=?
                """, (identifier,)).fetchone()
                return ("Evidence", receipt["operator_id"]) if receipt else None

            def version_lookup(identifier: str) -> tuple[str, str] | None:
                row = conn.execute("""
                  SELECT nv.node_id,n.operator_id FROM node_versions nv
                  JOIN nodes n USING(node_id) WHERE nv.version_id=?
                """, (identifier,)).fetchone()
                return (row["node_id"], row["operator_id"]) if row else None

            validate_payload_references(
                successor_type, payload, operator_id=operator_id,
                provenance_evidence_ids=evidence_ids,
                node_lookup=node_lookup, version_lookup=version_lookup,
            )
            event_payload = {
                "node_id": proposal_id,
                "source_id": proposal_id,
                "target_id": successor_id,
                "successor_type": successor_type,
                "reason": reason.strip(),
                "evidence_ids": evidence_ids,
                "successor_contract": value,
            }
            execution = self._consume_authority(
                conn, approval_token, command_name="proposal.authorize_successor",
                purpose="authorize typed Proposal successor", intent=event_payload,
                execution_fields=generated,
                prior_state={
                    "proposal_version_id": proposal["version_id"],
                    "proposal_payload_sha256": proposal["payload_sha256"],
                },
                authority_transition=(
                    f"{json.loads(proposal['payload_json'])['provenance']['authority_tier']}"
                    "_to_ratified_knowledge"
                ),
                subject_ids=(successor_id,), source_ids=tuple(evidence_ids),
                target_ids=(successor_id,), proposal_ids=(proposal_id,),
                result_version_ids=(
                    generated["node_version_id"], generated["edge_version_id"],
                ),
                scope=("proposal_successor", successor_type),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "proposal_succeeded", operator_id, now, valid_from,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload),
                 proposal["created_event_id"], "ratified"),
            )
            conn.execute(
                "INSERT INTO nodes VALUES(?,?,?,?)",
                (successor_id, successor_type, operator_id, event_id),
            )
            self._insert_node_version(conn, (
                execution["node_version_id"], successor_id,
                canonical_bytes(payload).decode(), payload_sha256(payload),
                "ratified", "ratified_knowledge",
                canonical_bytes(version_provenance(
                    status="ratified", authority_tier="ratified_knowledge",
                    actor_class="operator", actor_id=operator_id,
                    mechanism="explicit_proposal_successor", event_id=event_id,
                    proposal_id=proposal_id, ratifier=operator_id,
                )).decode(), json.dumps(evidence_ids), valid_from, None,
                now, None, event_id, None,
            ))
            relation_id = execution["relation_id"]
            conn.execute(
                "INSERT INTO edges VALUES(?,?,?,?,?,?)",
                (relation_id, "proposal_succeeded_by", proposal_id, successor_id,
                 operator_id, event_id),
            )
            relation_payload = {
                "relation": "proposal_succeeded_by", "why": reason.strip(),
                "successor_type": successor_type,
            }
            self._insert_edge_version(conn, (
                execution["edge_version_id"], relation_id,
                canonical_bytes(relation_payload).decode(),
                payload_sha256(relation_payload), "ratified", "ratified_knowledge",
                canonical_bytes(version_provenance(
                    status="ratified", authority_tier="ratified_knowledge",
                    actor_class="operator", actor_id=operator_id,
                    mechanism="explicit_proposal_successor", event_id=event_id,
                    proposal_id=proposal_id, ratifier=operator_id,
                    relation="proposal_succeeded_by",
                )).decode(), json.dumps(evidence_ids), valid_from, None,
                now, None, event_id, None,
            ))
        return {
            "status": "authorized", "proposal_id": proposal_id,
            "successor_id": successor_id, "relation_id": relation_id,
            "event_id": event_id,
        }

    def ratify_node(
        self, node_id: str, *, ratifier: str, note: str = "",
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Promote an inferred/extracted object through an explicit append-only event."""
        if not isinstance(ratifier, str) or not ratifier.strip():
            raise ValidationError("ratifier identity is required")
        self._require_configured_operator(ratifier)
        generated = {
            "event_id": make_urn("event"), "version_id": make_urn("node-version"),
            "system_time": utc_now(),
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("""
              SELECT n.operator_id,n.node_type,nv.*,ce.event_type AS created_event_type
              FROM nodes n JOIN node_versions nv USING(node_id)
              JOIN events ce ON ce.event_id=n.created_event_id
              WHERE n.node_id=? AND nv.system_to IS NULL
            """, (node_id,)).fetchone()
            if not current:
                raise ValidationError("node is missing or not current")
            if current["operator_id"] != ratifier:
                raise ValidationError("node authority actor must be the configured operator")
            if current["node_type"] in {"Proposal", "FeedbackProfile", "IngestedItem"}:
                raise ValidationError(
                    f"{current['node_type']} records cannot be ratified as ontology authority"
                )
            capture_promotion = (
                current["provenance_status"] == "captured"
                and current["authority_tier"] == "observed_candidate"
            )
            if not capture_promotion and current["provenance_status"] not in {"inferred", "extracted"}:
                raise ValidationError("only recorder candidates or inferred/extracted objects may be ratified")
            if current["created_event_type"].startswith("semantic_"):
                require_urn(ratifier, "operator", "operator ratifier")
                self._require_configured_operator(current["operator_id"])
                if ratifier != current["operator_id"]:
                    raise ValidationError("typed semantic authority may be ratified only by its operator")
            next_payload_json = current["payload_json"]
            next_payload_sha256 = current["payload_sha256"]
            if current["node_type"] in {"SelfModelAssertion", "InterventionRule"}:
                from imprint.ontology.operator import validate_operator_payload
                next_payload = json.loads(current["payload_json"])
                next_payload["review_state"] = "confirmed"
                next_payload["provenance"] = {
                    **next_payload["provenance"],
                    "status": "ratified", "actor_class": "operator", "actor_id": ratifier,
                }
                next_payload = validate_operator_payload(current["node_type"], next_payload)
                next_payload_json = canonical_bytes(next_payload).decode()
                next_payload_sha256 = payload_sha256(next_payload)
            next_status = "captured" if capture_promotion else "ratified"
            next_tier = "captured_judgment" if capture_promotion else "ratified_knowledge"
            event_payload = {
                "node_id": node_id,
                "prior_version_id": current["version_id"],
                "prior_status": current["provenance_status"],
                "new_status": next_status,
                "new_authority_tier": next_tier,
                "ratified_by": ratifier,
                "ratification_note": note,
            }
            execution = self._consume_authority(
                conn, approval_token, command_name="node.ratify",
                purpose="ratify canonical node", intent=event_payload,
                execution_fields=generated,
                prior_state={"payload_sha256": current["payload_sha256"], "version_id": current["version_id"]},
                authority_transition=f"{current['authority_tier']}_to_{next_tier}",
                subject_ids=(node_id,), proposal_ids=(current["event_id"],), scope=("node",),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "capture_promoted" if capture_promotion else "ratified", current["operator_id"], now, now,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload), current["event_id"],
                 next_status),
            )
            conn.execute("UPDATE node_versions SET system_to=? WHERE version_id=?", (now, current["version_id"]))
            self._insert_node_version(
                conn,
                (execution["version_id"], node_id, next_payload_json, next_payload_sha256,
                 next_status, next_tier, canonical_bytes(version_provenance(
                     status=next_status, authority_tier=next_tier, actor_class="operator",
                     actor_id=ratifier, mechanism="explicit_capture_promotion" if capture_promotion else "explicit_ratification", event_id=event_id,
                     proposal_id=current["event_id"], ratifier=None if capture_promotion else ratifier,
                 )).decode(), current["evidence_json"], current["valid_from"],
                 current["valid_to"], now, None, event_id, current["version_id"]),
            )
        return event_id

    def correct_typed_node(
        self, node_id: str, *, corrected_contract: dict[str, Any],
        corrector: str, reason: str, approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Replace a typed inference with an operator-authored, validated correction.

        The inferred proposal remains in ``node_versions`` as a closed version.  The
        new head is linked to it both by ``prior_version_id`` and by the correction
        event, so correction never rewrites or conceals what the model proposed.
        """
        require_urn(corrector, "operator", "operator corrector")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationError("correction reason is required")
        value = validate_node_contract(corrected_contract)
        if value["node_id"] != node_id:
            raise ValidationError("corrected contract must retain the original node_id")
        if value["node_type"] not in {"SelfModelAssertion", "InterventionRule"}:
            raise ValidationError("only SelfModelAssertion or InterventionRule may use typed correction")
        provenance = value["provenance"]
        if provenance["status"] != "ratified" or provenance["actor_class"] != "operator":
            raise ValidationError("typed correction must be operator-authored ratified knowledge")
        if provenance["actor_id"] != corrector or provenance["ratifier_id"] != corrector:
            raise ValidationError("typed correction actor and ratifier must be the correcting operator")
        if value["payload"]["review_state"] != "corrected":
            raise ValidationError("typed correction payload review_state must be corrected")

        generated = {
            "event_id": make_urn("event"), "version_id": make_urn("node-version"),
            "system_time": utc_now(),
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("""
              SELECT n.operator_id,n.node_type,nv.*,ce.event_type AS created_event_type
              FROM nodes n JOIN node_versions nv USING(node_id)
              JOIN events ce ON ce.event_id=n.created_event_id
              WHERE n.node_id=? AND nv.system_to IS NULL
            """, (node_id,)).fetchone()
            if not current:
                raise ValidationError("node is missing or not current")
            if current["node_type"] not in {"SelfModelAssertion", "InterventionRule"}:
                raise ValidationError("only SelfModelAssertion or InterventionRule may use typed correction")
            if not current["created_event_type"].startswith("semantic_"):
                raise ValidationError("typed correction requires a semantic proposal")
            if current["provenance_status"] not in {"inferred", "extracted"}:
                raise ValidationError("only inferred or extracted typed proposals may be corrected")
            if value["node_type"] != current["node_type"]:
                raise ValidationError("corrected contract must retain the original node_type")
            if current["operator_id"] != corrector or value["operator_id"] != corrector:
                raise ValidationError("typed proposal may be corrected only by its operator")
            self._require_configured_operator(current["operator_id"])
            evidence_ids = self._require_evidence(conn, provenance["evidence_ids"])

            def node_lookup(identifier: str) -> tuple[str, str] | None:
                row = conn.execute(
                    "SELECT node_type,operator_id FROM nodes WHERE node_id=?",
                    (identifier,),
                ).fetchone()
                if row:
                    return row["node_type"], row["operator_id"]
                receipt = conn.execute(
                    """SELECT e.operator_id FROM source_receipts sr
                       JOIN events e USING(event_id) WHERE sr.source_id=?""",
                    (identifier,),
                ).fetchone()
                return ("Evidence", receipt["operator_id"]) if receipt else None

            def version_lookup(identifier: str) -> tuple[str, str] | None:
                row = conn.execute(
                    """SELECT nv.node_id,n.operator_id FROM node_versions nv
                       JOIN nodes n USING(node_id) WHERE nv.version_id=?""",
                    (identifier,),
                ).fetchone()
                return (row["node_id"], row["operator_id"]) if row else None

            validate_payload_references(
                value["node_type"], value["payload"], operator_id=corrector,
                provenance_evidence_ids=evidence_ids,
                node_lookup=node_lookup, version_lookup=version_lookup,
            )
            event_payload = {
                "node_id": node_id,
                "node_type": current["node_type"],
                "prior_version_id": current["version_id"],
                "prior_event_id": current["event_id"],
                "prior_status": current["provenance_status"],
                "corrected_by": corrector,
                "reason": reason.strip(),
                "replacement_payload_sha256": payload_sha256(value["payload"]),
            }
            execution = self._consume_authority(
                conn, approval_token, command_name="node.correct_typed",
                purpose="correct typed canonical node", intent=event_payload,
                execution_fields=generated,
                prior_state={"payload_sha256": current["payload_sha256"], "version_id": current["version_id"]},
                authority_transition="proposal_to_corrected_ratified_knowledge",
                subject_ids=(node_id,), source_ids=tuple(evidence_ids),
                proposal_ids=(current["event_id"],), scope=("node", current["node_type"]),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "corrected", current["operator_id"], now, now,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload),
                 current["event_id"], "ratified"),
            )
            conn.execute("UPDATE node_versions SET system_to=? WHERE version_id=?", (now, current["version_id"]))
            self._insert_node_version(
                conn,
                (execution["version_id"], node_id, canonical_bytes(value["payload"]).decode(),
                 payload_sha256(value["payload"]), "ratified", "ratified_knowledge",
                 canonical_bytes(version_provenance(
                     status="ratified", authority_tier="ratified_knowledge", actor_class="operator",
                     actor_id=corrector, mechanism=provenance["mechanism"], event_id=event_id,
                     model=None, proposal_id=current["event_id"], ratifier=corrector,
                 )).decode(), json.dumps(evidence_ids), current["valid_from"],
                 current["valid_to"], now, None, event_id, current["version_id"]),
            )
        return event_id

    def contest_typed_node(
        self, node_id: str, *, contestor: str, reason: str,
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Record an operator's explicit contest and close the typed proposal head."""
        require_urn(contestor, "operator", "operator contestor")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationError("contest reason is required")
        generated = {"event_id": make_urn("event"), "system_time": utc_now()}
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("""
              SELECT n.operator_id,n.node_type,nv.*,ce.event_type AS created_event_type
              FROM nodes n JOIN node_versions nv USING(node_id)
              JOIN events ce ON ce.event_id=n.created_event_id
              WHERE n.node_id=? AND nv.system_to IS NULL
            """, (node_id,)).fetchone()
            if not current:
                raise ValidationError("node is missing or not current")
            if current["node_type"] not in {"SelfModelAssertion", "InterventionRule"}:
                raise ValidationError("only SelfModelAssertion or InterventionRule may be contested")
            if not current["created_event_type"].startswith("semantic_"):
                raise ValidationError("typed contest requires a semantic proposal")
            if current["provenance_status"] not in {"inferred", "extracted"}:
                raise ValidationError("only inferred or extracted typed proposals may be contested")
            if current["operator_id"] != contestor:
                raise ValidationError("typed proposal may be contested only by its operator")
            self._require_configured_operator(current["operator_id"])
            event_payload = {
                "node_id": node_id, "node_type": current["node_type"],
                "prior_version_id": current["version_id"],
                "prior_event_id": current["event_id"],
                "prior_status": current["provenance_status"],
                "contested_by": contestor, "reason": reason.strip(),
            }
            execution = self._consume_authority(
                conn, approval_token, command_name="node.contest_typed",
                purpose="contest typed canonical node", intent=event_payload,
                execution_fields=generated,
                prior_state={"payload_sha256": current["payload_sha256"], "version_id": current["version_id"]},
                authority_transition="proposal_to_contested", subject_ids=(node_id,),
                proposal_ids=(current["event_id"],), scope=("node", current["node_type"]),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "contested", current["operator_id"], now, now,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload),
                 current["event_id"], "ratified"),
            )
            conn.execute("UPDATE node_versions SET system_to=? WHERE version_id=?", (now, current["version_id"]))
        return event_id

    def _review_semantic_edge(
        self, edge_id: str, *, action: str, actor: str, reason: str,
        revisit_after: str | None = None, approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Apply an operator-only disposition to an inferred/extracted semantic edge."""
        require_urn(actor, "operator", "operator reviewer")
        if action not in {"ratified", "deferred", "rejected"}:
            raise ValidationError("unsupported semantic edge review action")
        if not isinstance(reason, str):
            raise ValidationError("edge review reason must be a string")
        if action in {"deferred", "rejected"} and not reason.strip():
            label = {"deferred": "deferral", "rejected": "rejection"}[action]
            raise ValidationError(f"edge {label} reason is required")
        if revisit_after is not None:
            try:
                parsed = datetime.fromisoformat(revisit_after.replace("Z", "+00:00"))
            except (AttributeError, ValueError) as exc:
                raise ValidationError("revisit_after must be an RFC3339 timestamp") from exc
            if parsed.tzinfo is None:
                raise ValidationError("revisit_after must include timezone")
        generated = {
            "event_id": make_urn("event"), "version_id": make_urn("edge-version"),
            "system_time": utc_now(),
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("""
              SELECT e.operator_id,e.edge_type,e.source_id,e.target_id,e.created_event_id,
                     sn.node_type AS source_type,tn.node_type AS target_type,
                     ev.*,ce.event_type AS created_event_type
              FROM edges e JOIN edge_versions ev USING(edge_id)
              JOIN nodes sn ON sn.node_id=e.source_id
              JOIN nodes tn ON tn.node_id=e.target_id
              JOIN events ce ON ce.event_id=e.created_event_id
              WHERE e.edge_id=? AND ev.system_to IS NULL
            """, (edge_id,)).fetchone()
            if not current:
                raise ValidationError("edge is missing or not current")
            if current["created_event_type"] != "semantic_relation":
                raise ValidationError("only typed semantic relations may use edge review")
            if current["provenance_status"] not in {"inferred", "extracted"}:
                raise ValidationError("only inferred or extracted semantic relations may be reviewed")
            if current["operator_id"] != actor:
                raise ValidationError("semantic relation may be reviewed only by its operator")
            self._require_configured_operator(current["operator_id"])
            event_payload = {
                "edge_id": edge_id, "edge_type": current["edge_type"],
                "prior_version_id": current["version_id"],
                "prior_event_id": current["event_id"],
                "prior_status": current["provenance_status"],
                "reviewed_by": actor, "disposition": action,
                "reason": reason.strip(), "revisit_after": revisit_after,
            }
            execution = self._consume_authority(
                conn, approval_token, command_name=f"relation.review.{action}",
                purpose=f"{action} canonical relation", intent=event_payload,
                execution_fields=generated,
                prior_state={"payload_sha256": current["payload_sha256"], "version_id": current["version_id"]},
                authority_transition=f"relation_to_{action}", subject_ids=(current["source_id"],),
                target_ids=(current["target_id"],), proposal_ids=(current["event_id"],),
                scope=("semantic_relation", current["edge_type"]),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, f"edge_{action}", current["operator_id"], now, now,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload),
                 current["event_id"], "ratified" if action in {"ratified", "rejected"} else current["provenance_status"]),
            )
            if action == "deferred":
                return event_id
            conn.execute("UPDATE edge_versions SET system_to=? WHERE version_id=?", (now, current["version_id"]))
            if action == "ratified":
                next_payload = json.loads(current["payload_json"])
                ratified_provenance = {
                    "status": "ratified", "authority_tier": "ratified_knowledge",
                    "actor_class": "operator", "actor_id": actor,
                    "mechanism": "explicit_edge_ratification",
                    "evidence_ids": json.loads(current["evidence_json"]),
                    "model": None, "ratifier_id": actor,
                }
                validate_relation_contract({
                    "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
                    "relation_id": edge_id, "relation_type": current["edge_type"],
                    "source_id": current["source_id"], "source_type": current["source_type"],
                    "target_id": current["target_id"], "target_type": current["target_type"],
                    "operator_id": current["operator_id"],
                    "evidence_mode": next_payload["evidence_mode"],
                    "why": next_payload["why"], "provenance": ratified_provenance,
                })
                self._insert_edge_version(
                    conn,
                    (execution["version_id"], edge_id, canonical_bytes(next_payload).decode(),
                     payload_sha256(next_payload),
                     "ratified", "ratified_knowledge", canonical_bytes(version_provenance(
                         status="ratified", authority_tier="ratified_knowledge", actor_class="operator",
                         actor_id=actor, mechanism="explicit_edge_ratification", event_id=event_id,
                         proposal_id=current["event_id"], ratifier=actor,
                         relation=current["edge_type"],
                     )).decode(), current["evidence_json"], current["valid_from"], current["valid_to"],
                     now, None, event_id, current["version_id"]),
                )
        return event_id

    def ratify_edge(self, edge_id: str, *, ratifier: str, note: str = "", approval_token=None) -> str:
        return self._review_semantic_edge(edge_id, action="ratified", actor=ratifier, reason=note, approval_token=approval_token)

    def defer_edge(
        self, edge_id: str, *, reviewer: str, reason: str,
        revisit_after: str | None = None, approval_token=None,
    ) -> str:
        return self._review_semantic_edge(
            edge_id, action="deferred", actor=reviewer, reason=reason,
            revisit_after=revisit_after, approval_token=approval_token,
        )

    def reject_edge(self, edge_id: str, *, rejector: str, reason: str, approval_token=None) -> str:
        return self._review_semantic_edge(edge_id, action="rejected", actor=rejector, reason=reason, approval_token=approval_token)

    def reject_node(
        self, node_id: str, *, rejector: str, reason: str,
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Close a proposal without erasing its inspectable history."""
        if not rejector.strip() or not reason.strip():
            raise ValidationError("rejector and rejection reason are required")
        generated = {"event_id": make_urn("event"), "system_time": utc_now()}
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("""
              SELECT n.operator_id,nv.*,ce.event_type AS created_event_type
              FROM nodes n JOIN node_versions nv USING(node_id)
              JOIN events ce ON ce.event_id=n.created_event_id
              WHERE n.node_id=? AND nv.system_to IS NULL
            """, (node_id,)).fetchone()
            if not current:
                raise ValidationError("node is missing or not current")
            if current["provenance_status"] not in {"inferred", "extracted"}:
                raise ValidationError("only inferred or extracted objects may be rejected")
            if current["created_event_type"].startswith("semantic_"):
                require_urn(rejector, "operator", "operator rejector")
                self._require_configured_operator(current["operator_id"])
                if rejector != current["operator_id"]:
                    raise ValidationError("typed semantic proposal may be rejected only by its operator")
            self._require_configured_operator(current["operator_id"])
            if rejector != current["operator_id"]:
                raise ValidationError("node rejection actor must be the configured operator")
            payload = {
                "node_id": node_id,
                "prior_version_id": current["version_id"],
                "prior_status": current["provenance_status"],
                "rejected_by": rejector,
                "reason": reason,
            }
            execution = self._consume_authority(
                conn, approval_token, command_name="node.reject",
                purpose="reject canonical node", intent=payload,
                execution_fields=generated,
                prior_state={"payload_sha256": current["payload_sha256"], "version_id": current["version_id"]},
                authority_transition="proposal_to_rejected", subject_ids=(node_id,),
                proposal_ids=(current["event_id"],), scope=("node",),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "rejected", current["operator_id"], now, now,
                 canonical_bytes(payload).decode(), payload_sha256(payload), current["event_id"],
                 "ratified"),
            )
            conn.execute("UPDATE node_versions SET system_to=? WHERE version_id=?", (now, current["version_id"]))
        return event_id

    def defer_node(
        self,
        node_id: str,
        *,
        reviewer: str,
        reason: str,
        revisit_after: str | None = None,
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Record an explicit no-decision without changing proposal authority.

        Deferral is an inspectable review event, not an implicit absence of a
        ratification.  The inferred/extracted head stays current and remains
        ineligible for authoritative retrieval.
        """
        reviewer = self._require_actor(reviewer)
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationError("deferral reason is required")
        if revisit_after is not None:
            if not isinstance(revisit_after, str):
                raise ValidationError("revisit_after must be an RFC3339 timestamp")
            try:
                parsed_revisit = datetime.fromisoformat(revisit_after.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValidationError("revisit_after must be an RFC3339 timestamp") from exc
            if parsed_revisit.tzinfo is None:
                raise ValidationError("revisit_after must include timezone")
        generated = {
            "event_id": make_urn("event"), "version_id": make_urn("node-version"),
            "system_time": utc_now(),
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("""
              SELECT n.operator_id,n.node_type,nv.*,ce.event_type AS created_event_type
              FROM nodes n JOIN node_versions nv USING(node_id)
              JOIN events ce ON ce.event_id=n.created_event_id
              WHERE n.node_id=? AND nv.system_to IS NULL
            """, (node_id,)).fetchone()
            if not current:
                raise ValidationError("node is missing or not current")
            if current["provenance_status"] not in {"inferred", "extracted"}:
                raise ValidationError("only inferred or extracted objects may be deferred")
            if current["created_event_type"].startswith("semantic_"):
                require_urn(reviewer, "operator", "operator reviewer")
                self._require_configured_operator(current["operator_id"])
                if reviewer != current["operator_id"]:
                    raise ValidationError("typed semantic proposal may be deferred only by its operator")
            self._require_configured_operator(current["operator_id"])
            if reviewer != current["operator_id"]:
                raise ValidationError("node review actor must be the configured operator")
            payload = {
                "node_id": node_id,
                "node_type": current["node_type"],
                "version_id": current["version_id"],
                "reviewed_by": reviewer,
                "reason": reason.strip(),
                "revisit_after": revisit_after,
            }
            execution = self._consume_authority(
                conn, approval_token, command_name="node.defer",
                purpose="defer canonical node review", intent=payload,
                execution_fields=generated,
                prior_state={"payload_sha256": current["payload_sha256"], "version_id": current["version_id"]},
                authority_transition="proposal_to_deferred", subject_ids=(node_id,),
                proposal_ids=(current["event_id"],), scope=("node",),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "deferred", current["operator_id"], now, now,
                 canonical_bytes(payload).decode(), payload_sha256(payload), current["event_id"],
                 current["provenance_status"]),
            )
            if current["node_type"] in {"SelfModelAssertion", "InterventionRule"}:
                from imprint.ontology.operator import validate_operator_payload
                next_payload = json.loads(current["payload_json"])
                next_payload["review_state"] = "deferred"
                next_payload = validate_operator_payload(current["node_type"], next_payload)
                next_provenance = json.loads(current["provenance_json"])
                next_provenance["event_id"] = event_id
                conn.execute("UPDATE node_versions SET system_to=? WHERE version_id=?", (now, current["version_id"]))
                self._insert_node_version(
                    conn,
                    (execution["version_id"], node_id, canonical_bytes(next_payload).decode(),
                     payload_sha256(next_payload), current["provenance_status"], current["authority_tier"],
                     canonical_bytes(next_provenance).decode(), current["evidence_json"],
                     current["valid_from"], current["valid_to"], now, None, event_id, current["version_id"]),
                )
        return event_id

    def node_history(self, node_id: str) -> dict[str, Any]:
        """Return every immutable version, including a closed rejected/tombstoned head."""
        with self.read_connection() as conn:
            rows = conn.execute("""
              SELECT nv.*,n.node_type,n.operator_id,e.event_type,e.payload_json AS event_payload_json
              FROM nodes n JOIN node_versions nv USING(node_id)
              JOIN events e ON e.event_id=nv.event_id
              WHERE n.node_id=? ORDER BY nv.system_from,nv.version_id
            """, (node_id,)).fetchall()
            dispositions = conn.execute("""
              SELECT e.event_id,e.event_type,e.system_time,e.payload_json
              FROM event_disposition_subjects ds
              JOIN events e USING(event_id)
              WHERE ds.subject_id=? AND e.event_type IN (
                'ratified','rejected','deferred','corrected','contested',
                'consent_revoked','tombstoned','reason_added','reinforced',
                'contradicts','supersedes','domain_selected','domain_frozen',
                'proposal_succeeded'
              )
              ORDER BY e.system_time,e.event_id
            """, (node_id,)).fetchall()
        if not rows:
            raise ValidationError("node does not exist")
        versions: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            item["event_payload"] = json.loads(item.pop("event_payload_json"))
            item["provenance"] = json.loads(item.pop("provenance_json"))
            item["evidence"] = json.loads(item.pop("evidence_json"))
            versions.append(item)
        return {
            "node_id": node_id,
            "versions": versions,
            "dispositions": [
                {
                    "event_id": row["event_id"],
                    "event_type": row["event_type"],
                    "system_time": row["system_time"],
                    "payload": json.loads(row["payload_json"]),
                }
                for row in dispositions
            ],
        }

    def add_reason(
        self,
        verdict_id: str,
        *,
        reason: str,
        actor_id: str,
        source_locator: str = "explicit_cli",
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Append a later WHY and evidence; never rewrite the original null payload."""
        if not reason.strip() or not actor_id.strip():
            raise ValidationError("reason and actor_id are required")
        return self._append_verdict_evidence(
            verdict_id,
            content=reason,
            actor_id=actor_id,
            source_locator=source_locator,
            event_type="reason_added",
            payload_update={"reason": reason, "reason_status": "later_added"},
            approval_token=approval_token,
        )

    def reinforce_verdict(
        self,
        verdict_id: str,
        *,
        evidence_text: str,
        actor_id: str,
        source_locator: str = "explicit_cli",
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        """Append supporting evidence and a new Verdict version without changing the call."""
        if not evidence_text.strip() or not actor_id.strip():
            raise ValidationError("evidence_text and actor_id are required")
        return self._append_verdict_evidence(
            verdict_id,
            content=evidence_text,
            actor_id=actor_id,
            source_locator=source_locator,
            event_type="reinforced",
            payload_update={},
            approval_token=approval_token,
        )

    def _append_verdict_evidence(
        self,
        verdict_id: str,
        *,
        content: str,
        actor_id: str,
        source_locator: str,
        event_type: str,
        payload_update: dict[str, Any],
        approval_token: Mapping[str, Any] | None,
    ) -> str:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("""
              SELECT n.operator_id,n.node_type,nv.* FROM nodes n JOIN node_versions nv USING(node_id)
              WHERE n.node_id=? AND nv.system_to IS NULL
            """, (verdict_id,)).fetchone()
            if not current or current["node_type"] != "Verdict":
                raise ValidationError("current Verdict does not exist")
            self._require_configured_operator(current["operator_id"])
            if actor_id != current["operator_id"]:
                raise ValidationError("verdict authority actor must be the configured operator")
            prior_payload = json.loads(current["payload_json"])
            if event_type == "reason_added" and prior_payload.get("reason") is not None:
                raise ValidationError("Verdict already has a reason; use a later call to supersede it")
            new_payload = {**prior_payload, **payload_update}
            prior_evidence = json.loads(current["evidence_json"])
            generated = {
                "event_id": make_urn("event"), "evidence_id": make_urn("evidence"),
                "evidence_version_id": make_urn("node-version"),
                "edge_id": make_urn("edge"), "edge_version_id": make_urn("edge-version"),
                "verdict_version_id": make_urn("node-version"), "system_time": utc_now(),
            }
            stable_intent = {
                "node_id": verdict_id, "prior_version_id": current["version_id"],
                "actor_id": actor_id, "source_locator": source_locator,
                "content_sha256": payload_sha256(content), "payload_update": payload_update,
                "event_type": event_type,
            }
            execution = self._consume_authority(
                conn, approval_token, command_name=f"verdict.{event_type}",
                purpose=f"append operator verdict evidence: {event_type}",
                intent=stable_intent, execution_fields=generated,
                prior_state={"payload_sha256": current["payload_sha256"], "version_id": current["version_id"]},
                authority_transition=f"captured_judgment_{event_type}", subject_ids=(verdict_id,),
                result_version_ids=(
                    generated["evidence_version_id"], generated["edge_version_id"],
                    generated["verdict_version_id"],
                ), scope=("verdict",),
            )
            event_id = execution["event_id"]
            evidence_id = execution["evidence_id"]
            now = execution["system_time"]
            evidence_payload = {
                "evidence_id": evidence_id, "kind": "operator_verbatim",
                "content": content, "content_sha256": payload_sha256(content),
                "source_locator": source_locator,
            }
            new_evidence = list(dict.fromkeys([*prior_evidence, evidence_id]))
            event_payload = {
                "node_id": verdict_id,
                "prior_version_id": current["version_id"],
                "evidence_id": evidence_id,
                "actor_id": actor_id,
                "source_locator": source_locator,
            }
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, event_type, current["operator_id"], now, now,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload), current["event_id"],
                 "captured"),
            )
            conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", (evidence_id, "Evidence", current["operator_id"], event_id))
            self._insert_node_version(
                conn,
                (execution["evidence_version_id"], evidence_id, canonical_bytes(evidence_payload).decode(),
                 payload_sha256(evidence_payload), "captured", "captured_judgment", canonical_bytes(version_provenance(
                     status="captured", authority_tier="captured_judgment", actor_class="operator",
                     actor_id=actor_id, mechanism=source_locator, event_id=event_id,
                 )).decode(), json.dumps([evidence_id]),
                 now, None, now, None, event_id, None),
            )
            conn.execute(
                "INSERT INTO source_receipts VALUES(?,?,?,?,?)",
                (evidence_id, "operator_verbatim", source_locator, evidence_payload["content_sha256"], event_id),
            )
            self._insert_edge_for_event(
                conn, "supported_by", verdict_id, evidence_id, current["operator_id"], event_id, now,
                evidence_id, edge_id=execution["edge_id"],
                edge_version_id=execution["edge_version_id"],
            )
            conn.execute("UPDATE node_versions SET system_to=? WHERE version_id=?", (now, current["version_id"]))
            self._insert_node_version(
                conn,
                (execution["verdict_version_id"], verdict_id, canonical_bytes(new_payload).decode(), payload_sha256(new_payload),
                 "captured", "captured_judgment", canonical_bytes(version_provenance(
                     status="captured", authority_tier="captured_judgment", actor_class="operator",
                     actor_id=actor_id, mechanism=source_locator, event_id=event_id,
                 )).decode(), json.dumps(new_evidence), current["valid_from"],
                 current["valid_to"], now, None, event_id, current["version_id"]),
            )
        return event_id

    def _insert_edge_for_event(
        self, conn, edge_type: str, source_id: str, target_id: str, operator_id: str,
        event_id: str, now: str, evidence_id: str, *, edge_id: str | None = None,
        edge_version_id: str | None = None,
    ) -> None:
        edge_id = edge_id or make_urn("edge")
        payload = {"why": "explicit later operator evidence", "relation": edge_type}
        conn.execute("INSERT INTO edges VALUES(?,?,?,?,?,?)", (edge_id, edge_type, source_id, target_id, operator_id, event_id))
        self._insert_edge_version(
            conn,
            (edge_version_id or make_urn("edge-version"), edge_id, canonical_bytes(payload).decode(), payload_sha256(payload),
             "captured", "captured_judgment", canonical_bytes(version_provenance(
                 status="captured", authority_tier="captured_judgment", actor_class="operator",
                 actor_id=operator_id, mechanism="explicit_later_evidence", event_id=event_id,
                 relation=edge_type,
             )).decode(), json.dumps([evidence_id]), now, None, now, None, event_id, None),
        )

    def tombstone_node(
        self, node_id: str, *, reason: str,
        approval_token: Mapping[str, Any] | None = None,
    ) -> str:
        if not reason.strip():
            raise ValidationError("tombstone reason is required")
        generated = {"event_id": make_urn("event"), "system_time": utc_now()}
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("""
              SELECT n.operator_id,nv.* FROM nodes n JOIN node_versions nv USING(node_id)
              WHERE n.node_id=? AND nv.system_to IS NULL
            """, (node_id,)).fetchone()
            if not current:
                raise ValidationError("node is missing or already tombstoned")
            payload = {"node_id": node_id, "reason": reason, "prior_version_id": current["version_id"]}
            execution = self._consume_authority(
                conn, approval_token, command_name="node.tombstone",
                purpose="tombstone canonical node", intent=payload,
                execution_fields=generated,
                prior_state={"payload_sha256": current["payload_sha256"], "version_id": current["version_id"]},
                authority_transition="current_to_tombstoned", subject_ids=(node_id,),
                scope=("node",),
            )
            event_id = execution["event_id"]
            now = execution["system_time"]
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "tombstoned", current["operator_id"], now, now,
                 canonical_bytes(payload).decode(), payload_sha256(payload), current["event_id"],
                 current["provenance_status"]),
            )
            conn.execute("UPDATE node_versions SET system_to=? WHERE version_id=?", (now, current["version_id"]))
            conn.execute("UPDATE edge_versions SET system_to=? WHERE edge_id IN (SELECT edge_id FROM edges WHERE source_id=? OR target_id=?) AND system_to IS NULL", (now, node_id, node_id))
        return event_id

    def current_edges(self) -> list[dict[str, Any]]:
        with self.read_connection() as conn:
            rows = conn.execute("""
              SELECT e.edge_id,e.edge_type,e.source_id,e.target_id,ev.payload_json,
                     ev.payload_sha256,ev.provenance_status,ev.authority_tier,ev.provenance_json,ev.evidence_json,
                     ev.valid_from,ev.valid_to,ev.system_from,ev.system_to,ev.event_id
              FROM edges e JOIN edge_versions ev USING(edge_id)
              WHERE ev.system_to IS NULL ORDER BY e.edge_type,e.edge_id
            """).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            item["provenance"] = json.loads(item.pop("provenance_json"))
            item["evidence"] = json.loads(item.pop("evidence_json"))
            result.append(item)
        return result

    def snapshot(self) -> dict[str, Any]:
        return {
            "store_schema_version": STORE_SCHEMA_VERSION,
            "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
            "nodes": self.current_nodes(),
            "edges": self.current_edges(),
        }
