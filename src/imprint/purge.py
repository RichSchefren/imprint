"""Explicit irreversible purge with dependency closure and content-free receipts."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import hashlib
import stat
from pathlib import Path
from typing import Any, Mapping

from .constants import STORE_SCHEMA_VERSION
from .authority.keys import validate_encrypted_key_blob
from .authority.ledger import verify_authority_chain
from .errors import SafetyError, ValidationError
from .ontology.schema import make_urn
from .paths import CONTENT_LOCATION_REGISTRY, content_locations, validate_data_root
from .permissions import assert_private_file, secure_directory, secure_file, secure_tree
from .projections import jsonld_document, markdown_document
from .store import ImprintStore
from .store.service import utc_now


OWNED_CONTENT_DIRS = tuple(dict.fromkeys(
    entry.relative_path.split("/", 1)[0]
    for entry in CONTENT_LOCATION_REGISTRY
    if entry.kind == "directory" and entry.relative_path
))


def _write_private_text(path: Path, content: str) -> None:
    secure_directory(path.parent)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(temporary_name)
    os.close(fd)
    try:
        secure_file(temporary)
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        secure_file(temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    secure_file(path)


def _closure(conn: sqlite3.Connection, scope: str) -> tuple[set[str], set[str], set[str], set[str], str]:
    """Resolve an exact node, operator, session, or source scope."""
    nodes: set[str] = set()
    seed_events: set[str] = set()
    ingest_items: set[str] = set()
    source = conn.execute("SELECT event_id FROM source_receipts WHERE source_id=?", (scope,)).fetchone()
    ingest_source = conn.execute("SELECT item_id FROM ingest_items WHERE source_id=?", (scope,)).fetchall()
    if source or ingest_source:
        scope_class = "source"
        if source:
            seed_events = {str(source[0])}
        ingest_items = {str(row[0]) for row in ingest_source}
    elif conn.execute("SELECT 1 FROM nodes WHERE node_id=?", (scope,)).fetchone():
        nodes = {scope}
        scope_class = "node_dependency_closure"
    elif (
        conn.execute("SELECT 1 FROM events WHERE operator_id=?", (scope,)).fetchone()
        or conn.execute("SELECT 1 FROM ingest_items WHERE operator_id=?", (scope,)).fetchone()
    ):
        scope_class = "operator"
        nodes = {str(row[0]) for row in conn.execute("SELECT node_id FROM nodes WHERE operator_id=?", (scope,))}
        seed_events = {str(row[0]) for row in conn.execute("SELECT event_id FROM events WHERE operator_id=?", (scope,))}
        ingest_items = {str(row[0]) for row in conn.execute("SELECT item_id FROM ingest_items WHERE operator_id=?", (scope,))}
    else:
        session_events = conn.execute(
            "SELECT event_id FROM events WHERE json_valid(payload_json) AND json_extract(payload_json,'$.session_id')=?",
            (scope,),
        ).fetchall()
        session_items = conn.execute("SELECT item_id FROM ingest_items WHERE session_id=?", (scope,)).fetchall()
        if not session_events and not session_items:
            raise ValidationError("purge scope must name an existing node, operator, session, or source")
        scope_class = "session"
        seed_events = {str(row[0]) for row in session_events}
        ingest_items = {str(row[0]) for row in session_items}
    if seed_events and not nodes:
        marks = ",".join("?" for _ in seed_events)
        nodes = {
            str(row[0]) for row in conn.execute(
                f"SELECT DISTINCT node_id FROM node_versions WHERE event_id IN ({marks}) UNION SELECT node_id FROM nodes WHERE created_event_id IN ({marks})",
                [*seed_events, *seed_events],
            )
        }
    if not nodes and not seed_events and not ingest_items:
        raise ValidationError("purge scope resolves to no canonical content")
    while True:
        before = (set(nodes), set(ingest_items))
        if ingest_items:
            item_marks = ",".join("?" for _ in ingest_items)
            nodes |= {
                str(row[0]) for row in conn.execute(
                    f"SELECT kept_node_id FROM ingest_items WHERE item_id IN ({item_marks}) AND kept_node_id IS NOT NULL",
                    list(ingest_items),
                )
            }
        if nodes:
            node_marks = ",".join("?" for _ in nodes)
            ingest_items |= {
                str(row[0]) for row in conn.execute(
                    f"SELECT item_id FROM ingest_items WHERE kept_node_id IN ({node_marks}) OR node_id IN ({node_marks})",
                    [*nodes, *nodes],
                )
            }
            rows = conn.execute(
                f"SELECT source_id,target_id FROM edges WHERE source_id IN ({node_marks}) OR target_id IN ({node_marks})",
                [*nodes, *nodes],
            ).fetchall()
            nodes |= {str(value) for row in rows for value in row}
        if before == (nodes, ingest_items):
            break
    placeholders = ",".join("?" for _ in nodes)
    edges = set()
    events = set(seed_events)
    if nodes:
        edges = {
            str(row[0]) for row in conn.execute(
                f"SELECT edge_id FROM edges WHERE source_id IN ({placeholders}) OR target_id IN ({placeholders})",
                [*nodes, *nodes],
            )
        }
        events |= {
            str(row[0]) for row in conn.execute(
                f"SELECT DISTINCT event_id FROM node_versions WHERE node_id IN ({placeholders})",
                list(nodes),
            )
        }
        ingest_items |= {
            str(row[0]) for row in conn.execute(
                f"SELECT item_id FROM ingest_items WHERE kept_node_id IN ({placeholders}) OR node_id IN ({placeholders})",
                [*nodes, *nodes],
            )
        }
    if edges:
        edge_marks = ",".join("?" for _ in edges)
        events |= {
            str(row[0]) for row in conn.execute(
                f"SELECT DISTINCT event_id FROM edge_versions WHERE edge_id IN ({edge_marks})", list(edges)
            )
        }
    # Disposition-only events (reject/tombstone) have no entity version of their
    # own. Their normalized subjects are transactionally indexed at event write.
    if nodes:
        events |= {
            str(row[0]) for row in conn.execute(
                f"SELECT DISTINCT event_id FROM event_disposition_subjects "
                f"WHERE subject_id IN ({placeholders})",
                list(nodes),
            )
        }
    if ingest_items:
        item_marks = ",".join("?" for _ in ingest_items)
        events |= {
            str(row[0]) for row in conn.execute(
                f"SELECT event_id FROM ingest_rulings WHERE item_id IN ({item_marks})", list(ingest_items)
            )
        }
    return nodes, edges, events, ingest_items, scope_class


def preview_purge(store: ImprintStore, root: Path, scope: str) -> dict[str, Any]:
    root = validate_data_root(root)
    with store.connect() as conn:
        nodes, edges, events, ingest_items, scope_class = _closure(conn, scope)
        receipts = conn.execute(
            f"SELECT COUNT(*) FROM source_receipts WHERE event_id IN ({','.join('?' for _ in events)})",
            list(events),
        ).fetchone()[0] if events else 0
    return {
        "purge_schema_version": "1.0.0",
        "scope_class": scope_class,
        "counts": {
            "nodes": len(nodes), "edges": len(edges), "events": len(events),
            "source_receipts": receipts, "ingest_items": len(ingest_items),
        },
        "active_locations": [
            {"surface_id": entry.surface_id, "path": str(path), "kind": entry.kind}
            for entry, path in content_locations(root) if path.exists()
        ],
        "external_backups_exports": "not_discoverable; inventory separately before purge",
        "confirmation_required": scope,
    }


def _contains_identity(value: Any, ids: set[str], hashes: set[str]) -> bool:
    if isinstance(value, str):
        return value in ids or value.lower() in hashes
    if isinstance(value, Mapping):
        return any(_contains_identity(key, ids, hashes) or _contains_identity(item, ids, hashes)
                   for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_identity(item, ids, hashes) for item in value)
    return False


def _file_has_identity(path: Path, ids: set[str], hashes: set[str]) -> bool:
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() in hashes:
        return True
    if content.startswith(b"SQLite format 3\x00"):
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True)
        try:
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            structured = {
                "events": ("event_id", "payload_sha256"),
                "nodes": ("node_id",),
                "node_versions": ("version_id", "node_id", "payload_sha256"),
                "edges": ("edge_id", "source_id", "target_id"),
                "edge_versions": ("version_id", "edge_id", "payload_sha256"),
                "source_receipts": ("source_id", "content_sha256", "event_id"),
                "ingest_items": ("item_id", "source_id", "source_sha256", "payload_sha256"),
                "semantic_node_versions": ("version_id", "record_id", "envelope_sha256"),
                "semantic_artifact_bytes": ("version_id", "content_sha256"),
                "semantic_relation_versions": (
                    "relation_version_id", "relation_id", "source_version_id",
                    "target_version_id", "envelope_sha256",
                ),
            }
            for table, columns in structured.items():
                if table not in tables:
                    continue
                selected = ",".join(f'"{column}"' for column in columns)
                for row in connection.execute(f'SELECT {selected} FROM "{table}"'):
                    if any(str(value) in ids or str(value).lower() in hashes for value in row if value is not None):
                        return True
        finally:
            connection.close()
        return False
    try:
        decoded = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return _contains_identity(decoded, ids, hashes)


def _registered_paths(store: ImprintStore) -> list[tuple[str, Path]]:
    with store.connect() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "content_locations" not in tables:
            return []
        rows = conn.execute(
            "SELECT surface_id,absolute_path FROM content_locations WHERE active=1 ORDER BY location_id"
        ).fetchall()
    return [(str(row[0]), Path(str(row[1]))) for row in rows]


def _trusted_authority_paths(store: ImprintStore, root: Path) -> set[Path]:
    """Return only ledger-bound, byte-identical, private trust-key blobs."""
    trusted: set[Path] = set()
    with store.connect() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "authority_keys" not in tables:
            return trusted
        rows = conn.execute(
            """SELECT k.*,l.event_json,l.event_sha256,l.signature_b64,
                      l.previous_event_sha256,l.event_type,l.created_at AS ledger_created_at
               FROM authority_keys k JOIN authority_ledger l
                 ON l.sequence=k.ledger_sequence AND l.key_id=k.key_id"""
        ).fetchall()
        operators = {row["operator_id"] for row in rows}
        if len(operators) != 1:
            return trusted
        try:
            chain = verify_authority_chain(
                conn, expected_operator_id=next(iter(operators)),
            )
        except ValidationError:
            return trusted
    resolved_root = root.resolve(strict=True)
    for raw in rows:
        row = dict(raw)
        relative = row["blob_rel_path"]
        expected_hash = row["blob_sha256"]
        expected_size = row["blob_size"]
        path = root / str(relative)
        try:
            expected_name = row["public_key_fingerprint"].removeprefix("sha256:") + ".blob"
            if Path(str(relative)).parts != ("authority", "keys", expected_name):
                continue
            ledger_event = json.loads(row["event_json"])
            key_state = chain["keys"].get(row["key_id"])
            certificate = ledger_event if int(row["ledger_sequence"]) == 1 else ledger_event.get("details", {})
            if (
                not isinstance(key_state, Mapping)
                or key_state.get("status") != row["status"]
                or key_state.get("install_id") != row["install_id"]
                or key_state.get("public_key_b64") != row["public_key_b64"]
                or key_state.get("public_key_fingerprint") != row["public_key_fingerprint"]
                or any(certificate.get(name) != row[name] for name in (
                    "blob_rel_path", "blob_sha256", "blob_size", "algorithm_suite",
                ))
            ):
                continue
            # Every component must be a real, non-link object. A replaced key
            # is content residue, never trusted merely by extension.
            current = root
            for component in Path(str(relative)).parts:
                current = current / component
                if current.is_symlink():
                    raise OSError("authority path contains a symlink")
            resolved = path.resolve(strict=True)
            resolved.relative_to(resolved_root)
            assert_private_file(resolved)
            content = resolved.read_bytes()
            if len(content) != int(expected_size) or hashlib.sha256(content).hexdigest() != expected_hash:
                continue
            validate_encrypted_key_blob(content)
        except (OSError, ValueError, TypeError, ValidationError, json.JSONDecodeError):
            continue
        trusted.add(path)
    return trusted


def _iter_location_files(store: ImprintStore, root: Path):
    seen: set[Path] = set()
    trusted_authority = _trusted_authority_paths(store, root)
    for entry, path in content_locations(root):
        if entry.kind == "sqlite":
            continue
        candidates = (
            root.glob(entry.relative_path) if entry.kind == "file_pattern"
            else path.rglob("*") if path.exists() else ()
        )
        for candidate in candidates:
            try:
                relative = candidate.relative_to(root)
            except ValueError:
                relative = None
            typed_trust_metadata = candidate in trusted_authority
            if typed_trust_metadata:
                continue
            if candidate in seen or candidate.is_symlink() or not candidate.is_file():
                continue
            seen.add(candidate)
            yield entry.surface_id, candidate
    for surface_id, path in _registered_paths(store):
        if path in seen or path.is_symlink() or not path.is_file():
            continue
        seen.add(path)
        yield surface_id, path


def _remove_owned_files_with_markers(
    store: ImprintStore, root: Path, identities: tuple[set[str], set[str]],
) -> list[str]:
    ids, hashes = identities
    deleted: list[str] = []
    for surface_id, path in sorted(_iter_location_files(store, root), key=lambda item: str(item[1])):
        try:
            try:
                if path.relative_to(root).parts[0] == "authority":
                    # Untrusted files in the authority namespace require the
                    # separate authority-destruction ceremony. They block
                    # purge success instead of being deleted by content purge.
                    continue
            except (ValueError, IndexError):
                pass
            if _file_has_identity(path, ids, hashes):
                path.unlink()
                try:
                    label = str(path.relative_to(root))
                except ValueError:
                    label = str(path)
                deleted.append(f"{surface_id}:{label}")
                receipt = path.with_suffix(path.suffix + ".receipt.json")
                if receipt.exists():
                    receipt.unlink()
                    deleted.append(f"{surface_id}:{receipt}")
        except OSError:
            continue
    return deleted


def _scan_active_root(root: Path, identities: tuple[set[str], set[str]], store: ImprintStore | None = None) -> list[str]:
    ids, hashes = identities
    remaining: list[str] = []
    if store is not None:
        for entry, path in content_locations(root):
            if path.is_symlink():
                remaining.append(f"{entry.surface_id}:{path}:unreadable_symlink")
        for surface_id, path in _registered_paths(store):
            if path.is_symlink() or (path.exists() and not path.is_file()):
                remaining.append(f"{surface_id}:{path}:unreadable")
    iterator = _iter_location_files(store, root) if store is not None else (
        ("untyped", path) for path in sorted(root.rglob("*")) if path.is_file()
    )
    for surface_id, path in iterator:
        try:
            if surface_id == "authority.nontrust_content_guard":
                try:
                    label = str(path.relative_to(root))
                except ValueError:
                    label = str(path)
                remaining.append(f"{surface_id}:{label}:untrusted_authority_artifact")
                continue
            if _file_has_identity(path, ids, hashes):
                try:
                    label = str(path.relative_to(root))
                except ValueError:
                    label = str(path)
                remaining.append(f"{surface_id}:{label}")
        except OSError:
            remaining.append(f"{surface_id}:{path}:unreadable")
    return remaining


def _database_content_has_markers(store: ImprintStore, identities: tuple[set[str], set[str]]) -> bool:
    """Scan typed content columns while excluding authority trust metadata."""
    ids, hashes = identities
    columns = {
        "events": ("payload_json",),
        "node_versions": ("payload_json", "provenance_json", "evidence_json"),
        "edge_versions": ("payload_json", "provenance_json", "evidence_json"),
        "source_receipts": ("locator",),
        "ingest_items": ("source_locator", "payload_json"),
        "semantic_node_versions": ("provenance_v2_1_json", "envelope_json"),
        "semantic_artifact_bytes": ("content",),
        "semantic_relation_versions": ("qualifier_json", "envelope_json"),
    }
    with store.connect() as conn:
        known = {
            str(row[0]) for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        for table, names in columns.items():
            if table not in known:
                continue
            selected = ",".join(f'"{name}"' for name in names)
            for row in conn.execute(f'SELECT {selected} FROM "{table}"').fetchall():
                for value in row:
                    content = value if isinstance(value, bytes) else str(value or "").encode("utf-8")
                    if hashlib.sha256(content).hexdigest() in hashes:
                        return True
                    try:
                        decoded = json.loads(content)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        decoded = None
                    if decoded is not None and _contains_identity(decoded, ids, hashes):
                        return True
    return False


def hard_purge(
    store: ImprintStore,
    root: Path,
    scope: str,
    *,
    confirmation: str,
    sentinel: str | None = None,
    approval_token: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Purge one connected entity closure after exact, separate confirmation."""
    if confirmation != scope:
        raise SafetyError("purge confirmation must exactly name the scope")
    root = validate_data_root(root)
    operation_id = make_urn("purge")
    purged_at = utc_now()
    with store.connect() as conn:
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute("BEGIN IMMEDIATE")
        nodes, edges, events, ingest_items, scope_class = _closure(conn, scope)
        counts = {
            "nodes": len(nodes), "edges": len(edges), "events": len(events),
            "ingest_items": len(ingest_items),
        }
        node_versions = {
            str(row[0]) for row in conn.execute(
                f"SELECT version_id FROM node_versions WHERE node_id IN ({','.join('?' for _ in nodes)})",
                list(nodes),
            )
        } if nodes else set()
        edge_versions = {
            str(row[0]) for row in conn.execute(
                f"SELECT version_id FROM edge_versions WHERE edge_id IN ({','.join('?' for _ in edges)})",
                list(edges),
            )
        } if edges else set()
        content_hashes: set[str] = set()
        if node_versions:
            marks = ",".join("?" for _ in node_versions)
            content_hashes |= {str(row[0]) for row in conn.execute(
                f"SELECT payload_sha256 FROM node_versions WHERE version_id IN ({marks})", list(node_versions)
            )}
            if "semantic_artifact_bytes" in {
                row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }:
                content_hashes |= {str(row[0]) for row in conn.execute(
                    f"SELECT content_sha256 FROM semantic_artifact_bytes WHERE version_id IN ({marks})", list(node_versions)
                )}
        if edge_versions:
            marks = ",".join("?" for _ in edge_versions)
            content_hashes |= {str(row[0]) for row in conn.execute(
                f"SELECT payload_sha256 FROM edge_versions WHERE version_id IN ({marks})", list(edge_versions)
            )}
        if ingest_items:
            marks = ",".join("?" for _ in ingest_items)
            content_hashes |= {str(row[0]) for row in conn.execute(
                f"SELECT source_sha256 FROM ingest_items WHERE item_id IN ({marks})", list(ingest_items)
            )}
        identity_ids = set(nodes) | set(edges) | set(events) | set(ingest_items) | node_versions | edge_versions | {scope}
        identities = (identity_ids, content_hashes)
        planned_locations = [
            {"surface_id": entry.surface_id, "kind": entry.kind, "path": str(path)}
            for entry, path in content_locations(root)
        ]
        planned_locations.extend(
            {"surface_id": str(row[0]), "kind": "registered_external", "path": str(row[1])}
            for row in conn.execute(
                "SELECT surface_id,absolute_path FROM content_locations WHERE active=1 ORDER BY location_id"
            )
        )
        execution = store._consume_authority(
            conn, approval_token, command_name="purge.execute",
            purpose="irreversibly purge canonical data",
            intent={"scope": scope, "scope_class": scope_class, "counts": counts},
            execution_fields={"operation_id": operation_id, "purged_at": purged_at},
            prior_state={
                "nodes": sorted(nodes), "edges": sorted(edges),
                "events": sorted(events), "ingest_items": sorted(ingest_items),
            },
            authority_transition="canonical_data_to_purged",
            subject_ids=tuple(sorted(nodes)), target_ids=tuple(sorted(edges)),
            scope=(scope_class, scope),
        )
        operation_id = execution["operation_id"]
        purged_at = execution["purged_at"]
        conn.execute(
            """INSERT INTO purge_operations VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                operation_id, store.expected_operator_id or scope, scope, scope_class,
                json.dumps(sorted(identity_ids)), json.dumps(sorted(content_hashes)),
                json.dumps(planned_locations, sort_keys=True), "incomplete", purged_at,
                None, json.dumps(planned_locations, sort_keys=True),
                json.dumps(counts, sort_keys=True),
            ),
        )
        node_marks = ",".join("?" for _ in nodes)
        if node_versions:
            version_marks = ",".join("?" for _ in node_versions)
            relation_versions = {
                str(row[0]) for row in conn.execute(
                    f"""SELECT relation_version_id FROM semantic_relation_versions
                        WHERE source_version_id IN ({version_marks}) OR target_version_id IN ({version_marks})""",
                    [*node_versions, *node_versions],
                )
            }
            if relation_versions:
                relation_marks = ",".join("?" for _ in relation_versions)
                conn.execute(
                    f"DELETE FROM semantic_relation_versions WHERE relation_version_id IN ({relation_marks})",
                    list(relation_versions),
                )
                identity_ids |= relation_versions
            conn.execute(
                f"DELETE FROM semantic_confidence_heads WHERE assessment_version_id IN ({version_marks}) OR subject_version_id IN ({version_marks})",
                [*node_versions, *node_versions],
            )
            conn.execute(f"DELETE FROM semantic_artifact_bytes WHERE version_id IN ({version_marks})", list(node_versions))
            conn.execute(f"DELETE FROM semantic_node_versions WHERE version_id IN ({version_marks})", list(node_versions))
            if nodes:
                conn.execute(
                    f"DELETE FROM semantic_correction_events WHERE record_id IN ({node_marks})",
                    list(nodes),
                )
                conn.execute(
                    f"DELETE FROM semantic_contest_events WHERE record_id IN ({node_marks})",
                    list(nodes),
                )
        if edges:
            edge_marks = ",".join("?" for _ in edges)
            conn.execute(f"DELETE FROM edge_versions WHERE edge_id IN ({edge_marks})", list(edges))
            conn.execute(f"DELETE FROM edges WHERE edge_id IN ({edge_marks})", list(edges))
        item_marks = ",".join("?" for _ in ingest_items)
        if ingest_items:
            counts["ingest_rulings"] = conn.execute(
                f"SELECT COUNT(*) FROM ingest_rulings WHERE item_id IN ({item_marks})", list(ingest_items)
            ).fetchone()[0]
        if events:
            event_marks = ",".join("?" for _ in events)
            counts["source_receipts"] = conn.execute(
                f"SELECT COUNT(*) FROM source_receipts WHERE event_id IN ({event_marks})", list(events)
            ).fetchone()[0]
            conn.execute(f"DELETE FROM source_receipts WHERE event_id IN ({event_marks})", list(events))
            conn.execute(f"DELETE FROM ingest_rulings WHERE event_id IN ({event_marks})", list(events))
        if ingest_items:
            conn.execute(f"DELETE FROM ingest_rulings WHERE item_id IN ({item_marks})", list(ingest_items))
            conn.execute(f"DELETE FROM ingest_items WHERE item_id IN ({item_marks})", list(ingest_items))
        if nodes:
            conn.execute(f"DELETE FROM node_versions WHERE node_id IN ({node_marks})", list(nodes))
            conn.execute(f"DELETE FROM nodes WHERE node_id IN ({node_marks})", list(nodes))
        if events:
            # Source-only ingest rulings have events but no canonical nodes.
            # Delete their event closure after dependent ruling/item rows just
            # as we do for node-backed scopes.
            event_marks = ",".join("?" for _ in events)
            conn.execute(
                f"DELETE FROM captured_feedback_dedup WHERE first_event_id IN ({event_marks})",
                list(events),
            )
            conn.execute(f"DELETE FROM consumed_inputs WHERE input_event_id IN ({event_marks})", list(events))
            conn.execute(f"DELETE FROM events WHERE event_id IN ({event_marks})", list(events))
    connection = sqlite3.connect(store.path)
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("VACUUM")
    finally:
        connection.close()
    projection_dir = root / "projections"
    secure_directory(projection_dir)
    snapshot = store.snapshot()
    markdown_path = projection_dir / "imprint.md"
    jsonld_path = projection_dir / "imprint.jsonld"
    _write_private_text(markdown_path, markdown_document(snapshot))
    _write_private_text(
        jsonld_path,
        json.dumps(jsonld_document(snapshot), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )
    secure_tree(root)
    del sentinel  # legacy plaintext sentinels are not a purge identity.
    deleted_files = _remove_owned_files_with_markers(store, root, identities)
    try:
        remaining = _scan_active_root(root, identities, store)
    except TypeError:
        # Compatibility for injected two-argument inventory probes.
        remaining = _scan_active_root(root, identities)
    if _database_content_has_markers(store, identities):
        remaining.append(store.path.name)
    if remaining:
        with store.connect() as conn:
            conn.execute(
                "UPDATE purge_operations SET remaining_locations_json=? WHERE operation_id=?",
                (json.dumps(sorted(remaining)), operation_id),
            )
        return {
            "status": "purged_with_residue",
            "purge_state": "incomplete",
            "operation_id": operation_id,
            "scope_class": scope_class,
            "counts": counts,
            "content_files_removed": len(deleted_files),
            "active_root_scan": "residue",
            "residue_locations": remaining,
            "committed": True,
            "external_backups_exports": "not_discoverable; inventory separately",
            "preserved_trust_metadata": {
                "path": "authority", "status": "preserved",
                "destruction_requires": "separate signed authority-destruction ceremony",
            },
        }
    with store.connect() as conn:
        conn.execute(
            """UPDATE purge_operations SET status='complete',completed_at=?,remaining_locations_json='[]'
               WHERE operation_id=?""",
            (utc_now(), operation_id),
        )
        conn.execute(
            "INSERT INTO purge_receipts VALUES(?,?,?,?,?)",
            (operation_id, purged_at, STORE_SCHEMA_VERSION, scope_class, json.dumps(counts, sort_keys=True)),
        )
    return {
        "status": "purged",
        "purge_state": "complete",
        "operation_id": operation_id,
        "scope_class": scope_class,
        "counts": counts,
        "content_files_removed": len(deleted_files),
        "active_root_scan": "clear",
        "external_backups_exports": "not_discoverable; inventory separately",
        "preserved_trust_metadata": {
            "path": "authority", "status": "preserved",
            "destruction_requires": "separate signed authority-destruction ceremony",
        },
    }
