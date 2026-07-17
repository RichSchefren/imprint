"""High-level human-present enrollment, approval, and verification service."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from imprint.errors import ConflictError, ValidationError
from imprint.durable_io import publish_new_private
from imprint.permissions import secure_directory, secure_file, unsafe_private_permissions
from imprint.store import ImprintStore
from .challenge import (
    ApprovalToken, ChallengeRequest, canonical_bytes, sha256_hex, signature_message,
    parse_timestamp,
)
from .keys import (
    ALGORITHM_SUITE, decrypt_private_key, encrypt_private_key, generate_key,
    key_aad, prepare_key_directory, read_verified_blob, verify_public_binding,
)
from .ledger import (
    LEDGER_DOMAIN, active_binding, append_ledger_event, create_checkpoint as ledger_create_checkpoint,
    insert_genesis, issue_challenge, utc_now, utc_text, verify_authority_chain,
    verify_and_consume as ledger_verify_and_consume, verify_genesis,
)
from .recovery import (
    decrypt_recovery_key, encrypt_recovery_key, verify_authority_transport,
    verify_recovery_bundle, write_authority_transport, write_recovery_bundle,
)
from .trust import (
    advance_anchor_to_local_head, assert_authority_writes_allowed,
    establish_authority_trust_anchor,
    load_authority_trust_anchor, pin_local_checkpoint, retain_authority_conflict,
)
from .tty import CeremonyConsole, NativeConsole


class AuthorityService:
    def __init__(
        self, data_root: Path, store: ImprintStore, *, operator_id: str,
        clock: Callable[[], datetime] | None = None,
    ):
        if not isinstance(operator_id, str) or not operator_id.startswith("urn:imprint:operator:"):
            raise ValidationError("configured operator identity is invalid")
        self.data_root = Path(data_root)
        self.store = store
        self.operator_id = operator_id
        self.clock = clock

    def _checkpoint(self, name: str) -> None:
        """Fault-injection seam; production execution intentionally does nothing."""
        del name

    def _store_identity(self, conn: sqlite3.Connection) -> str:
        row = conn.execute("SELECT value FROM meta WHERE key='store_identity'").fetchone()
        if row is not None:
            value = row[0]
            if not isinstance(value, str) or not value.startswith("urn:imprint:store:"):
                raise ValidationError("store identity is corrupt")
            return value
        value = f"urn:imprint:store:{uuid.uuid4()}"
        conn.execute("INSERT INTO meta(key,value) VALUES('store_identity',?)", (value,))
        return value

    def _installation_id(self) -> str:
        return f"urn:imprint:installation:{secrets.token_hex(32)}"

    @staticmethod
    def _exact_confirmation(
        terminal: CeremonyConsole, *, label: str, transition: Mapping[str, Any], phrase: str,
    ) -> None:
        encoded = canonical_bytes(dict(transition))
        terminal.write(f"\nExact {label} (RFC 8785 canonical JSON):\n")
        terminal.write(encoded.decode("utf-8") + "\n")
        terminal.write(f"Transition SHA-256: {sha256_hex(encoded)}\n")
        if terminal.read_line(f"Type {phrase} to sign this exact transition: ") != phrase:
            raise ValidationError(f"{label} was not confirmed")

    def _authoritative_legacy_rows(self, conn: sqlite3.Connection) -> int:
        node_count = conn.execute(
            "SELECT COUNT(*) FROM node_versions WHERE authority_tier IN ('captured_judgment','ratified_knowledge')"
        ).fetchone()[0]
        edge_count = conn.execute(
            "SELECT COUNT(*) FROM edge_versions WHERE authority_tier IN ('captured_judgment','ratified_knowledge')"
        ).fetchone()[0]
        return int(node_count) + int(edge_count)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _write_staging(path: Path, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = -1
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            secure_file(path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _publish_stage(staging: Path, final: Path) -> None:
        if final.exists() or final.is_symlink():
            raise ConflictError("authority key target already exists")
        try:
            os.link(staging, final, follow_symlinks=False)
        except FileExistsError as exc:
            raise ConflictError("authority key target already exists") from exc
        secure_file(final)
        if final.stat(follow_symlinks=False).st_nlink != 2:
            final.unlink(missing_ok=True)
            raise ValidationError("authority key publication identity is invalid")
        staging.unlink()
        if final.stat(follow_symlinks=False).st_nlink != 1:
            raise ValidationError("authority key publication has unexpected links")

    def _recovery_journal_path(self) -> Path:
        return self.data_root / "authority" / "recovery-publication.journal"

    def _create_recovery_journal(self, value: Mapping[str, Any]) -> Path:
        directory = secure_directory(self.data_root / "authority")
        final = self._recovery_journal_path()
        if final.exists() or final.is_symlink():
            raise ConflictError(
                "unfinished recovery publication journal requires native reconciliation"
            )
        staging = directory / f".{final.name}.{uuid.uuid4().hex}.staged"
        self._write_staging(staging, canonical_bytes(dict(value)) + b"\n")
        self._publish_stage(staging, final)
        self._fsync_directory(directory)
        return final

    def _clear_recovery_journal(self) -> None:
        journal = self._recovery_journal_path()
        if journal.exists() and not journal.is_symlink():
            journal.unlink()
            self._fsync_directory(journal.parent)

    @staticmethod
    def _read_canonical_file(path: Path, *, label: str) -> dict[str, Any]:
        candidate = Path(path)
        if candidate.is_symlink() or not candidate.is_file():
            raise ValidationError(f"{label} must be a regular non-symlink file")
        raw = candidate.read_bytes()
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError(f"{label} is malformed") from exc
        if not isinstance(value, dict) or canonical_bytes(value) + b"\n" != raw:
            raise ValidationError(f"{label} is not canonical")
        return value

    def reconcile(self) -> dict[str, int]:
        """Fail closed on committed corruption; quarantine unbound key files."""
        journal_path = self._recovery_journal_path()
        if journal_path.exists() or journal_path.is_symlink():
            journal = self._read_canonical_file(
                journal_path, label="interrupted recovery publication journal",
            )
            raise ValidationError(
                "unfinished recovery publication requires native reconciliation; "
                f"retained destination={journal.get('destination')}"
            )
        keys_dir = self.data_root / "authority" / "keys"
        if keys_dir.exists() or keys_dir.is_symlink():
            if keys_dir.is_symlink() or not keys_dir.is_dir():
                raise ValidationError("authority key directory is unsafe")
            unsafe = unsafe_private_permissions(keys_dir)
            if unsafe:
                raise ValidationError(
                    "authority key state has unsafe permissions: " + ", ".join(unsafe)
                )
        else:
            keys_dir = prepare_key_directory(self.data_root)
        quarantine = secure_directory(self.data_root / "authority" / "quarantine")
        referenced: set[Path] = set()
        with self.store.connect() as conn:
            bindings = [dict(row) for row in conn.execute("SELECT * FROM authority_keys")]
            chain = verify_authority_chain(
                conn, expected_operator_id=self.operator_id,
            ) if bindings else None
            for binding in bindings:
                referenced.add(self.data_root / binding["blob_rel_path"])
                blob = read_verified_blob(self.data_root, binding)
                row = conn.execute(
                    "SELECT * FROM authority_ledger WHERE sequence=?", (binding["ledger_sequence"],),
                ).fetchone()
                if row is None:
                    raise ValidationError("authority ledger binding is missing")
                if int(binding["ledger_sequence"]) == 1:
                    verify_genesis(binding, dict(row))
                    certificate = json.loads(row["event_json"])
                else:
                    certificate = json.loads(row["event_json"]).get("details", {})
                state = chain["keys"].get(binding["key_id"])
                if (
                    not isinstance(certificate, dict) or state is None
                    or state["status"] != binding["status"]
                    or state["install_id"] != binding["install_id"]
                    or state["public_key_b64"] != binding["public_key_b64"]
                    or any(certificate.get(name) != binding[name] for name in (
                        "blob_rel_path", "blob_sha256", "blob_size", "algorithm_suite",
                    ))
                ):
                    raise ValidationError("authority key materialization disagrees with the signed ledger")
        moved = 0
        for candidate in keys_dir.iterdir():
            if candidate in referenced:
                continue
            if candidate.is_symlink() or not candidate.is_file():
                raise ValidationError("unsafe unbound authority key artifact")
            target = quarantine / f"orphan-{uuid.uuid4().hex}.blob"
            os.replace(candidate, target)
            secure_file(target)
            moved += 1
        self._fsync_directory(keys_dir)
        self._fsync_directory(quarantine)
        return {"quarantined_orphans": moved, "active_bindings": len(referenced)}

    def abandon_interrupted_recovery(
        self, *, console: CeremonyConsole | None = None,
    ) -> dict[str, Any]:
        """Explicitly clear only the journal; never delete the retained offline proof."""
        terminal = console or NativeConsole()
        terminal.require_native()
        journal = self._read_canonical_file(
            self._recovery_journal_path(), label="interrupted recovery publication journal",
        )
        self._exact_confirmation(
            terminal, label="interrupted recovery abandonment",
            transition=journal, phrase="ABANDON INTERRUPTED RECOVERY",
        )
        self._clear_recovery_journal()
        return {
            "status": "abandoned", "retained_destination": journal["destination"],
            "warning": "the retained external bundle is not active authority and must not be used",
        }

    def _enroll_with_recovery(
        self, destination: Path, terminal: CeremonyConsole,
    ) -> dict[str, Any]:
        """Create genesis with recovery bound at sequence one; publish bundle first."""
        destination = Path(destination).absolute()
        try:
            destination.relative_to(self.data_root.absolute())
        except ValueError:
            pass
        else:
            raise ValidationError("recovery bundle must be stored outside the ordinary data root")
        if terminal.read_line(
            "Type ENROLL WITH-RECOVERY to create this trust domain and its offline recovery bundle: "
        ) != "ENROLL WITH-RECOVERY":
            raise ValidationError("authority recovery enrollment was not confirmed")
        authority_passphrase = terminal.read_secret("New authority signing passphrase: ")
        repeated = terminal.read_secret("Repeat authority signing passphrase: ")
        if authority_passphrase != repeated:
            raise ValidationError("authority passphrases do not match")
        recovery_passphrase = terminal.read_secret("New separate recovery passphrase: ")
        recovery_repeated = terminal.read_secret("Repeat separate recovery passphrase: ")
        if recovery_passphrase != recovery_repeated:
            raise ValidationError("recovery passphrases do not match")
        machine, recovery_key = generate_key(), generate_key()
        with self.store.connect() as conn:
            store_identity = self._store_identity(conn)
        install_id = self._installation_id()
        recovery_install_id = f"urn:imprint:recovery:{secrets.token_hex(32)}"
        created_at = utc_text(utc_now(self.clock))
        enrollment_nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
        metadata = {
            "operator_id": self.operator_id, "install_id": install_id,
            "store_identity": store_identity, "key_id": machine.key_id,
            "public_key_b64": base64.b64encode(machine.public_key_raw).decode(),
            "public_key_fingerprint": machine.fingerprint, "created_at": created_at,
            "algorithm_suite": ALGORITHM_SUITE, "ledger_sequence": 1,
            "enrollment_nonce": enrollment_nonce,
        }
        recovery_metadata = {
            "operator_id": self.operator_id, "store_identity": store_identity,
            "recovery_key_id": recovery_key.key_id,
            "recovery_public_key_b64": base64.b64encode(recovery_key.public_key_raw).decode(),
            "recovery_public_key_fingerprint": recovery_key.fingerprint,
            "recovery_install_id": recovery_install_id, "created_at": created_at,
        }
        recovery_binding = {
            "key_id": recovery_key.key_id,
            "public_key_b64": recovery_metadata["recovery_public_key_b64"],
            "public_key_fingerprint": recovery_key.fingerprint,
            "install_id": recovery_install_id,
        }
        machine_blob = encrypt_private_key(
            machine.private_key, authority_passphrase, aad=key_aad(metadata),
        )
        encrypted_recovery = encrypt_recovery_key(
            recovery_key, recovery_passphrase, metadata=recovery_metadata,
        )
        authority_passphrase = repeated = recovery_passphrase = recovery_repeated = ""
        keys_dir = prepare_key_directory(self.data_root)
        final = keys_dir / f"{machine.fingerprint.removeprefix('sha256:')}.blob"
        staging = keys_dir / f".{final.name}.{uuid.uuid4().hex}.staged"
        relative = str(final.relative_to(self.data_root))
        self._write_staging(staging, machine_blob)
        self._fsync_directory(keys_dir)
        journal: Path | None = None
        published_key = committed = False
        try:
            with self.store.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                if conn.execute("SELECT 1 FROM authority_ledger LIMIT 1").fetchone():
                    raise ConflictError("authority was enrolled concurrently")
                receipt = insert_genesis(
                    conn, metadata=metadata, blob_rel_path=relative,
                    blob_sha256=hashlib.sha256(machine_blob).hexdigest(),
                    blob_size=len(machine_blob), private_key=machine.private_key,
                    recovery_binding=recovery_binding,
                    approve=lambda event: self._exact_confirmation(
                        terminal, label="initial authority and recovery binding",
                        transition=event, phrase="BIND INITIAL AUTHORITY",
                    ),
                )
                chain = verify_authority_chain(
                    conn, expected_operator_id=self.operator_id,
                    expected_store_identity=store_identity,
                )
                checkpoint = ledger_create_checkpoint(
                    conn, expected_operator_id=self.operator_id,
                    signer_binding=metadata, signer_private_key=machine.private_key,
                    clock=self.clock,
                )
                rows = [dict(row) for row in conn.execute(
                    "SELECT * FROM authority_ledger ORDER BY sequence"
                )]
                journal = self._create_recovery_journal({
                    "journal_version": "imprint.authority.recovery-publication/1.0.0",
                    "operation_id": f"urn:imprint:recovery-publication:{uuid.uuid4()}",
                    "destination": str(destination), "recovery_key_id": recovery_key.key_id,
                    "ledger_head_sha256": chain["head_sha256"],
                    "state": "prepared-before-external-publication",
                })
                bundle_result = write_recovery_bundle(
                    destination, manifest_base={
                        **recovery_metadata, "ledger_sequence": chain["head_sequence"],
                        "ledger_head_sha256": chain["head_sha256"],
                        "authority_ledger_genesis_sha256": chain["genesis_event_sha256"],
                        "signer_key_id": machine.key_id, "signer_install_id": install_id,
                        "checkpoint_history": [checkpoint],
                        "creation_checkpoint": checkpoint,
                    }, ledger_rows=rows, encrypted_recovery_key=encrypted_recovery,
                    signer_private_key=machine.private_key,
                )
                self._checkpoint("enrollment_recovery_bundle_published")
                self._publish_stage(staging, final)
                published_key = True
                self._fsync_directory(keys_dir)
                if hashlib.sha256(final.read_bytes()).hexdigest() != hashlib.sha256(machine_blob).hexdigest():
                    raise ValidationError("published authority key failed verification")
                establish_authority_trust_anchor(
                    conn, chain=chain, recovery_key_id=recovery_key.key_id,
                    recovery_public_key_b64=recovery_metadata["recovery_public_key_b64"],
                    checkpoint=checkpoint, now=utc_now(self.clock),
                )
                conn.commit()
                committed = True
            self._fsync_store()
        except Exception:
            staging.unlink(missing_ok=True)
            if published_key and not committed and final.exists() and not final.is_symlink():
                quarantine = secure_directory(self.data_root / "authority" / "quarantine")
                os.replace(final, quarantine / f"orphan-{uuid.uuid4().hex}.blob")
                self._fsync_directory(quarantine)
            raise
        self._clear_recovery_journal()
        return {
            "status": "enrolled", "operator_id": self.operator_id,
            "install_id": install_id, "store_identity": store_identity,
            "key_id": machine.key_id, "public_key_fingerprint": machine.fingerprint,
            "ledger_sequence": 1, "ledger_event_sha256": receipt["event_sha256"],
            "recovery": "created", "recovery_bundle": bundle_result,
        }

    def enroll(
        self, *, console: CeremonyConsole | None = None,
        recovery_destination: Path | None = None,
    ) -> dict[str, Any]:
        """Perform the only first-trust ceremony and commit activation last."""
        terminal = console or NativeConsole()
        terminal.require_native()
        self.store.initialize()
        keys_dir = prepare_key_directory(self.data_root)
        with self.store.connect() as conn:
            if conn.execute("SELECT 1 FROM authority_ledger LIMIT 1").fetchone() is not None:
                raise ConflictError("authority is already enrolled")
            if self._authoritative_legacy_rows(conn):
                raise ConflictError("store has authority-bearing data but no verifiable authority ledger")
            store_identity = self._store_identity(conn)
        if recovery_destination is not None:
            terminal.write(
                "\nRecovery will be bound at authority-ledger sequence 1. "
                "The encrypted bundle must be kept offline.\n"
            )
            return self._enroll_with_recovery(recovery_destination, terminal)
        install_id = self._installation_id()
        terminal.write(
            "\nImprint authority enrollment\n"
            f"Operator: {self.operator_id}\nInstallation: {install_id}\nStore: {store_identity}\n"
            "Losing the passphrase and every recovery path permanently removes the ability to preserve authority.\n"
        )
        if terminal.read_line(
            "Type ENROLL DECLINE-RECOVERY to create this trust domain without an offline recovery key: "
        ) != "ENROLL DECLINE-RECOVERY":
            raise ValidationError("authority enrollment was not confirmed")
        passphrase = terminal.read_secret("New authority signing passphrase: ")
        repeated = terminal.read_secret("Repeat authority signing passphrase: ")
        if passphrase != repeated:
            raise ValidationError("authority passphrases do not match")
        key = generate_key()
        created_at = utc_text(utc_now(self.clock))
        enrollment_nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
        metadata = {
            "operator_id": self.operator_id,
            "install_id": install_id,
            "store_identity": store_identity,
            "key_id": key.key_id,
            "public_key_b64": base64.b64encode(key.public_key_raw).decode("ascii"),
            "public_key_fingerprint": key.fingerprint,
            "created_at": created_at,
            "algorithm_suite": ALGORITHM_SUITE,
            "ledger_sequence": 1,
            "enrollment_nonce": enrollment_nonce,
        }
        blob = encrypt_private_key(key.private_key, passphrase, aad=key_aad(metadata))
        # Drop Python references as early as possible.  CPython strings cannot
        # be reliably zeroized; the secret is never persisted or emitted.
        passphrase = repeated = ""
        final_name = f"{key.fingerprint.removeprefix('sha256:')}.blob"
        final = keys_dir / final_name
        staging = keys_dir / f".{final_name}.{uuid.uuid4().hex}.staged"
        relative = str(final.relative_to(self.data_root))
        blob_sha = hashlib.sha256(blob).hexdigest()
        self._write_staging(staging, blob)
        self._fsync_directory(keys_dir)
        self._checkpoint("staging_durable")
        published = False
        committed = False
        receipt: dict[str, Any]
        try:
            with self.store.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                if conn.execute("SELECT 1 FROM authority_ledger LIMIT 1").fetchone() is not None:
                    raise ConflictError("authority was enrolled concurrently")
                # The signed intent is inserted in this uncommitted transaction.
                receipt = insert_genesis(
                    conn, metadata=metadata, blob_rel_path=relative,
                    blob_sha256=blob_sha, blob_size=len(blob), private_key=key.private_key,
                )
                chain = verify_authority_chain(
                    conn, expected_operator_id=self.operator_id,
                    expected_store_identity=store_identity,
                )
                initial_checkpoint = ledger_create_checkpoint(
                    conn, expected_operator_id=self.operator_id,
                    signer_binding=metadata, signer_private_key=key.private_key,
                    clock=self.clock,
                )
                establish_authority_trust_anchor(
                    conn, chain=chain, checkpoint=initial_checkpoint,
                    now=utc_now(self.clock),
                )
                self._checkpoint("sqlite_intent_inserted")
                self._publish_stage(staging, final)
                published = True
                self._fsync_directory(keys_dir)
                self._checkpoint("blob_published")
                verified = final.read_bytes()
                secure_file(final)
                if len(verified) != len(blob) or hashlib.sha256(verified).hexdigest() != blob_sha:
                    raise ValidationError("published authority key failed verification")
                self._checkpoint("blob_reverified")
                conn.commit()  # Activation point; filesystem was verified first.
                committed = True
                self._checkpoint("sqlite_committed")
            self._fsync_store()
        except Exception:
            staging.unlink(missing_ok=True)
            if published and not committed and final.exists() and not final.is_symlink():
                quarantine = secure_directory(self.data_root / "authority" / "quarantine")
                os.replace(final, quarantine / f"orphan-{uuid.uuid4().hex}.blob")
                self._fsync_directory(quarantine)
                self._fsync_directory(keys_dir)
            raise
        return {
            "status": "enrolled", "operator_id": self.operator_id,
            "install_id": install_id, "store_identity": store_identity,
            "key_id": key.key_id, "public_key_fingerprint": key.fingerprint,
            "ledger_sequence": 1, "ledger_event_sha256": receipt["event_sha256"],
            "recovery": "explicitly_declined",
        }

    def _fsync_store(self) -> None:
        if not self.store.path.exists():
            return
        # Windows rejects fsync() on a read-only descriptor. The store is an
        # Imprint-owned SQLite file, so use a write-capable descriptor on every
        # platform and preserve the no-follow boundary where it is available.
        descriptor = os.open(
            self.store.path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._fsync_directory(self.store.path.parent)

    def _active_private_key(
        self, terminal: CeremonyConsole, *, prompt: str = "Authority signing passphrase: ",
    ) -> tuple[dict[str, Any], Any]:
        self.reconcile()
        with self.store.connect() as conn:
            assert_authority_writes_allowed(conn)
            binding = active_binding(conn, expected_operator_id=self.operator_id)
            chain = verify_authority_chain(conn, expected_operator_id=self.operator_id)
            chain_key = chain["keys"].get(binding["key_id"])
            if (
                chain_key is None or chain_key["status"] != "active"
                or chain_key["kind"] != "installation"
                or chain_key["install_id"] != binding["install_id"]
                or chain_key["public_key_b64"] != binding["public_key_b64"]
            ):
                raise ValidationError("local authority key state disagrees with the signed ledger")
        passphrase = terminal.read_secret(prompt)
        blob = read_verified_blob(self.data_root, binding)
        private_key = decrypt_private_key(blob, passphrase, aad=key_aad(binding))
        passphrase = ""
        verify_public_binding(private_key, binding["public_key_b64"])
        return binding, private_key

    def create_checkpoint(
        self, *, console: CeremonyConsole | None = None, ttl_seconds: int = 24 * 60 * 60,
    ) -> dict[str, Any]:
        terminal = console or NativeConsole()
        terminal.require_native()
        binding, private_key = self._active_private_key(terminal)
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            anchor = assert_authority_writes_allowed(conn)
            checkpoint = ledger_create_checkpoint(
                conn, expected_operator_id=self.operator_id, signer_binding=binding,
                signer_private_key=private_key, clock=self.clock, ttl_seconds=ttl_seconds,
                prior_checkpoint_sha256=anchor.checkpoint_sha256,
            )
            pin_local_checkpoint(
                conn, checkpoint=checkpoint,
                operation_digest="local-checkpoint:" + sha256_hex(canonical_bytes(checkpoint)),
                now=utc_now(self.clock),
            )
            conn.commit()
        self._fsync_store()
        return checkpoint

    def sign_portable_payload(
        self, payload: Mapping[str, Any], *, domain_separator: bytes,
        checkpoint_time_field: str | None = None,
        console: CeremonyConsole | None = None,
    ) -> dict[str, Any]:
        """Human-present detached signing without exposing private key material."""
        allowed = {
            b"imprint-backup-receipt-v1\x00",
            b"imprint-export-manifest-v1\x00",
        }
        if domain_separator not in allowed:
            raise ValidationError("portable signature domain is not allowed")
        terminal = console or NativeConsole()
        terminal.require_native()
        binding, private_key = self._active_private_key(terminal)
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            anchor = assert_authority_writes_allowed(conn)
            chain = verify_authority_chain(conn, expected_operator_id=self.operator_id)
            checkpoint = ledger_create_checkpoint(
                conn, expected_operator_id=self.operator_id, signer_binding=binding,
                signer_private_key=private_key, clock=self.clock,
                prior_checkpoint_sha256=anchor.checkpoint_sha256,
            )
            pin_local_checkpoint(
                conn, checkpoint=checkpoint,
                operation_digest="portable-sign:" + sha256_hex(canonical_bytes(payload)),
                now=utc_now(self.clock),
            )
            conn.commit()
        self._fsync_store()
        final_payload = dict(payload)
        if checkpoint_time_field is not None:
            if not isinstance(checkpoint_time_field, str) or not checkpoint_time_field:
                raise ValidationError("checkpoint time field is invalid")
            supplied = final_payload.get(checkpoint_time_field)
            if supplied is not None and supplied != checkpoint["issued_at"]:
                raise ValidationError("portable manifest checkpoint time conflicts with the signed checkpoint")
            final_payload[checkpoint_time_field] = checkpoint["issued_at"]
        encoded = canonical_bytes(final_payload)
        terminal.write("\nExact portable manifest (RFC 8785 canonical JSON):\n")
        terminal.write(encoded.decode("utf-8") + "\n")
        if terminal.read_line("Type SIGN SNAPSHOT to sign this exact manifest: ") != "SIGN SNAPSHOT":
            raise ValidationError("portable manifest was not approved")
        signature = private_key.sign(domain_separator + encoded)
        return {
            "payload": final_payload,
            "signer_key_id": binding["key_id"], "signer_install_id": binding["install_id"],
            "ledger_sequence": chain["head_sequence"],
            "ledger_head_sha256": chain["head_sha256"],
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "checkpoint": checkpoint,
        }

    def sign_backup_snapshot(
        self, payload_factory, *, console: CeremonyConsole | None = None,
    ) -> dict[str, Any]:
        """Pin trust before copying a backup, then sign that exact copied state.

        ``payload_factory`` is invoked only after the new checkpoint is durably
        committed.  It receives the active signer key ID and must return the
        detached-signature payload.  Private key material and the checkpoint
        cannot be supplied by the caller and never leave this method.
        """
        terminal = console or NativeConsole()
        terminal.require_native()
        binding, private_key = self._active_private_key(terminal)
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            anchor = assert_authority_writes_allowed(conn)
            chain = verify_authority_chain(conn, expected_operator_id=self.operator_id)
            checkpoint = ledger_create_checkpoint(
                conn, expected_operator_id=self.operator_id, signer_binding=binding,
                signer_private_key=private_key, clock=self.clock,
                prior_checkpoint_sha256=anchor.checkpoint_sha256,
            )
            pin_local_checkpoint(
                conn, checkpoint=checkpoint,
                operation_digest="backup-snapshot-pending",
                now=utc_now(self.clock),
            )
            conn.commit()
        self._fsync_store()

        payload = payload_factory(binding["key_id"])
        if not isinstance(payload, Mapping):
            raise ValidationError("backup snapshot payload factory returned an invalid payload")
        encoded = canonical_bytes(payload)
        terminal.write("\nExact backup receipt (RFC 8785 canonical JSON):\n")
        terminal.write(encoded.decode("utf-8") + "\n")
        if terminal.read_line("Type SIGN SNAPSHOT to sign this exact manifest: ") != "SIGN SNAPSHOT":
            raise ValidationError("portable manifest was not approved")
        return {
            "payload": dict(payload),
            "signer_key_id": binding["key_id"],
            "signer_install_id": binding["install_id"],
            "ledger_sequence": chain["head_sequence"],
            "ledger_head_sha256": chain["head_sha256"],
            "signature_b64": base64.b64encode(
                private_key.sign(b"imprint-backup-receipt-v1\x00" + encoded)
            ).decode("ascii"),
            "checkpoint": checkpoint,
        }

    def export_authority_transport(
        self, destination: Path, *, console: CeremonyConsole | None = None,
    ) -> dict[str, Any]:
        """Create-new the public chain plus a fresh, locally pinned checkpoint."""
        terminal = console or NativeConsole()
        terminal.require_native()
        checkpoint = self.create_checkpoint(console=terminal)
        with self.store.connect() as conn:
            chain = verify_authority_chain(
                conn, expected_operator_id=self.operator_id,
                checkpoint=checkpoint, now=utc_now(self.clock),
            )
            rows = [dict(row) for row in conn.execute(
                "SELECT * FROM authority_ledger ORDER BY sequence"
            )]
            checkpoint_history = [
                json.loads(row[0]) for row in conn.execute(
                    "SELECT checkpoint_json FROM authority_checkpoint_pins ORDER BY accepted_at, rowid"
                )
            ]
        transition = {
            "operation": "export_authority_transport",
            "destination": str(Path(destination).absolute()),
            "checkpoint_sha256": sha256_hex(canonical_bytes(checkpoint)),
            "ledger_sequence": chain["head_sequence"],
            "ledger_head_sha256": chain["head_sha256"],
        }
        self._exact_confirmation(
            terminal, label="authority transport publication",
            transition=transition, phrase="PUBLISH AUTHORITY TRANSPORT",
        )
        return write_authority_transport(
            destination, operator_id=self.operator_id,
            store_identity=chain["store_identity"],
            genesis_event_sha256=chain["genesis_event_sha256"],
            ledger_rows=rows, checkpoint_history=checkpoint_history,
            checkpoint=checkpoint,
        )

    def bootstrap_recovery_trust(
        self, recovery_bundle: Path, *, console: CeremonyConsole | None = None,
    ) -> dict[str, Any]:
        """Separate native ceremony that makes recovery trust destination-owned."""
        terminal = console or NativeConsole()
        terminal.require_native()
        verified = verify_recovery_bundle(recovery_bundle)
        manifest = verified["manifest"]
        if manifest["operator_id"] != self.operator_id:
            raise ValidationError("recovery trust bootstrap belongs to another operator")
        passphrase = terminal.read_secret("Recovery passphrase: ")
        # Successful decryption proves possession of the separately carried
        # recovery credential; the private key is never installed locally.
        decrypt_recovery_key(
            verified["encrypted_recovery_key"], passphrase, metadata=manifest,
        )
        passphrase = ""
        pin = {
            "bootstrap_version": "imprint.authority.recovery-trust-bootstrap/1.0.0",
            "operator_id": self.operator_id, "store_identity": manifest["store_identity"],
            "authority_ledger_genesis_sha256": manifest["authority_ledger_genesis_sha256"],
            "recovery_key_id": manifest["recovery_key_id"],
            "recovery_public_key_fingerprint": manifest["recovery_public_key_fingerprint"],
            "checkpoint_sha256": sha256_hex(canonical_bytes(manifest["creation_checkpoint"])),
        }
        self._exact_confirmation(
            terminal, label="destination recovery trust pin", transition=pin,
            phrase="PIN RECOVERY TRUST",
        )
        self.store.initialize()
        with self.store.connect() as conn:
            if conn.execute("SELECT 1 FROM authority_ledger LIMIT 1").fetchone():
                raise ConflictError("recovery trust bootstrap requires a fresh target ledger")
            conn.execute("BEGIN IMMEDIATE")
            existing = load_authority_trust_anchor(conn)
            if existing is None:
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key,value) VALUES('store_identity',?)",
                    (manifest["store_identity"],),
                )
                establish_authority_trust_anchor(
                    conn, chain=verified["chain"],
                    recovery_key_id=manifest["recovery_key_id"],
                    recovery_public_key_b64=manifest["recovery_public_key_b64"],
                    checkpoint=manifest["creation_checkpoint"],
                    checkpoint_history=manifest["checkpoint_history"],
                    now=utc_now(self.clock),
                )
            elif (
                existing.operator_id != self.operator_id
                or existing.store_identity != manifest["store_identity"]
                or existing.genesis_event_sha256 != manifest["authority_ledger_genesis_sha256"]
                or existing.recovery_key_id != manifest["recovery_key_id"]
                or existing.recovery_public_key_b64 != manifest["recovery_public_key_b64"]
            ):
                raise ValidationError("existing destination trust anchor rejects this recovery key")
            conn.commit()
        self._fsync_store()
        return {"status": "recovery_trust_pinned", **pin}

    def create_pairing_request(
        self, destination: Path, *,
        console: CeremonyConsole | None = None,
    ) -> dict[str, Any]:
        """Create a target-owned key and request; no source private key is copied."""
        terminal = console or NativeConsole()
        terminal.require_native()
        self.store.initialize()
        with self.store.connect() as conn:
            if conn.execute("SELECT 1 FROM authority_ledger LIMIT 1").fetchone():
                raise ConflictError("pairing request requires a fresh target authority ledger")
            anchor = assert_authority_writes_allowed(conn)
            if anchor.recovery_key_id is None:
                raise ValidationError("pairing target lacks a separately pinned recovery trust key")
        passphrase = terminal.read_secret("New machine authority passphrase: ")
        repeated = terminal.read_secret("Repeat new machine authority passphrase: ")
        if passphrase != repeated:
            raise ValidationError("new machine authority passphrases do not match")
        key, install_id = generate_key(), self._installation_id()
        created = utc_now(self.clock)
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        metadata = {
            "operator_id": self.operator_id, "install_id": install_id,
            "store_identity": anchor.store_identity, "key_id": key.key_id,
            "public_key_b64": base64.b64encode(key.public_key_raw).decode(),
            "public_key_fingerprint": key.fingerprint, "created_at": utc_text(created),
            "algorithm_suite": ALGORITHM_SUITE,
            "ledger_sequence": anchor.pinned_sequence + 1,
            "enrollment_nonce": nonce,
        }
        blob = encrypt_private_key(key.private_key, passphrase, aad=key_aad(metadata))
        passphrase = repeated = ""
        keys_dir = prepare_key_directory(self.data_root)
        final = keys_dir / f"{key.fingerprint.removeprefix('sha256:')}.blob"
        staging = keys_dir / f".{final.name}.{uuid.uuid4().hex}.staged"
        self._write_staging(staging, blob)
        request = {
            "request_version": "imprint.authority.pairing-request/1.0.0",
            "request_id": f"urn:imprint:pairing-request:{uuid.uuid4()}",
            "operator_id": self.operator_id, "store_identity": anchor.store_identity,
            "install_id": install_id, "key_id": key.key_id,
            "public_key_b64": metadata["public_key_b64"],
            "public_key_fingerprint": key.fingerprint,
            "pairing_nonce": nonce, "blob_rel_path": str(final.relative_to(self.data_root)),
            "blob_sha256": hashlib.sha256(blob).hexdigest(), "blob_size": len(blob),
            "algorithm_suite": ALGORITHM_SUITE, "created_at": utc_text(created),
            "expires_at": utc_text(created + timedelta(hours=24)),
            "expected_ledger_sequence": metadata["ledger_sequence"],
        }
        self._exact_confirmation(
            terminal, label="new-machine pairing request", transition=request,
            phrase="CREATE PAIRING REQUEST",
        )
        self._publish_stage(staging, final)
        self._fsync_directory(keys_dir)
        request_json = canonical_bytes(request).decode()
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO authority_pairing_requests(
                   request_id,request_json,request_sha256,key_id,install_id,blob_rel_path,
                   blob_sha256,blob_size,enrollment_nonce,created_at,expires_at,status,finalized_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?, ?,NULL)""",
                (request["request_id"], request_json, sha256_hex(request_json.encode()),
                 key.key_id, install_id, request["blob_rel_path"], request["blob_sha256"],
                 request["blob_size"], nonce, request["created_at"], request["expires_at"],
                 "pending"),
            )
            conn.commit()
        self._fsync_store()
        publish_new_private(Path(destination), canonical_bytes(request) + b"\n")
        return {"status": "pairing_requested", "request": request, "path": str(destination)}

    def authorize_pairing_request(
        self, request_path: Path, destination: Path, *,
        console: CeremonyConsole | None = None,
    ) -> dict[str, Any]:
        """An active authorized machine signs the exact remote installation binding."""
        terminal = console or NativeConsole()
        terminal.require_native()
        request = self._read_canonical_file(request_path, label="pairing request")
        fields = {
            "request_version", "request_id", "operator_id", "store_identity",
            "install_id", "key_id", "public_key_b64", "public_key_fingerprint",
            "pairing_nonce", "blob_rel_path", "blob_sha256", "blob_size",
            "algorithm_suite", "created_at", "expires_at",
            "expected_ledger_sequence",
        }
        if set(request) != fields or request["request_version"] != "imprint.authority.pairing-request/1.0.0":
            raise ValidationError("pairing request has unknown fields or version")
        if request["operator_id"] != self.operator_id or utc_now(self.clock) >= parse_timestamp(request["expires_at"]):
            raise ValidationError("pairing request operator or expiry is invalid")
        binding, signer = self._active_private_key(terminal)
        if request["store_identity"] != binding["store_identity"]:
            raise ValidationError("pairing request belongs to another trust domain")
        request_sha = sha256_hex(canonical_bytes(request))
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            anchor = assert_authority_writes_allowed(conn)
            if request["expected_ledger_sequence"] != anchor.pinned_sequence + 1:
                raise ValidationError("pairing request is stale relative to the trusted ledger head")
            authorization = {
                "certificate_version": "imprint.authority.authorize-installation/1.0.0",
                "operator_id": self.operator_id, "store_identity": binding["store_identity"],
                "new_install_id": request["install_id"], "new_key_id": request["key_id"],
                "new_public_key_b64": request["public_key_b64"],
                "pairing_nonce": request["pairing_nonce"],
                "pairing_request_sha256": request_sha,
                "preceding_authority_head_sha256": anchor.pinned_head_sha256,
                "expires_at": request["expires_at"],
            }
            appended = append_ledger_event(
                conn, event_type="installation_paired", operator_id=self.operator_id,
                install_id=request["install_id"], key_id=request["key_id"],
                details={
                    "key_id": request["key_id"], "public_key_b64": request["public_key_b64"],
                    "public_key_fingerprint": request["public_key_fingerprint"],
                    "install_id": request["install_id"], "blob_rel_path": request["blob_rel_path"],
                    "blob_sha256": request["blob_sha256"], "blob_size": request["blob_size"],
                    "algorithm_suite": request["algorithm_suite"], "authorization": authorization,
                }, signer_key_id=binding["key_id"], signer_private_key=signer,
                clock=self.clock,
                approve=lambda event: self._exact_confirmation(
                    terminal, label="active-machine pairing certificate", transition=event,
                    phrase="AUTHORIZE EXACT PAIRING",
                ),
            )
            chain = verify_authority_chain(conn, expected_operator_id=self.operator_id)
            advance_anchor_to_local_head(conn, chain=chain, now=utc_now(self.clock))
            current_anchor = assert_authority_writes_allowed(conn)
            checkpoint = ledger_create_checkpoint(
                conn, expected_operator_id=self.operator_id, signer_binding=binding,
                signer_private_key=signer, clock=self.clock,
                prior_checkpoint_sha256=current_anchor.checkpoint_sha256,
            )
            pin_local_checkpoint(
                conn, checkpoint=checkpoint,
                operation_digest="pairing:" + request_sha, now=utc_now(self.clock),
            )
            rows = [dict(row) for row in conn.execute(
                "SELECT * FROM authority_ledger ORDER BY sequence"
            )]
            history = [json.loads(row[0]) for row in conn.execute(
                "SELECT checkpoint_json FROM authority_checkpoint_pins ORDER BY accepted_at, rowid"
            )]
            conn.commit()
        self._fsync_store()
        package = {
            "package_version": "imprint.authority.pairing-package/1.0.0",
            "request": request, "request_sha256": request_sha,
            "transport": {
                "transport_version": "imprint.authority.transport/1.0.0",
                "operator_id": self.operator_id, "store_identity": binding["store_identity"],
                "authority_ledger_genesis_sha256": chain["genesis_event_sha256"],
                "ledger": rows,
                "ledger_sha256": sha256_hex(canonical_bytes({"ledger": rows})),
                "checkpoint_history": history, "checkpoint": checkpoint,
            },
            "certificate_event_sha256": appended["event_sha256"],
        }
        publish_new_private(Path(destination), canonical_bytes(package) + b"\n")
        return {"status": "pairing_authorized", "path": str(destination), "request_sha256": request_sha}

    def finalize_pairing(
        self, package_path: Path, *, console: CeremonyConsole | None = None,
    ) -> dict[str, Any]:
        """Commit an authorized remote ledger only against target-owned pending state."""
        terminal = console or NativeConsole()
        terminal.require_native()
        package = self._read_canonical_file(package_path, label="pairing package")
        fields = {"package_version", "request", "request_sha256", "transport", "certificate_event_sha256"}
        if set(package) != fields or package["package_version"] != "imprint.authority.pairing-package/1.0.0":
            raise ValidationError("pairing package has unknown fields or version")
        request = package["request"]
        if package["request_sha256"] != sha256_hex(canonical_bytes(request)):
            raise ValidationError("pairing package request digest mismatch")
        transported = verify_authority_transport(package["transport"], now=utc_now(self.clock))
        with self.store.connect() as conn:
            pending = conn.execute(
                "SELECT * FROM authority_pairing_requests WHERE request_id=?",
                (request["request_id"],),
            ).fetchone()
            anchor = assert_authority_writes_allowed(conn)
            if (
                pending is None or pending["status"] != "pending"
                or pending["request_json"] != canonical_bytes(request).decode()
                or pending["request_sha256"] != package["request_sha256"]
            ):
                raise ValidationError("pairing package does not match target-owned pending state")
            if (
                transported["chain"]["genesis_event_sha256"] != anchor.genesis_event_sha256
                or transported["chain"]["store_identity"] != anchor.store_identity
            ):
                raise ValidationError("pairing package belongs to another destination trust anchor")
        self._exact_confirmation(
            terminal, label="pairing finalization", transition={
                "request_sha256": package["request_sha256"],
                "certificate_event_sha256": package["certificate_event_sha256"],
                "checkpoint_sha256": sha256_hex(canonical_bytes(transported["checkpoint"])),
                "new_install_id": request["install_id"], "new_key_id": request["key_id"],
            }, phrase="FINALIZE EXACT PAIRING",
        )
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for row in transported["ledger"]:
                conn.execute(
                    "INSERT INTO authority_ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(row[name] for name in (
                        "sequence", "event_id", "event_type", "operator_id", "install_id", "key_id",
                        "event_json", "event_sha256", "signature_b64", "previous_event_sha256", "created_at",
                    )),
                )
            history = transported["transport"]["checkpoint_history"]
            existing = load_authority_trust_anchor(conn)
            assert existing is not None
            start = next((i for i, item in enumerate(history) if sha256_hex(canonical_bytes(item)) == existing.checkpoint_sha256), None)
            if start is None:
                raise ValidationError("pairing transport does not extend bootstrap checkpoint")
            for item in history[start + 1:]:
                pin_local_checkpoint(
                    conn, checkpoint=item,
                    operation_digest="pairing-finalize:" + package["request_sha256"],
                    now=utc_now(self.clock),
                    enforce_freshness=False,
                )
            event_row = conn.execute(
                "SELECT * FROM authority_ledger WHERE event_sha256=?",
                (package["certificate_event_sha256"],),
            ).fetchone()
            if event_row is None:
                raise ValidationError("pairing certificate event is absent")
            if int(event_row["sequence"]) != request["expected_ledger_sequence"]:
                raise ValidationError("pairing certificate sequence does not match the pending key binding")
            details = json.loads(event_row["event_json"])["details"]
            if details["authorization"]["pairing_request_sha256"] != package["request_sha256"]:
                raise ValidationError("pairing certificate does not bind the pending request")
            conn.execute(
                """INSERT INTO authority_keys VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (request["key_id"], self.operator_id, request["install_id"], request["store_identity"],
                 request["public_key_b64"], request["public_key_fingerprint"], "active",
                 event_row["sequence"], request["blob_rel_path"], request["blob_sha256"],
                 request["blob_size"], request["algorithm_suite"], request["pairing_nonce"],
                 request["created_at"]),
            )
            chain = verify_authority_chain(conn, expected_operator_id=self.operator_id)
            advance_anchor_to_local_head(conn, chain=chain, now=utc_now(self.clock))
            conn.execute(
                "UPDATE authority_pairing_requests SET status='finalized',finalized_at=? WHERE request_id=?",
                (utc_text(utc_now(self.clock)), request["request_id"]),
            )
            conn.commit()
        self._fsync_store()
        return {"status": "paired", "install_id": request["install_id"], "key_id": request["key_id"]}

    def create_recovery_bundle(
        self, destination: Path, *, console: CeremonyConsole | None = None,
    ) -> dict[str, Any]:
        terminal = console or NativeConsole()
        terminal.require_native()
        terminal.write("\nCreate encrypted offline authority recovery bundle.\n")
        if terminal.read_line("Type CREATE RECOVERY to continue: ") != "CREATE RECOVERY":
            raise ValidationError("recovery creation was not confirmed")
        binding, signer = self._active_private_key(terminal)
        recovery_passphrase = terminal.read_secret("New separate recovery passphrase: ")
        repeated = terminal.read_secret("Repeat separate recovery passphrase: ")
        if recovery_passphrase != repeated:
            raise ValidationError("recovery passphrases do not match")
        destination = Path(destination).absolute()
        try:
            destination.relative_to(self.data_root.absolute())
        except ValueError:
            pass
        else:
            raise ValidationError("recovery bundle must be stored outside the ordinary data root")
        recovery_key = generate_key()
        recovery_install_id = f"urn:imprint:recovery:{secrets.token_hex(32)}"
        created_at = utc_text(utc_now(self.clock))
        metadata = {
            "operator_id": self.operator_id, "store_identity": binding["store_identity"],
            "recovery_key_id": recovery_key.key_id,
            "recovery_public_key_b64": base64.b64encode(recovery_key.public_key_raw).decode(),
            "recovery_public_key_fingerprint": recovery_key.fingerprint,
            "recovery_install_id": recovery_install_id, "created_at": created_at,
        }
        encrypted = encrypt_recovery_key(
            recovery_key, recovery_passphrase, metadata=metadata,
        )
        recovery_passphrase = repeated = ""
        journal: Path | None = None
        try:
            with self.store.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                anchor = assert_authority_writes_allowed(conn)
                append_ledger_event(
                    conn, event_type="recovery_created", operator_id=self.operator_id,
                    install_id=recovery_install_id, key_id=recovery_key.key_id,
                    details={
                        "key_id": recovery_key.key_id,
                        "public_key_b64": metadata["recovery_public_key_b64"],
                        "public_key_fingerprint": recovery_key.fingerprint,
                        "install_id": recovery_install_id,
                    },
                    signer_key_id=binding["key_id"], signer_private_key=signer,
                    clock=self.clock,
                    approve=lambda event: self._exact_confirmation(
                        terminal, label="recovery-key binding", transition=event,
                        phrase="BIND RECOVERY KEY",
                    ),
                )
                chain = verify_authority_chain(conn, expected_operator_id=self.operator_id)
                checkpoint = ledger_create_checkpoint(
                    conn, expected_operator_id=self.operator_id, signer_binding=binding,
                    signer_private_key=signer, clock=self.clock,
                    prior_checkpoint_sha256=anchor.checkpoint_sha256,
                )
                rows = [dict(row) for row in conn.execute(
                    "SELECT * FROM authority_ledger ORDER BY sequence"
                )]
                checkpoint_history = [
                    json.loads(row[0]) for row in conn.execute(
                        "SELECT checkpoint_json FROM authority_checkpoint_pins ORDER BY accepted_at, rowid"
                    )
                ] + [checkpoint]
                journal = self._create_recovery_journal({
                    "journal_version": "imprint.authority.recovery-publication/1.0.0",
                    "operation_id": f"urn:imprint:recovery-publication:{uuid.uuid4()}",
                    "destination": str(destination),
                    "recovery_key_id": recovery_key.key_id,
                    "ledger_head_sha256": chain["head_sha256"],
                    "state": "prepared-before-external-publication",
                })
                result = write_recovery_bundle(
                    destination, manifest_base={
                        **metadata, "ledger_sequence": chain["head_sequence"],
                        "ledger_head_sha256": chain["head_sha256"],
                        "authority_ledger_genesis_sha256": chain["genesis_event_sha256"],
                        "signer_key_id": binding["key_id"],
                        "signer_install_id": binding["install_id"],
                        "checkpoint_history": checkpoint_history,
                        "creation_checkpoint": checkpoint,
                    }, ledger_rows=rows, encrypted_recovery_key=encrypted,
                    signer_private_key=signer,
                )
                self._checkpoint("recovery_bundle_published")
                pin_local_checkpoint(
                    conn, checkpoint=checkpoint,
                    operation_digest="recovery-publication:" + result["bundle_sha256"],
                    now=utc_now(self.clock),
                )
                conn.execute(
                    """UPDATE authority_trust_anchor SET
                       recovery_key_id=?,recovery_public_key_b64=?,updated_at=? WHERE anchor_id=1""",
                    (recovery_key.key_id, metadata["recovery_public_key_b64"], created_at),
                )
                conn.commit()
                self._checkpoint("recovery_ledger_committed")
            self._fsync_store()
        except Exception:
            # The journal and any already-published offline bundle are retained.
            # They are evidence of an interrupted ceremony and are never guessed away.
            raise
        self._clear_recovery_journal()
        return result

    def restore_recovery_bundle(
        self, source: Path, *, console: CeremonyConsole | None = None,
        authority_transport: Path | Mapping[str, Any] | None = None,
        replace_install_id: str | None = None,
    ) -> dict[str, Any]:
        """Restore authority to a fresh installation with a distinct machine key."""
        terminal = console or NativeConsole()
        terminal.require_native()
        verified_bundle = verify_recovery_bundle(source, now=utc_now(self.clock))
        manifest = verified_bundle["manifest"]
        if manifest["operator_id"] != self.operator_id:
            raise ValidationError("recovery bundle belongs to another operator")
        if authority_transport is None:
            raise ValidationError(
                "recovery restore requires a separately supplied fresh authority transport"
            )
        transported = verify_authority_transport(authority_transport, now=utc_now(self.clock))
        transport_chain = transported["chain"]
        if (
            transport_chain["operator_id"] != self.operator_id
            or transport_chain["store_identity"] != manifest["store_identity"]
            or transport_chain["genesis_event_sha256"] != manifest["authority_ledger_genesis_sha256"]
        ):
            raise ValidationError("fresh authority transport belongs to another trust domain")
        current_recovery = transport_chain["keys"].get(manifest["recovery_key_id"])
        if (
            current_recovery is None or current_recovery["kind"] != "recovery"
            or current_recovery["status"] != "active"
            or current_recovery["public_key_b64"] != manifest["recovery_public_key_b64"]
        ):
            raise ValidationError("offline recovery credential is not active at the fresh checkpoint")
        self.store.initialize()
        with self.store.connect() as conn:
            if conn.execute("SELECT 1 FROM authority_ledger LIMIT 1").fetchone():
                raise ConflictError("recovery restore requires a fresh authority ledger")
            if self._authoritative_legacy_rows(conn):
                raise ConflictError("fresh recovery target already contains authority-bearing data")
            existing_anchor = load_authority_trust_anchor(conn)
            if existing_anchor is None:
                raise ValidationError(
                    "recovery restore requires a separate destination trust-bootstrap ceremony"
                )
            if (
                existing_anchor.operator_id != self.operator_id
                or existing_anchor.store_identity != manifest["store_identity"]
                or existing_anchor.genesis_event_sha256 != manifest["authority_ledger_genesis_sha256"]
                or existing_anchor.recovery_key_id != manifest["recovery_key_id"]
                or existing_anchor.recovery_public_key_b64 != manifest["recovery_public_key_b64"]
                or existing_anchor.checkpoint_sha256
                != sha256_hex(canonical_bytes(manifest["creation_checkpoint"]))
            ):
                raise ValidationError("existing destination trust anchor rejects this recovery bundle")
        recovery_passphrase = terminal.read_secret("Recovery passphrase: ")
        recovery_private = decrypt_recovery_key(
            verified_bundle["encrypted_recovery_key"], recovery_passphrase,
            metadata=manifest,
        )
        recovery_passphrase = ""
        new_passphrase = terminal.read_secret("New machine authority passphrase: ")
        repeated = terminal.read_secret("Repeat new machine authority passphrase: ")
        if new_passphrase != repeated:
            raise ValidationError("new machine authority passphrases do not match")
        machine = generate_key()
        install_id = self._installation_id()
        created_at = utc_text(utc_now(self.clock))
        next_sequence = transport_chain["head_sequence"] + 1
        metadata = {
            "operator_id": self.operator_id, "install_id": install_id,
            "store_identity": manifest["store_identity"], "key_id": machine.key_id,
            "public_key_b64": base64.b64encode(machine.public_key_raw).decode(),
            "public_key_fingerprint": machine.fingerprint, "created_at": created_at,
            "algorithm_suite": ALGORITHM_SUITE, "ledger_sequence": next_sequence,
            "enrollment_nonce": base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode(),
        }
        blob = encrypt_private_key(machine.private_key, new_passphrase, aad=key_aad(metadata))
        new_passphrase = repeated = ""
        keys_dir = prepare_key_directory(self.data_root)
        final = keys_dir / f"{machine.fingerprint.removeprefix('sha256:')}.blob"
        staging = keys_dir / f".{final.name}.{uuid.uuid4().hex}.staged"
        self._write_staging(staging, blob)
        self._checkpoint("recovery_restore_staging_durable")
        authorization = {
            "certificate_version": "imprint.authority.authorize-installation/1.0.0",
            "operator_id": self.operator_id,
            "store_identity": manifest["store_identity"],
            "new_install_id": install_id,
            "new_key_id": machine.key_id,
            "new_public_key_b64": metadata["public_key_b64"],
            "pairing_nonce": metadata["enrollment_nonce"],
            "pairing_request_sha256": sha256_hex(canonical_bytes({
                "ceremony": "recovery_restore",
                "install_id": install_id,
                "key_id": machine.key_id,
                "public_key_b64": metadata["public_key_b64"],
                "nonce": metadata["enrollment_nonce"],
            })),
            "preceding_authority_head_sha256": transport_chain["head_sha256"],
            "expires_at": transported["checkpoint"]["expires_at"],
        }
        self._exact_confirmation(
            terminal, label="recovery installation authorization",
            transition=authorization, phrase="RESTORE AUTHORITY",
        )
        published = committed = False
        try:
            with self.store.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key,value) VALUES('store_identity',?)",
                    (manifest["store_identity"],),
                )
                for row in transported["ledger"]:
                    conn.execute(
                        "INSERT INTO authority_ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        tuple(row[name] for name in (
                            "sequence", "event_id", "event_type", "operator_id", "install_id", "key_id",
                            "event_json", "event_sha256", "signature_b64", "previous_event_sha256", "created_at",
                        )),
                    )
                details = {
                    "key_id": machine.key_id, "public_key_b64": metadata["public_key_b64"],
                    "public_key_fingerprint": machine.fingerprint, "install_id": install_id,
                    "blob_rel_path": str(final.relative_to(self.data_root)),
                    "blob_sha256": hashlib.sha256(blob).hexdigest(), "blob_size": len(blob),
                    "algorithm_suite": ALGORITHM_SUITE,
                    "authorization": authorization,
                }
                event_type = "installation_paired"
                if replace_install_id is not None:
                    details["old_install_id"] = replace_install_id
                    event_type = "installation_rebound"
                appended = append_ledger_event(
                    conn, event_type=event_type, operator_id=self.operator_id,
                    install_id=install_id, key_id=machine.key_id, details=details,
                    signer_key_id=manifest["recovery_key_id"],
                    signer_private_key=recovery_private, clock=self.clock,
                    approve=lambda event: self._exact_confirmation(
                        terminal, label="recovery-signed ledger transition",
                        transition=event, phrase="SIGN RESTORE CERTIFICATE",
                    ),
                )
                self._checkpoint("recovery_restore_ledger_intent")
                relative = str(final.relative_to(self.data_root))
                self._publish_stage(staging, final)
                published = True
                self._fsync_directory(keys_dir)
                self._checkpoint("recovery_restore_blob_published")
                if hashlib.sha256(final.read_bytes()).hexdigest() != hashlib.sha256(blob).hexdigest():
                    raise ValidationError("restored authority key failed publication verification")
                conn.execute(
                    """INSERT INTO authority_keys VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (machine.key_id, self.operator_id, install_id, manifest["store_identity"],
                     metadata["public_key_b64"], machine.fingerprint, "active",
                     appended["event"]["sequence"], relative, hashlib.sha256(blob).hexdigest(),
                     len(blob), ALGORITHM_SUITE, metadata["enrollment_nonce"], created_at),
                )
                chain = verify_authority_chain(
                    conn, expected_operator_id=self.operator_id,
                    expected_store_identity=manifest["store_identity"],
                    pinned_head={"sequence": transport_chain["head_sequence"], "event_sha256": transport_chain["head_sha256"]},
                )
                # Replay every signed checkpoint pin in order, then advance the
                # destination-owned anchor to the locally appended certificate.
                history = transported["transport"]["checkpoint_history"]
                existing_checkpoint = manifest["creation_checkpoint"]
                start = next(
                    (index for index, item in enumerate(history)
                     if dict(item) == dict(existing_checkpoint)),
                    None,
                )
                if start is None:
                    raise ValidationError("fresh transport does not extend recovery bootstrap checkpoint")
                for item in history[start + 1:]:
                    pin_local_checkpoint(
                        conn, checkpoint=item,
                        operation_digest="recovery-restore:" + sha256_hex(canonical_bytes(item)),
                        now=utc_now(self.clock),
                        enforce_freshness=False,
                    )
                conn.execute(
                    """UPDATE authority_trust_anchor SET
                       pinned_sequence=?,pinned_head_sha256=?,key_state_sha256=?,updated_at=?
                       WHERE anchor_id=1""",
                    (chain["head_sequence"], chain["head_sha256"], chain["key_state_sha256"], created_at),
                )
                conn.commit()
                committed = True
                self._checkpoint("recovery_restore_committed")
            self._fsync_store()
        except Exception:
            staging.unlink(missing_ok=True)
            if published and not committed and final.exists() and not final.is_symlink():
                quarantine = secure_directory(self.data_root / "authority" / "quarantine")
                os.replace(final, quarantine / f"orphan-{uuid.uuid4().hex}.blob")
            raise
        return {
            "status": "restored", "operator_id": self.operator_id,
            "store_identity": manifest["store_identity"], "install_id": install_id,
            "key_id": machine.key_id, "ledger_sequence": next_sequence,
            "snapshot_valid_as_of": transported["checkpoint"]["issued_at"],
        }

    def rotate_key(self, *, console: CeremonyConsole | None = None) -> dict[str, Any]:
        """Rotate the local installation key with publish-before-commit activation."""
        terminal = console or NativeConsole()
        terminal.require_native()
        if terminal.read_line("Type ROTATE AUTHORITY KEY to continue: ") != "ROTATE AUTHORITY KEY":
            raise ValidationError("authority rotation was not confirmed")
        old, signer = self._active_private_key(terminal)
        new_passphrase = terminal.read_secret("New authority passphrase: ")
        repeated = terminal.read_secret("Repeat new authority passphrase: ")
        if new_passphrase != repeated:
            raise ValidationError("new authority passphrases do not match")
        key = generate_key()
        created_at = utc_text(utc_now(self.clock))
        with self.store.connect() as conn:
            chain = verify_authority_chain(conn, expected_operator_id=self.operator_id)
        metadata = {
            "operator_id": self.operator_id, "install_id": old["install_id"],
            "store_identity": old["store_identity"], "key_id": key.key_id,
            "public_key_b64": base64.b64encode(key.public_key_raw).decode(),
            "public_key_fingerprint": key.fingerprint, "created_at": created_at,
            "algorithm_suite": ALGORITHM_SUITE,
            "ledger_sequence": chain["head_sequence"] + 1,
            "enrollment_nonce": base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode(),
        }
        blob = encrypt_private_key(key.private_key, new_passphrase, aad=key_aad(metadata))
        new_passphrase = repeated = ""
        keys_dir = prepare_key_directory(self.data_root)
        final = keys_dir / f"{key.fingerprint.removeprefix('sha256:')}.blob"
        staging = keys_dir / f".{final.name}.{uuid.uuid4().hex}.staged"
        self._write_staging(staging, blob)
        self._checkpoint("rotation_staging_durable")
        published = committed = False
        try:
            with self.store.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                current = active_binding(conn, expected_operator_id=self.operator_id)
                if current["key_id"] != old["key_id"]:
                    raise ConflictError("authority key changed during rotation")
                appended = append_ledger_event(
                    conn, event_type="key_rotated", operator_id=self.operator_id,
                    install_id=old["install_id"], key_id=key.key_id,
                    details={
                        "old_key_id": old["key_id"], "key_id": key.key_id,
                        "public_key_b64": metadata["public_key_b64"],
                        "public_key_fingerprint": key.fingerprint,
                        "install_id": old["install_id"],
                        "blob_rel_path": str(final.relative_to(self.data_root)),
                        "blob_sha256": hashlib.sha256(blob).hexdigest(),
                        "blob_size": len(blob), "algorithm_suite": ALGORITHM_SUITE,
                    }, signer_key_id=old["key_id"], signer_private_key=signer,
                    clock=self.clock,
                    approve=lambda event: self._exact_confirmation(
                        terminal, label="authority key rotation", transition=event,
                        phrase="SIGN EXACT ROTATION",
                    ),
                )
                self._checkpoint("rotation_ledger_intent")
                self._publish_stage(staging, final)
                published = True
                self._fsync_directory(keys_dir)
                self._checkpoint("rotation_blob_published")
                if len(final.read_bytes()) != len(blob) or hashlib.sha256(final.read_bytes()).hexdigest() != hashlib.sha256(blob).hexdigest():
                    raise ValidationError("rotated authority key failed publication verification")
                conn.execute("UPDATE authority_keys SET status='retired' WHERE key_id=?", (old["key_id"],))
                conn.execute(
                    "INSERT INTO authority_keys VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (key.key_id, self.operator_id, old["install_id"], old["store_identity"],
                     metadata["public_key_b64"], key.fingerprint, "active",
                     appended["event"]["sequence"], str(final.relative_to(self.data_root)),
                     hashlib.sha256(blob).hexdigest(), len(blob), ALGORITHM_SUITE,
                     metadata["enrollment_nonce"], created_at),
                )
                verified_chain = verify_authority_chain(
                    conn, expected_operator_id=self.operator_id,
                )
                advance_anchor_to_local_head(
                    conn, chain=verified_chain, now=utc_now(self.clock),
                )
                conn.commit()
                committed = True
                self._checkpoint("rotation_committed")
            self._fsync_store()
        except Exception:
            staging.unlink(missing_ok=True)
            if published and not committed and final.exists() and not final.is_symlink():
                quarantine = secure_directory(self.data_root / "authority" / "quarantine")
                os.replace(final, quarantine / f"orphan-{uuid.uuid4().hex}.blob")
            raise
        return {
            "status": "rotated", "old_key_id": old["key_id"], "key_id": key.key_id,
            "ledger_sequence": appended["event"]["sequence"],
        }

    def change_key_state(
        self, target_key_id: str, *, state: str, reason: str,
        console: CeremonyConsole | None = None, recovery_bundle: Path | None = None,
        effective_at: str | None = None, compromised_at: str | None = None,
        replacement_key_id: str | None = None,
        evidence_sha256s: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        """Append revocation/compromise facts; emergency self-compromise requires recovery."""
        if state not in {"revoked", "compromised"} or not reason.strip():
            raise ValidationError("authority key state or reason is invalid")
        terminal = console or NativeConsole()
        terminal.require_native()
        if terminal.read_line(f"Type MARK {state.upper()} to continue: ") != f"MARK {state.upper()}":
            raise ValidationError("authority key-state change was not confirmed")
        with self.store.connect() as conn:
            chain = verify_authority_chain(conn, expected_operator_id=self.operator_id)
            target = chain["keys"].get(target_key_id)
            if target is None or target["status"] != "active":
                raise ValidationError("authority target key is unknown or inactive")
            local = None
            try:
                local = active_binding(conn, expected_operator_id=self.operator_id)
            except ValidationError:
                pass
        if recovery_bundle is not None:
            recovered = verify_recovery_bundle(recovery_bundle, now=utc_now(self.clock))
            recovery_passphrase = terminal.read_secret("Recovery passphrase: ")
            signer = decrypt_recovery_key(
                recovered["encrypted_recovery_key"], recovery_passphrase,
                metadata=recovered["manifest"],
            )
            recovery_passphrase = ""
            signer_id = recovered["manifest"]["recovery_key_id"]
            if signer_id not in chain["keys"] or chain["keys"][signer_id]["status"] != "active":
                raise ValidationError("recovery key is not active in the current ledger")
        else:
            if local is None or (state == "compromised" and local["key_id"] == target_key_id):
                raise ValidationError("emergency compromise of the active key requires recovery authority")
            local, signer = self._active_private_key(terminal)
            signer_id = local["key_id"]
        event_type = "key_compromised" if state == "compromised" else (
            "recovery_revoked" if target["kind"] == "recovery" else "key_revoked"
        )
        effective = effective_at or utc_text(utc_now(self.clock))
        compromise_boundary = compromised_at
        if state == "compromised" and compromise_boundary is None:
            compromise_boundary = effective
        details = {
            "target_key_id": target_key_id,
            "effective_at": effective,
            "compromised_at": compromise_boundary,
            "reason": reason,
            "replacement_key_id": replacement_key_id,
            "affected_installation_ids": [target["install_id"]],
            "evidence_sha256s": list(evidence_sha256s),
            "required_revocation_key_ids": [target_key_id],
        }
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            appended = append_ledger_event(
                conn, event_type=event_type, operator_id=self.operator_id,
                install_id=target["install_id"], key_id=target_key_id,
                details=details,
                signer_key_id=signer_id, signer_private_key=signer, clock=self.clock,
                approve=lambda event: self._exact_confirmation(
                    terminal, label="authority key-state transition", transition=event,
                    phrase="SIGN EXACT KEY STATE",
                ),
            )
            conn.execute("UPDATE authority_keys SET status=? WHERE key_id=?", (state, target_key_id))
            verified_chain = verify_authority_chain(conn, expected_operator_id=self.operator_id)
            advance_anchor_to_local_head(
                conn, chain=verified_chain, now=utc_now(self.clock),
            )
            if state == "compromised":
                retain_authority_conflict(
                    conn, conflict_class="compromise-security-hold",
                    local_proof={
                        "checkpoint_sha256": load_authority_trust_anchor(conn).checkpoint_sha256,
                        "ledger_head_sha256": verified_chain["head_sha256"],
                    },
                    candidate_proof={"compromise_event": appended, "scope": details},
                    now=utc_now(self.clock),
                )
            conn.commit()
        self._fsync_store()
        return {
            "status": state, "key_id": target_key_id,
            "ledger_sequence": appended["event"]["sequence"],
        }

    def adjudicate_authority_conflict(
        self, proof_id: str, *, chosen_checkpoint_sha256: str, reason: str,
        recovery_bundle: Path, console: CeremonyConsole | None = None,
    ) -> dict[str, Any]:
        """Recovery-sign an exact fork decision; never auto-select a competing proof."""
        terminal = console or NativeConsole()
        terminal.require_native()
        recovered = verify_recovery_bundle(recovery_bundle)
        recovery_passphrase = terminal.read_secret("Recovery passphrase: ")
        recovery_private = decrypt_recovery_key(
            recovered["encrypted_recovery_key"], recovery_passphrase,
            metadata=recovered["manifest"],
        )
        recovery_passphrase = ""
        signer_id = recovered["manifest"]["recovery_key_id"]
        with self.store.connect() as conn:
            anchor = load_authority_trust_anchor(conn)
            proof = conn.execute(
                "SELECT * FROM authority_equivocation_proofs WHERE proof_id=?", (proof_id,),
            ).fetchone()
            if anchor is None or not anchor.writes_blocked or proof is None:
                raise ValidationError("authority conflict is not pending adjudication")
            if proof["adjudication_event_sha256"] is not None:
                raise ConflictError("authority conflict was already adjudicated")
            chain = verify_authority_chain(conn, expected_operator_id=self.operator_id)
            recovery_state = chain["keys"].get(signer_id)
            if recovery_state is None or recovery_state["kind"] != "recovery" or recovery_state["status"] != "active":
                raise ValidationError("adjudication recovery key is not active")
            if chosen_checkpoint_sha256 != anchor.checkpoint_sha256:
                raise ValidationError(
                    "v3.1 adjudication may retain only the already destination-pinned checkpoint"
                )
            rejected_sha = proof["candidate_proof_sha256"]
        effective = utc_text(utc_now(self.clock))
        details = {
            "proof_id": proof_id, "chosen_checkpoint_sha256": chosen_checkpoint_sha256,
            "rejected_proof_sha256": rejected_sha, "reason": reason,
            "effective_at": effective,
        }
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            appended = append_ledger_event(
                conn, event_type="authority_conflict_adjudicated",
                operator_id=self.operator_id, install_id=recovery_state["install_id"],
                key_id=signer_id, details=details, signer_key_id=signer_id,
                signer_private_key=recovery_private, clock=self.clock,
                approve=lambda event: self._exact_confirmation(
                    terminal, label="authority conflict adjudication", transition=event,
                    phrase="ADJUDICATE EXACT CONFLICT",
                ),
            )
            verified = verify_authority_chain(conn, expected_operator_id=self.operator_id)
            conn.execute(
                "UPDATE authority_equivocation_proofs SET adjudication_event_sha256=? WHERE proof_id=?",
                (appended["event_sha256"], proof_id),
            )
            conn.execute(
                """UPDATE authority_trust_anchor SET
                   pinned_sequence=?,pinned_head_sha256=?,key_state_sha256=?,updated_at=?,
                   writes_blocked=0,block_reason=NULL WHERE anchor_id=1""",
                (verified["head_sequence"], verified["head_sha256"],
                 verified["key_state_sha256"], effective),
            )
            conn.commit()
        self._fsync_store()
        return {"status": "adjudicated", "proof_id": proof_id, "event_sha256": appended["event_sha256"]}

    def approve(
        self, request: ChallengeRequest, *, console: CeremonyConsole | None = None,
        ttl_seconds: int = 120,
    ) -> ApprovalToken:
        terminal = console or NativeConsole()
        terminal.require_native()
        self.reconcile()
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            assert_authority_writes_allowed(conn)
            prepared = conn.execute(
                "SELECT request_json,status,expires_at FROM authority_prepared_mutations WHERE operation_id=?",
                (request.operation_id,),
            ).fetchone()
            if prepared is None or prepared["status"] != "pending":
                raise ValidationError("authority approval requires a pending stored mutation")
            request_value = {
                "operation_id": request.operation_id, "purpose": request.purpose,
                "payload_sha256": request.payload_sha256,
                "prior_state_sha256": request.prior_state_sha256,
                "execution_fields_sha256": request.execution_fields_sha256,
                "authority_transition": request.authority_transition,
                "subject_ids": list(request.subject_ids), "source_ids": list(request.source_ids),
                "target_ids": list(request.target_ids), "proposal_ids": list(request.proposal_ids),
                "result_version_ids": list(request.result_version_ids), "scope": list(request.scope),
                "field_paths": list(request.field_paths),
            }
            if canonical_bytes(request_value).decode("utf-8") != prepared["request_json"]:
                raise ValidationError("authority approval request differs from stored mutation")
            from .challenge import parse_timestamp
            if utc_now(self.clock) >= parse_timestamp(prepared["expires_at"]):
                raise ValidationError("prepared mutation has expired")
            challenge, binding = issue_challenge(
                conn, request, expected_operator_id=self.operator_id,
                ttl_seconds=ttl_seconds, clock=self.clock,
            )
        terminal.write("\nExact authority mutation (RFC 8785 canonical JSON):\n")
        terminal.write(canonical_bytes(challenge).decode("utf-8") + "\n")
        if terminal.read_line("Type APPROVE to sign this exact mutation: ") != "APPROVE":
            raise ValidationError("authority operation was not approved")
        passphrase = terminal.read_secret("Authority signing passphrase: ")
        blob = read_verified_blob(self.data_root, binding)
        private_key = decrypt_private_key(blob, passphrase, aad=key_aad(binding))
        passphrase = ""
        verify_public_binding(private_key, binding["public_key_b64"])
        signature = private_key.sign(signature_message(challenge))
        return ApprovalToken(challenge=challenge, signature_b64=base64.b64encode(signature).decode("ascii"))

    def verify_and_consume(
        self, conn: sqlite3.Connection, token: ApprovalToken | Mapping[str, Any], *,
        expected: ChallengeRequest,
    ) -> str:
        assert_authority_writes_allowed(conn)
        return ledger_verify_and_consume(
            conn, token, expected=expected, expected_operator_id=self.operator_id,
            clock=self.clock,
        )
