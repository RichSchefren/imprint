"""Transactional referential rules for typed semantic payloads."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from imprint.errors import ValidationError


NodeLookup = Callable[[str], tuple[str, str] | None]
VersionLookup = Callable[[str], tuple[str, str] | None]


def validate_payload_references(
    node_type: str,
    payload: Mapping[str, Any],
    *,
    operator_id: str,
    provenance_evidence_ids: list[str],
    node_lookup: NodeLookup,
    version_lookup: VersionLookup,
) -> None:
    """Resolve semantic references against the canonical transaction view."""

    def nodes(ids: list[str], field: str, allowed: set[str] | None = None) -> None:
        for identifier in ids:
            found = node_lookup(identifier)
            if not found:
                raise ValidationError(f"{field} references a missing canonical node")
            actual_type, owner = found
            if owner != operator_id:
                raise ValidationError(f"{field} references another operator")
            if allowed is not None and actual_type not in allowed:
                raise ValidationError(f"{field} references an incompatible node type")

    def evidence(ids: list[str], field: str) -> None:
        nodes(ids, field, {"Evidence"})

    outer_evidence = set(provenance_evidence_ids)
    if provenance_evidence_ids:
        evidence(provenance_evidence_ids, "provenance.evidence_ids")

    if node_type == "Pattern":
        nodes(payload["case_ids"], "Pattern.case_ids", {"Case"})
    elif node_type == "SelfModelAssertion":
        evidence(payload["evidence_ids"], "SelfModelAssertion.evidence_ids")
        evidence(payload["confidence"]["basis_evidence_ids"], "confidence.basis_evidence_ids")
        if set(payload["evidence_ids"]) != outer_evidence:
            raise ValidationError("SelfModelAssertion evidence must match canonical provenance evidence")
        nodes([payload["derivation_trace_id"]], "derivation_trace_id", {"DerivationTrace"})
    elif node_type == "Observation":
        evidence(payload.get("evidence_ids", payload.get("source_refs", [])), "Observation evidence")
        if "confidence" in payload:
            evidence(payload["confidence"]["basis_evidence_ids"], "confidence.basis_evidence_ids")
        grant_id = payload.get("consent_grant_id")
        if grant_id is not None:
            nodes([grant_id], "consent_grant_id", {"ConsentGrant"})
    elif node_type == "Outcome":
        evidence(payload.get("source_refs", []), "Outcome.source_refs")
    elif node_type == "CalibrationTrial" and payload.get("outcome_id") is not None:
        nodes([payload["outcome_id"]], "CalibrationTrial.outcome_id", {"Outcome"})
    elif node_type == "Cue":
        evidence(payload["evidence_ids"], "Cue.evidence_ids")
        nodes([payload["observation_id"]], "Cue.observation_id", {"Observation"})
    elif node_type == "LexiconTerm":
        evidence(payload["evidence_ids"], "LexiconTerm.evidence_ids")
    elif node_type == "InterventionRule":
        evidence(payload["evidence_ids"], "InterventionRule.evidence_ids")
        nodes(payload["trigger_ids"], "InterventionRule.trigger_ids", {"Cue", "SelfModelAssertion"})
        nodes(
            payload["protects_standard_ids"], "InterventionRule.protects_standard_ids",
            {"Rule", "Principle", "SelfModelAssertion"},
        )
    elif node_type == "DerivationTrace":
        nodes(payload["input_ids"], "DerivationTrace.input_ids")
        found = version_lookup(payload["element_version_id"])
        if not found:
            raise ValidationError("DerivationTrace.element_version_id is missing")
        _, owner = found
        if owner != operator_id:
            raise ValidationError("DerivationTrace.element_version_id belongs to another operator")
    elif "source_refs" in payload:
        evidence(payload["source_refs"], f"{node_type}.source_refs")
