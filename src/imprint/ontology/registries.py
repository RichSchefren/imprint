"""Frozen public Imprint ontology registries.

This module contains only the public Imprint storage and relation contract.
Private product ontologies are extensions and are deliberately not embedded,
enumerated, or inferable from this distribution.
"""
from __future__ import annotations

import hashlib
import re
from typing import Final


ONTOLOGY_BINDING_ID: Final = "imprint.ontology.binding/3.7.0"
PROVENANCE_SCHEMA_ID: Final = "imprint.provenance/2.1.0"
NODE_REGISTRY_ID: Final = "imprint.node.registry/1.0.0"
RELATION_REGISTRY_ID: Final = "imprint.relation.registry/1.1.0"
QUALIFIER_REGISTRY_ID: Final = "imprint.relation.qualifiers/1.1.0"
BUSINESS_NODE_REGISTRY_ID: Final = "imprint.business.node.registry/1.3.0"
BUSINESS_RELATION_REGISTRY_ID: Final = "imprint.business.relation.registry/1.3.0"

# The public recorder owns one built-in provenance phase. Product-specific
# phase taxonomies remain private and may cross this boundary only as explicit,
# namespaced extension identifiers (for example ``vendor.pipeline-step``).
BUILTIN_SOURCE_PHASE_IDS: Final = ("operator_authored",)
_NAMESPACED_SOURCE_PHASE = re.compile(
    r"^[a-z][a-z0-9-]*(?:[.:][a-z][a-z0-9._-]*)+$"
)


def is_public_source_phase_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and (
            value in BUILTIN_SOURCE_PHASE_IDS
            or _NAMESPACED_SOURCE_PHASE.fullmatch(value) is not None
        )
    )

CORE_NODE_SCHEMA_IDS: Final = (
    "imprint.node.decision-episode/1.0.0", "imprint.node.actor/1.0.0",
    "imprint.node.role-assignment/1.0.0", "imprint.node.expected-outcome/1.0.0",
    "imprint.node.confidence-assessment/1.0.0", "imprint.node.evidence-artifact/1.0.0",
    "imprint.node.access-policy/1.0.0", "imprint.node.deletion-event/1.0.0",
)

PREDICATE_IDS: Final = (
    "has_case", "has_verdict", "makes_call", "considered", "selected", "rejected",
    "made_on", "extracted_from", "protects", "expresses", "depends_on",
    "inferred_from", "similar_to", "contradicts", "superseded_by", "expected",
    "led_to", "supports", "weakens", "assesses", "assigns", "governs_scope",
    "participant", "evidenced_by", "derived_from", "authorized_by",
    "controlled_by", "deleted", "invalidated", "ratifies", "corrects", "cites",
    "supersedes", "serves", "targets", "experiences", "desires", "occurs_in",
    "promises", "expects", "requires", "supported_by", "delivered_through",
    "priced_as", "purchased_via", "used", "produced", "refunded_because",
    "retained_by", "referred_by", "observes", "tested_by", "confirms", "extends",
)
PREDICATE_IDENTITY_SHA256: Final = hashlib.sha256(
    "\n".join(PREDICATE_IDS).encode()
).hexdigest()

QUALIFIER_SCHEMA_IDS: Final = (
    "q.episode_structure@1", "q.capture_ref@1", "q.disposition@1", "q.derivation@1",
    "q.scope@1", "q.dependency@1", "q.similarity@1", "q.contradiction@1",
    "q.supersession@1", "q.expectation@1", "q.outcome@1", "q.assessment@1",
    "q.confidence@1", "q.role@1", "q.authority_scope@1", "q.evidence@1",
    "q.transform@1", "q.access@1.1", "q.deletion@1.1", "q.invalidation@1",
    "q.ratification@1", "q.correction@1", "q.cites@1", "q.success@1",
    "q.declared@1", "q.evidence_mode@1",
    "q.requirement@1", "q.price@1", "q.criterion@1", "q.extension@1",
)

_CLAIMS = frozenset({
    "Belief", "Claim", "Intervention", "Mechanism", "Offer", "Principle",
    "Promise", "Rule", "SelfModelAssertion", "Verdict",
})
_EVIDENTIARY = frozenset({
    "Belief", "Call", "Case", "Claim", "Cue", "DecisionEpisode", "ExpectedOutcome", "Intervention",
    "InterventionRule", "Mechanism", "Offer", "Outcome", "Pattern", "Principle",
    "Promise", "Rule", "SelfModelAssertion", "Verdict",
})
_DECLARED = frozenset({
    "Channel", "Claim", "Customer", "Desire", "Expectation", "Intervention",
    "Mechanism", "Offer", "Price", "Problem", "Promise", "RequiredBehavior",
    "Segment", "Situation",
})
_OBSERVED_EVENTS = frozenset({
    "Purchase", "Referral", "Refund", "Retention", "SupportAction", "Usage",
})
_OBSERVED = _OBSERVED_EVENTS | {"Observation", "Outcome", "Result"}
_PROTECTED = _EVIDENTIARY | frozenset({
    "AccessPolicy", "Actor", "Alternative", "Channel",
    "ConfidenceAssessment", "ConsentGrant", "CorrectionEvent", "Customer",
    "DeletionEvent", "DerivationTrace", "Desire", "EvidenceArtifact", "Expectation",
    "Objection", "Observation", "Price", "Problem", "Proof", "Purchase", "RatificationEvent",
    "Referral", "RequiredBehavior", "Result", "Retention", "RoleAssignment", "Segment",
    "Situation", "Standard", "SupportAction", "Usage",
})

ENDPOINT_UNIONS: Final = {
    "ClaimUnionV1": _CLAIMS,
    "EvidentiarySubjectV1": _EVIDENTIARY,
    "ProtectedRecordV1": _PROTECTED,
    "GovernedScopeV1": _PROTECTED | {"Partition", "RelationVersion"},
    "DeletionTargetV1": _PROTECTED | {"RelationVersion", "SubgraphSelection"},
    "DependentVersionV1": frozenset({
        "ExportVersion", "NodeVersion", "ProjectionVersion", "RelationVersion",
    }),
    "ProposalVersionV1": frozenset({
        "BusinessClaimProposal", "InterventionRuleProposal", "SelfModelAssertionProposal",
    }),
    "CorrectableVersionV1": _CLAIMS | {
        "BusinessClaimProposal", "ExpectedOutcome",
        "InterventionRuleProposal", "Outcome", "SelfModelAssertionProposal",
    },
    "DerivationInputV1": frozenset({
        "Belief", "Case", "EvidenceArtifact",
        "Observation", "Outcome", "Principle", "SelfModelAssertion", "Verdict",
    }),
    "DeclaredWorldV1": _DECLARED,
    "ObservedEventV1": _OBSERVED_EVENTS,
    "ObservedWorldV1": _OBSERVED,
    "WorldNodeV1": _DECLARED | _OBSERVED | {"Objection", "Proof"},
}


class RegistryError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def compile_registry_bundle() -> dict[str, object]:
    """Compile only the public Imprint registries.

    Product-specific self-model ontologies must be supplied privately through
    namespaced extension values; this bundle intentionally carries none.
    """
    if not PREDICATE_IDS or len(set(PREDICATE_IDS)) != len(PREDICATE_IDS):
        raise RegistryError("E_RELATION_REGISTRY_INCOMPLETE", "predicate identity")
    if not QUALIFIER_SCHEMA_IDS or len(set(QUALIFIER_SCHEMA_IDS)) != len(QUALIFIER_SCHEMA_IDS):
        raise RegistryError("E_RELATION_REGISTRY_INCOMPLETE", "qualifier identity")
    if len(ENDPOINT_UNIONS) != 13 or any(not value for value in ENDPOINT_UNIONS.values()):
        raise RegistryError("E_RELATION_REGISTRY_INCOMPLETE", "union identity")
    return {
        "contract_id": ONTOLOGY_BINDING_ID,
        "nodes": CORE_NODE_SCHEMA_IDS,
        "predicates": PREDICATE_IDS,
        "qualifiers": QUALIFIER_SCHEMA_IDS,
        "unions": tuple(ENDPOINT_UNIONS),
    }
