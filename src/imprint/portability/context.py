"""Pinned, network-free JSON-LD contexts for Imprint 3.1 exports."""

from __future__ import annotations

from types import MappingProxyType


CORE_IRI = "https://imprint.local/schema/v3#"
BUSINESS_IRI = "https://imprint.local/schema/business/v1#"

# @vocab gives every closed payload/qualifier field a deterministic field-level
# IRI. Reference-bearing fields are explicit so expansion never treats an exact
# version ID as an ordinary string. Nothing in this context dereferences a URL.
_CONTEXT = {
    "@version": 1.1,
    "@vocab": CORE_IRI,
    "imprint": CORE_IRI,
    "business": BUSINESS_IRI,
    "id": "@id",
    "type": "@type",
    "entity": {"@id": f"{CORE_IRI}entity", "@type": "@id"},
    "source": {"@id": f"{CORE_IRI}source", "@type": "@id"},
    "target": {"@id": f"{CORE_IRI}target", "@type": "@id"},
    "sourceVersion": {"@id": f"{CORE_IRI}sourceVersion", "@type": "@id"},
    "targetVersion": {"@id": f"{CORE_IRI}targetVersion", "@type": "@id"},
    "artifactVersion": {"@id": f"{CORE_IRI}artifactVersion", "@type": "@id"},
    "accessPolicyVersion": {"@id": f"{CORE_IRI}accessPolicyVersion", "@type": "@id"},
    "consentVersion": {"@id": f"{CORE_IRI}consentVersion", "@type": "@id"},
    "actor": {"@id": f"{CORE_IRI}actor", "@type": "@id"},
    "roleAssignmentVersion": {"@id": f"{CORE_IRI}roleAssignmentVersion", "@type": "@id"},
    "evidenceVersionIds": {"@id": f"{CORE_IRI}evidenceVersion", "@type": "@id", "@container": "@set"},
    "sourceArtifactVersionIds": {"@id": f"{CORE_IRI}sourceArtifactVersion", "@type": "@id", "@container": "@set"},
    "validFrom": {"@id": f"{CORE_IRI}validFrom", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
    "validTo": {"@id": f"{CORE_IRI}validTo", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
    "systemFrom": {"@id": f"{CORE_IRI}systemFrom", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
    "systemTo": {"@id": f"{CORE_IRI}systemTo", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
    "windowStart": {"@id": f"{BUSINESS_IRI}windowStart", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
    "windowEnd": {"@id": f"{BUSINESS_IRI}windowEnd", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
    "occurredAt": {"@id": f"{BUSINESS_IRI}occurredAt", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
    "decidedAt": {"@id": f"{BUSINESS_IRI}decidedAt", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
}

CONTEXT = MappingProxyType(_CONTEXT)
CONTEXT_VERSION = "imprint.context/3.2.0"
BUSINESS_CONTEXT_VERSION = "imprint.business.context/1.3.0"


def local_context() -> dict:
    """Return a mutable copy suitable for JSON serialization."""
    return {key: (dict(value) if isinstance(value, dict) else value) for key, value in CONTEXT.items()}
