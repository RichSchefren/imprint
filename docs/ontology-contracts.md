# Typed Ontology Contracts

Ontology schema `3.1.0` is additive to store and capture schema `3.0.0`. The
SQLite node/edge ledger remains canonical; these contracts prevent future
systems from assigning incompatible meanings to preserved JSON.

## Write boundary

New semantic classes must enter through:

```bash
imprint ontology add-node --input node.json --valid-from 2026-07-14T12:00:00Z
imprint ontology add-relation --input relation.json --valid-from 2026-07-14T12:00:00Z
imprint consent grant --input consent.json --valid-from 2026-07-14T12:00:00Z
imprint observation add --input observation.json --valid-from 2026-07-14T12:00:00Z
imprint outcome add --input outcome.json --valid-from 2026-07-14T12:00:00Z
```

The configured operator identity must match `operator_id`. Every inferred,
extracted, or ratified object requires canonical evidence. Unknown fields,
unknown types, invalid endpoint signatures, and authority escalation are
rejected before the ledger is mutated.

The older derived-node API exists only for v3 and legacy compatibility. It
cannot create self-model, direction, observation, outcome, consent, or
calibration classes.

## Producer coverage

`imprint ontology coverage` publishes the complete type inventory with one of
two classifications. `shipped` means a product path actually creates the type:
the Stop `CapturePipeline`, the deterministic `derive --capture` reference
deriver, or a dedicated Domain/Observation/Outcome/Consent command.
`integration_only` means Imprint preserves and validates the type through
`ontology add-node`, but does not pretend to ship a domain-specific producer.
The ontology remains intact so future integrations can store the correct typed
data from their first write.

## Node envelope

```json
{
  "record_schema_version": "3.1.0",
  "node_id": "urn:imprint:principle:UUID",
  "node_type": "Principle",
  "operator_id": "urn:imprint:operator:UUID",
  "payload": {"statement": "Report material source failures explicitly."},
  "provenance": {
    "status": "inferred",
    "authority_tier": "inferred_candidate",
    "actor_class": "model",
    "actor_id": "urn:imprint:model:UUID",
    "mechanism": "typed_ontology_proposal",
    "evidence_ids": ["urn:imprint:evidence:UUID"],
    "model": "provider/model-version",
    "ratifier_id": null
  }
}
```

`captured`, `extracted`, `inferred`, and `ratified` are distinct provenance
states. Ratified objects require the same operator identity as author and
ratifier. Inferred objects remain candidates and are excluded from authoritative
retrieval until explicit review.

## Relation envelope

```json
{
  "record_schema_version": "3.1.0",
  "relation_id": "urn:imprint:relation:UUID",
  "relation_type": "inferred_from",
  "source_id": "urn:imprint:principle:UUID",
  "source_type": "Principle",
  "target_id": "urn:imprint:verdict:UUID",
  "target_type": "Verdict",
  "operator_id": "urn:imprint:operator:UUID",
  "evidence_mode": "inferred",
  "why": "The proposed principle was inferred from this witnessed verdict.",
  "provenance": {}
}
```

The complete provenance object is identical to the node envelope. Both
endpoints must exist, have the declared types, and belong to the same operator.
Evidence mode is first-class and must agree with provenance.

## Semantic partitions

The judgment partition includes Case, Verdict, Call, Alternative, Principle,
Belief, Value, Rule, Pattern, Domain, Outcome, and CalibrationTrial. A Pattern
must name at least two distinct Case IDs. A missing reason remains `null` with an
explicit reason status.

The public core does not publish private identity, personal-direction, or
cross-model relation taxonomies. Those semantics may be supplied only by a
separately distributed namespaced extension with explicit validators, authority
rules, and migrations. Until such an extension is installed, the canonical
writer rejects those records rather than preserving them as opaque core data.

The business/world partition includes declared customers, problems, desires,
claims, promises, expectations, mechanisms, offers, prices, channels,
objections, and proof; plus observed support, purchases, usage, results, refunds,
retention, referrals, general Observations, and Outcomes. Typed relations keep
declared theory separate from observed operating evidence.

## Retrieval partitions and authority modes

Every rendered retrieval record carries an `ontology` object with its semantic
`partition`, `type`, `path`, optional `confidence`, and plain-language
`disclosure`. The stable public-core partitions are `judgment`,
`business_declared`, and `business_observed`. Declared business theory and
observed operating evidence therefore remain distinguishable even when both
are deliberately requested. Extension partitions must be namespaced and cannot
claim public-core authority.

Retrieval defaults to `authoritative`, which excludes inference. Analytical
retrieval requires an explicit partition request and preserves a clear
non-authority disclosure for model-produced material.

## Consent

Explicit local judgment capture is the sole consent-exempt source. Conversation
imports, transcripts, Screenpipe, financial records, behavioral telemetry,
business systems, customer results, approved imports, and external connectors
are denied unless a current ConsentGrant authorizes the source class, purpose,
operation, sensitivity, retention rule, and effective interval.

Consent is checked inside the canonical writer. A JSON field that merely names
a grant is insufficient: the referenced grant must exist, belong to the same
operator, be unexpired and unrevoked, and authorize the attempted write.
Day-based retention expires from `effective_from`; it is not advisory metadata.
Create, inspect, and revoke grants through the append-only control surface:

```bash
imprint consent grant --input CONSENT_GRANT.json --valid-from RFC3339
imprint consent list
imprint consent revoke GRANT_URN --by OPERATOR_URN --reason "reason"
```

Revocation creates a new grant version and durable `consent_revoked` event.
It does not silently delete previously captured evidence; deletion remains a
separate preview-and-confirm operation so residue can be reported honestly.

## Portability

JSON-LD exports include `ontologySchemaVersion`, semantic payloads, evidence,
operator identity, provenance, authority, typed endpoints, and bitemporal
intervals directly in `@graph`, plus the complete lossless ledger. Imports
require both compatible store and ontology schema versions and verify hashes
before writing an empty store. Import does not trust those hashes for meaning:
it re-runs the typed node and relation contracts, re-checks consent for every
observed record, and enforces the authority lattice on every version — so a
document cannot smuggle ratified or model-authored authority, or a
consent-bearing observation, by pointing a record at an unexpected creation
event. Import fails closed rather than lowering any of these checks.

Two scope caveats. The lossless guarantee covers the canonical database, not the
local operator identity: `identity.json` is outside the export, so importing into
a fresh operator root mints a new operator URN and later writes against the
imported records will fail the operator-match checks unless you carry the
original identity across as well. And because import pins the exact store schema
(`3.0.0`) and column sets, a store that has taken an additive migration is not
re-importable through this path; export before migrating if you need a portable
copy. `--dry-run` validates the full document and writes nothing, not even an
empty database file.
