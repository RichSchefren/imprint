# Limitations and Roadmap

## Current limits

- Claude Code hook payloads and lifecycle behavior can change upstream. Hook
  failures are visible and must be revalidated against new Claude Code releases.
- The default retrieval budget is byte-based and deterministic, not a promise of
  an exact model-token count.
- Canonical SQLite is single-writer and this release is not a collaborative
  database service. Data roots under recognized cloud-sync folders (Dropbox,
  OneDrive, iCloud/`CloudStorage`, Google Drive) are refused by name; other
  network or shared file systems are unsupported but not automatically detected,
  so keep the data root on a local disk.
- Cold-start input still requires conservative operator review. A source being
  parseable does not make it authoritative.
- Digest generation and profile learning are not shipped surfaces. Their inert
  configuration and CLI claims were removed.
- Optional graph adapters are portability conveniences. Local SQLite remains the
  authority.
- The public ontology stores Imprint judgment, business observation, confidence,
  calibration, consent, and outcome records. Private identity or direction
  models require a separately distributed namespaced extension and are not
  enumerated by this release.
- No software can guarantee that sensitive data is safe on a compromised host.

## Explicit non-claims

This release does not passively observe screens, reconstruct unspoken intent, or
capture decisions from Screenpipe. Screenpipe-assisted observation is roadmap
research only. Imprint does not fabricate a missing reason, infer authorship as
fact, or silently promote imported or inferred material.

## Roadmap

- Opt-in Screenpipe candidate capture with explicit consent, content boundaries,
  provenance receipts, and a complete privacy/retention threat model.
- Stable digest resolution and profile-learning lifecycles after longitudinal
  evidence and uninstall/recovery coverage exist.
- A documented extension interface for independently distributed semantic
  packages, with namespaced schemas, explicit authority policies, migrations,
  and fail-closed installation checks.
- A networked Neo4j connector layered over the shipped offline generic/Atlas
  projections, with provider-specific integration fixtures.
- Additional hook-provider adapters that preserve the same recorder/compiler
  separation.
