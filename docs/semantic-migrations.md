# Ontology Compatibility and Legacy Records

The SQLite store schema and the ontology schema are versioned independently.
`imprint migrate verify` checks both. `imprint migrate ontology-report` produces
the semantic compatibility path and inventories records that predate the typed
ontology.

The built-in catalog currently defines the additive semantic boundary from
ontology `3.0.0` to `3.1.0`. It does not change storage tables or reinterpret
stored content.

## Legacy policy

Opaque `FeedbackProfile` payloads and business records created outside the
typed semantic writer are reported as `legacy_untyped`. Their original records
remain intact and retain their existing provenance and authority.

Imprint never converts profile prose, personality summaries, or legacy business
prose into `SelfModelAssertion`, `Observation`, or any other typed knowledge.
Those records can only be created separately through evidence-backed typed
creation and operator review. The report's `required_action` states this
boundary for every legacy record.

```bash
imprint migrate ontology-report
```

Exit status is zero when the ontology is current or a known migration path is
available. Missing or unsupported ontology versions return exit status 2.
