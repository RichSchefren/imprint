# Architecture and Provenance

Imprint separates witnessing from interpretation:

1. **Recorder:** writes an immutable capture envelope containing raw Case,
   Verdict, Call, nullable Reason, alternatives, evidence hashes, and actor data.
2. **Compiler:** the sole canonical writer validates and appends the envelope to
   SQLite in WAL mode.
3. **Derivation:** proposes Principles, Rules, Patterns, Beliefs, Values, and
   Domains through an immutable proposal spool without rewriting source evidence.
4. **Ratification:** explicit operator action may promote eligible extracted or
   inferred typed material. A generic `Proposal` is never ratified in place;
   one exact signed action instead creates a typed, evidence-linked successor,
   a `proposal_succeeded_by` relation, and a disposition event atomically while
   leaving the Proposal unchanged.
5. **Retrieval:** selects only eligible current records under a deterministic
   byte budget and emits provenance with every item.

Nodes and edges carry one of `captured`, `extracted`, `inferred`, or `ratified`.
The store preserves valid time and system time, plus supersession,
contradiction, reversal, and tombstone history. Stable typed URNs and schema
versions make migrations additive and replay idempotent.

Canonical Domains are stable, operator-scoped nodes with evidence-backed add,
select, and freeze transitions. A `contradicts` edge keeps both current heads. A
`supersedes` edge runs from the replacement to the prior head; only the prior
head is closed for current retrieval, while its versions and the transition
remain inspectable.

After canonical commit, the compiler writes a content-free acknowledgement with
the input event ID and exact hashes. `spool prune` may delete only the configured
producer node's inputs after that acknowledgement has aged past the configured
retention period and every hash and path check succeeds.

External documents enter quarantine. `KEEP` requires a WHY and creates an
`imported_floor` record with a source receipt; it cannot become captured operator
judgment. `KILL` remains an auditable ruling. A finished, approved, published, or
frozen deliverable is refused as cold-start evidence.

SQLite is canonical. Markdown is a human-readable projection. JSON-LD is the
lossless portable graph projection. Optional Atlas or Neo4j integrations are
adapters, never required canonical stores.

## Semantic ontology contract

The store schema and semantic ontology are versioned independently. The generic
versioned graph remains stable while the `3.1.0` public semantic contract closes
two core evidence channels and one extension boundary:

1. **Imprint judgment:** witnessed Cases, Verdicts, Calls, alternatives, then
   evidence-linked Principles, Beliefs, Values, Rules, Patterns, Outcomes, and
   CalibrationTrials.
2. **Business/world model:** declared market and operating relationships remain
   separate from observed purchases, usage, support, results, refunds,
   retention, and referrals. Each relation states its evidence mode.
3. **Optional semantic extensions:** the public core does not enumerate private
   models of identity, personal direction, or their graph topology. A separately
   distributed extension must use a namespaced schema, declare its own authority
   and migration rules, and install explicit validators before those records can
   enter the canonical graph. Unknown extension records fail closed.

New ontology classes can be written only through the strict semantic node and
relation writer. The older derived-node path remains available solely so v3 and
legacy imports stay readable; it cannot write extension, Observation, Outcome,
calibration, or consent classes. This separation preserves backward
compatibility without allowing old untyped payloads into new data.

Both nodes and edges preserve evidence, provenance, authority, valid/system
time, and typed endpoint signatures. The JSON-LD graph includes payload and
evidence directly in addition to the lossless ledger, so another implementation
does not need Imprint-specific reconstruction merely to understand the graph.

## Dynamic Selection and Token Budgets

To prevent **context dilution** and the failure modes associated with static prompt stuffing,
Imprint integrates an optional dynamic relevance selector powered by JEV (`typesafe/jev-1.13`
via `jev_selector.py`):

1. **Eligibility Pre-filtering:** Local retrieval filters the store for candidate records matching
   current domain, authority status, provenance completeness, and ontology partition criteria.
2. **Sub-Second Relevance Scoring:** Candidates and current turn text are dispatched to the JEV endpoint,
   which scores semantic relevance against the operator's active task.
3. **Budget Enforcement:** Selections are packed greedily into surface-specific token budgets defined
   in `IMPRINT-BUDGETS.json` (e.g., 10,800 tokens for session start, 8,100 tokens for per-prompt turns,
   13,500–16,200 tokens for lane lead turns; worker and codex execution contexts receive 0 tokens).
4. **Fail-Open Resilience:** Timeouts (>4.5s), network drops, or missing credentials automatically
   fall back to local deterministic retrieval without interrupting host execution.

## Token Minimization Ecosystem

Imprint operates alongside two complementary token-minimization components:

- **Aider-Style Structural Mapping (`repomap.py`):** Uses AST extraction and PageRank to generate
  compact structural skeletons of code repositories (capped at 1,024 tokens) and Obsidian knowledge
  vaults (capped at 1,200 tokens), providing high-level orientation without consuming model attention.
- **Hermes-Style Structured Reasoning Scratchpads (`scratchpad.py`):** Enforces disciplined "Think
  Before Tool" chain-of-thought inside `<scratchpad>...</scratchpad>` blocks for Codex and Claude Sonnet,
  ensuring agents verify ground truth and assert invariants before executing mutations.

## Separation of Logger and Doer (`CONTRACTS.md`)

Production operation strictly separates the observation and capture lifecycle from canonical mutation:

- **The Logger (Capture Spool):** Operates without model invocation or database write locks. The
  Stop hook records raw Case, Verdict, Call, Reason, and alternatives to an immutable, per-node spool.
- **The Doer (Single-Writer SQLite Compiler):** Only the designated compiler node validates envelopes
  and mutates the canonical SQLite database in WAL mode.
- **Explicit Ratification:** Extracted or inferred patterns remain inert proposals until explicit
  human operator action ratifies them into typed, authoritative nodes with complete provenance.

