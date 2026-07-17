"""SQLite schema for immutable events and bitemporal entity versions."""

SCHEMA_SQL = r"""
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=FULL;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT OR IGNORE INTO meta(key,value) VALUES('content_generation','0');
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  operator_id TEXT NOT NULL,
  system_time TEXT NOT NULL,
  valid_time TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  prior_event_id TEXT,
  provenance_status TEXT NOT NULL
);
-- Normalized event subjects replace unindexed JSON substring scans for
-- disposition history and purge closure. The role is retained so callers can
-- distinguish a reviewed node from relation endpoints without reparsing JSON.
CREATE TABLE IF NOT EXISTS event_disposition_subjects (
  event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
  subject_role TEXT NOT NULL CHECK(subject_role IN ('node_id','source_id','target_id')),
  subject_id TEXT NOT NULL,
  PRIMARY KEY(event_id,subject_role,subject_id)
);
CREATE INDEX IF NOT EXISTS disposition_subjects_by_subject
  ON event_disposition_subjects(subject_id,event_id);
CREATE TRIGGER IF NOT EXISTS event_disposition_subjects_insert
AFTER INSERT ON events BEGIN
  INSERT OR IGNORE INTO event_disposition_subjects(event_id,subject_role,subject_id)
    SELECT NEW.event_id,'node_id',json_extract(NEW.payload_json,'$.node_id')
    WHERE json_type(NEW.payload_json,'$.node_id')='text';
  INSERT OR IGNORE INTO event_disposition_subjects(event_id,subject_role,subject_id)
    SELECT NEW.event_id,'source_id',json_extract(NEW.payload_json,'$.source_id')
    WHERE json_type(NEW.payload_json,'$.source_id')='text';
  INSERT OR IGNORE INTO event_disposition_subjects(event_id,subject_role,subject_id)
    SELECT NEW.event_id,'target_id',json_extract(NEW.payload_json,'$.target_id')
    WHERE json_type(NEW.payload_json,'$.target_id')='text';
END;
-- Deterministic upgrade backfill for stores created before the normalized
-- subject index. INSERT OR IGNORE makes every initialize idempotent.
INSERT OR IGNORE INTO event_disposition_subjects(event_id,subject_role,subject_id)
  SELECT event_id,'node_id',json_extract(payload_json,'$.node_id') FROM events
  WHERE json_type(payload_json,'$.node_id')='text';
INSERT OR IGNORE INTO event_disposition_subjects(event_id,subject_role,subject_id)
  SELECT event_id,'source_id',json_extract(payload_json,'$.source_id') FROM events
  WHERE json_type(payload_json,'$.source_id')='text';
INSERT OR IGNORE INTO event_disposition_subjects(event_id,subject_role,subject_id)
  SELECT event_id,'target_id',json_extract(payload_json,'$.target_id') FROM events
  WHERE json_type(payload_json,'$.target_id')='text';
CREATE TABLE IF NOT EXISTS nodes (
  node_id TEXT PRIMARY KEY,
  node_type TEXT NOT NULL,
  operator_id TEXT NOT NULL,
  created_event_id TEXT NOT NULL REFERENCES events(event_id)
);
CREATE TABLE IF NOT EXISTS node_versions (
  version_id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(node_id),
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  provenance_status TEXT NOT NULL,
  authority_tier TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  system_from TEXT NOT NULL,
  system_to TEXT,
  event_id TEXT NOT NULL REFERENCES events(event_id),
  prior_version_id TEXT
);
DROP INDEX IF EXISTS one_current_node_version;
CREATE INDEX IF NOT EXISTS current_node_versions
  ON node_versions(node_id, valid_from, valid_to) WHERE system_to IS NULL;
CREATE INDEX IF NOT EXISTS node_version_history
  ON node_versions(node_id, system_from);
CREATE TABLE IF NOT EXISTS edges (
  edge_id TEXT PRIMARY KEY,
  edge_type TEXT NOT NULL,
  source_id TEXT NOT NULL REFERENCES nodes(node_id),
  target_id TEXT NOT NULL REFERENCES nodes(node_id),
  operator_id TEXT NOT NULL,
  created_event_id TEXT NOT NULL REFERENCES events(event_id)
);
CREATE TABLE IF NOT EXISTS edge_versions (
  version_id TEXT PRIMARY KEY,
  edge_id TEXT NOT NULL REFERENCES edges(edge_id),
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  provenance_status TEXT NOT NULL,
  authority_tier TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  system_from TEXT NOT NULL,
  system_to TEXT,
  event_id TEXT NOT NULL REFERENCES events(event_id),
  prior_version_id TEXT
);
CREATE INDEX IF NOT EXISTS edges_by_source ON edges(source_id);
CREATE INDEX IF NOT EXISTS edges_by_target ON edges(target_id);
CREATE UNIQUE INDEX IF NOT EXISTS one_current_edge_version
  ON edge_versions(edge_id) WHERE system_to IS NULL;

-- Defense in depth for every raw writer.  Python validators remain more
-- specific, but no module can mint a provenance/authority combination outside
-- the canonical lattice by issuing SQL directly.
CREATE TRIGGER IF NOT EXISTS node_version_authority_lattice_insert
BEFORE INSERT ON node_versions
WHEN NOT (
  (NEW.provenance_status='captured' AND NEW.authority_tier IN ('observed_candidate','captured_judgment','ratified_knowledge')) OR
  (NEW.provenance_status='extracted' AND NEW.authority_tier IN ('imported_floor','observed_candidate','ratified_knowledge')) OR
  (NEW.provenance_status='inferred' AND NEW.authority_tier IN ('inferred_candidate','observed_candidate','ratified_knowledge')) OR
  (NEW.provenance_status='ratified' AND NEW.authority_tier='ratified_knowledge')
) OR (NEW.authority_tier='ratified_knowledge'
      AND json_extract(NEW.provenance_json,'$.ratifier') IS NULL
      AND json_extract(NEW.provenance_json,'$.ratification_event_version_id') IS NULL)
BEGIN SELECT RAISE(ABORT, 'node version violates authority lattice'); END;
CREATE TRIGGER IF NOT EXISTS node_version_authority_lattice_update
BEFORE UPDATE OF provenance_status,authority_tier ON node_versions
WHEN NOT (
  (NEW.provenance_status='captured' AND NEW.authority_tier IN ('observed_candidate','captured_judgment','ratified_knowledge')) OR
  (NEW.provenance_status='extracted' AND NEW.authority_tier IN ('imported_floor','observed_candidate','ratified_knowledge')) OR
  (NEW.provenance_status='inferred' AND NEW.authority_tier IN ('inferred_candidate','observed_candidate','ratified_knowledge')) OR
  (NEW.provenance_status='ratified' AND NEW.authority_tier='ratified_knowledge')
) OR (NEW.authority_tier='ratified_knowledge'
      AND json_extract(NEW.provenance_json,'$.ratifier') IS NULL
      AND json_extract(NEW.provenance_json,'$.ratification_event_version_id') IS NULL)
BEGIN SELECT RAISE(ABORT, 'node version violates authority lattice'); END;
CREATE TRIGGER IF NOT EXISTS edge_version_authority_lattice_insert
BEFORE INSERT ON edge_versions
WHEN NOT (
  (NEW.provenance_status='captured' AND NEW.authority_tier IN ('observed_candidate','captured_judgment','ratified_knowledge')) OR
  (NEW.provenance_status='extracted' AND NEW.authority_tier IN ('imported_floor','observed_candidate','ratified_knowledge')) OR
  (NEW.provenance_status='inferred' AND NEW.authority_tier IN ('inferred_candidate','observed_candidate','ratified_knowledge')) OR
  (NEW.provenance_status='ratified' AND NEW.authority_tier='ratified_knowledge')
) OR (NEW.authority_tier='ratified_knowledge'
      AND json_extract(NEW.provenance_json,'$.ratifier') IS NULL
      AND json_extract(NEW.provenance_json,'$.ratification_event_version_id') IS NULL)
BEGIN SELECT RAISE(ABORT, 'edge version violates authority lattice'); END;
CREATE TRIGGER IF NOT EXISTS edge_version_authority_lattice_update
BEFORE UPDATE OF provenance_status,authority_tier ON edge_versions
WHEN NOT (
  (NEW.provenance_status='captured' AND NEW.authority_tier IN ('observed_candidate','captured_judgment','ratified_knowledge')) OR
  (NEW.provenance_status='extracted' AND NEW.authority_tier IN ('imported_floor','observed_candidate','ratified_knowledge')) OR
  (NEW.provenance_status='inferred' AND NEW.authority_tier IN ('inferred_candidate','observed_candidate','ratified_knowledge')) OR
  (NEW.provenance_status='ratified' AND NEW.authority_tier='ratified_knowledge')
) OR (NEW.authority_tier='ratified_knowledge'
      AND json_extract(NEW.provenance_json,'$.ratifier') IS NULL
      AND json_extract(NEW.provenance_json,'$.ratification_event_version_id') IS NULL)
BEGIN SELECT RAISE(ABORT, 'edge version violates authority lattice'); END;

-- Retrieval identity is transactionally coupled to canonical graph changes.
-- The counter is deliberately row-granular rather than wall-clock based: it
-- need only be monotonic and change whenever a retrieval-visible row changes.
CREATE TRIGGER IF NOT EXISTS content_generation_nodes_insert
AFTER INSERT ON nodes BEGIN
  UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)
   WHERE key='content_generation';
END;
CREATE TRIGGER IF NOT EXISTS content_generation_nodes_update
AFTER UPDATE ON nodes BEGIN
  UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)
   WHERE key='content_generation';
END;
CREATE TRIGGER IF NOT EXISTS content_generation_nodes_delete
AFTER DELETE ON nodes BEGIN
  UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)
   WHERE key='content_generation';
END;
CREATE TRIGGER IF NOT EXISTS content_generation_node_versions_insert
AFTER INSERT ON node_versions BEGIN
  UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)
   WHERE key='content_generation';
END;
CREATE TRIGGER IF NOT EXISTS content_generation_node_versions_update
AFTER UPDATE ON node_versions BEGIN
  UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)
   WHERE key='content_generation';
END;
CREATE TRIGGER IF NOT EXISTS content_generation_node_versions_delete
AFTER DELETE ON node_versions BEGIN
  UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)
   WHERE key='content_generation';
END;
CREATE TRIGGER IF NOT EXISTS content_generation_edges_insert
AFTER INSERT ON edges BEGIN
  UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)
   WHERE key='content_generation';
END;
CREATE TRIGGER IF NOT EXISTS content_generation_edges_update
AFTER UPDATE ON edges BEGIN
  UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)
   WHERE key='content_generation';
END;
CREATE TRIGGER IF NOT EXISTS content_generation_edges_delete
AFTER DELETE ON edges BEGIN
  UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)
   WHERE key='content_generation';
END;
CREATE TRIGGER IF NOT EXISTS content_generation_edge_versions_insert
AFTER INSERT ON edge_versions BEGIN
  UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)
   WHERE key='content_generation';
END;
CREATE TRIGGER IF NOT EXISTS content_generation_edge_versions_update
AFTER UPDATE ON edge_versions BEGIN
  UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)
   WHERE key='content_generation';
END;
CREATE TRIGGER IF NOT EXISTS content_generation_edge_versions_delete
AFTER DELETE ON edge_versions BEGIN
  UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)
   WHERE key='content_generation';
END;
CREATE TABLE IF NOT EXISTS source_receipts (
  source_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  locator TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  event_id TEXT NOT NULL REFERENCES events(event_id)
);
CREATE TABLE IF NOT EXISTS captured_feedback_dedup (
  operator_id TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  first_event_id TEXT NOT NULL REFERENCES events(event_id),
  first_captured_at TEXT NOT NULL,
  PRIMARY KEY(operator_id, content_sha256)
);
CREATE TABLE IF NOT EXISTS ingest_rulings (
  ruling_id TEXT PRIMARY KEY,
  item_id TEXT NOT NULL,
  verdict TEXT NOT NULL,
  why TEXT,
  event_id TEXT NOT NULL REFERENCES events(event_id)
);
CREATE TABLE IF NOT EXISTS ingest_items (
  item_id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  session_id TEXT,
  node_id TEXT,
  source_id TEXT NOT NULL UNIQUE,
  source_kind TEXT NOT NULL,
  source_locator TEXT NOT NULL,
  source_sha256 TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  discovered_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('unruled','kept','killed')),
  kept_node_id TEXT,
  UNIQUE(source_kind, source_locator, source_sha256)
);
CREATE TABLE IF NOT EXISTS migrations (
  migration_id TEXT PRIMARY KEY,
  from_version TEXT NOT NULL,
  to_version TEXT NOT NULL,
  code_sha256 TEXT NOT NULL,
  applied_at TEXT NOT NULL,
  backup_receipt TEXT NOT NULL,
  result_sha256 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS consumed_inputs (
  input_event_id TEXT PRIMARY KEY,
  payload_sha256 TEXT NOT NULL,
  consumed_at TEXT NOT NULL,
  source_path TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projection_state (
  projection TEXT PRIMARY KEY,
  snapshot_sha256 TEXT NOT NULL,
  generator_version TEXT NOT NULL,
  generated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS purge_receipts (
  operation_id TEXT PRIMARY KEY,
  purged_at TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  scope_class TEXT NOT NULL,
  counts_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS content_locations (
  location_id TEXT PRIMARY KEY,
  surface_id TEXT NOT NULL,
  absolute_path TEXT NOT NULL UNIQUE,
  operator_id TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  active INTEGER NOT NULL CHECK(active IN (0,1))
);
CREATE TABLE IF NOT EXISTS purge_operations (
  operation_id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  scope_class TEXT NOT NULL,
  planned_ids_json TEXT NOT NULL,
  planned_hashes_json TEXT NOT NULL,
  planned_locations_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('incomplete','complete')),
  started_at TEXT NOT NULL,
  completed_at TEXT,
  remaining_locations_json TEXT NOT NULL,
  counts_json TEXT NOT NULL
);

-- v3.1 semantic metadata remains additive to the generic ledger.  The generic
-- node/version rows are still canonical; this table binds the exact 3.6.1
-- envelope and governance fields to each immutable generic version.
CREATE TABLE IF NOT EXISTS semantic_node_versions (
  version_id TEXT PRIMARY KEY REFERENCES node_versions(version_id),
  record_id TEXT NOT NULL,
  payload_schema_id TEXT NOT NULL,
  record_schema_version TEXT NOT NULL,
  ontology_schema_version TEXT NOT NULL,
  provenance_v2_1_json TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  access_policy_version_id TEXT NOT NULL,
  consent_version_id TEXT,
  actor_id TEXT NOT NULL,
  role_assignment_version_id TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  contested_set_id TEXT,
  envelope_json TEXT NOT NULL,
  envelope_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS semantic_as_of
  ON semantic_node_versions(record_id, scope_id, version_id);
CREATE TABLE IF NOT EXISTS semantic_artifact_bytes (
  version_id TEXT PRIMARY KEY REFERENCES semantic_node_versions(version_id),
  content BLOB NOT NULL,
  content_sha256 TEXT NOT NULL,
  byte_count INTEGER NOT NULL CHECK(byte_count >= 0)
);
CREATE TABLE IF NOT EXISTS semantic_relation_versions (
  relation_version_id TEXT PRIMARY KEY,
  relation_id TEXT NOT NULL,
  predicate_id TEXT NOT NULL,
  predicate_version INTEGER NOT NULL,
  source_version_id TEXT NOT NULL,
  target_version_id TEXT NOT NULL,
  operator_id TEXT NOT NULL,
  qualifier_schema_id TEXT NOT NULL,
  qualifier_json TEXT NOT NULL,
  envelope_json TEXT NOT NULL,
  envelope_sha256 TEXT NOT NULL,
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  system_from TEXT NOT NULL,
  system_to TEXT,
  contested_set_id TEXT
);
CREATE INDEX IF NOT EXISTS semantic_relation_as_of
  ON semantic_relation_versions(relation_id, valid_from, valid_to, system_from, system_to);
CREATE TABLE IF NOT EXISTS semantic_business_node_versions (
  version_id TEXT PRIMARY KEY REFERENCES semantic_node_versions(version_id),
  partition_id TEXT NOT NULL CHECK(partition_id IN ('business_declared','business_observed'))
);
CREATE INDEX IF NOT EXISTS semantic_business_node_partition
  ON semantic_business_node_versions(partition_id, version_id);
CREATE TABLE IF NOT EXISTS semantic_business_relation_versions (
  relation_version_id TEXT PRIMARY KEY REFERENCES semantic_relation_versions(relation_version_id),
  policy_code TEXT NOT NULL CHECK(policy_code IN ('O','B','C')),
  authority_minimum TEXT NOT NULL CHECK(authority_minimum IN ('I','J','R'))
);
CREATE INDEX IF NOT EXISTS semantic_business_relation_policy
  ON semantic_business_relation_versions(policy_code, authority_minimum, relation_version_id);
CREATE TABLE IF NOT EXISTS semantic_correction_events (
  correction_event_id TEXT PRIMARY KEY,
  record_id TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  prior_version_id TEXT NOT NULL,
  carry_forward_version_id TEXT NOT NULL,
  corrected_version_id TEXT NOT NULL,
  effective_from TEXT NOT NULL,
  evidence_version_ids_json TEXT NOT NULL,
  diff_json TEXT NOT NULL,
  event_id TEXT NOT NULL REFERENCES events(event_id)
);
CREATE TABLE IF NOT EXISTS semantic_contest_events (
  contest_event_id TEXT PRIMARY KEY,
  contested_set_id TEXT NOT NULL,
  record_id TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  prior_version_id TEXT NOT NULL,
  preserved_version_id TEXT NOT NULL,
  competing_version_id TEXT NOT NULL,
  evidence_version_ids_json TEXT NOT NULL,
  event_id TEXT NOT NULL REFERENCES events(event_id)
);
CREATE TABLE IF NOT EXISTS semantic_confidence_heads (
  subject_version_id TEXT NOT NULL,
  assessor_actor_version_id TEXT NOT NULL,
  method TEXT NOT NULL,
  scale TEXT NOT NULL,
  assessment_version_id TEXT NOT NULL UNIQUE REFERENCES semantic_node_versions(version_id),
  PRIMARY KEY(subject_version_id, assessor_actor_version_id, method, scale)
);
CREATE TRIGGER IF NOT EXISTS semantic_node_versions_no_update
BEFORE UPDATE ON semantic_node_versions BEGIN
  SELECT RAISE(ABORT, 'semantic envelope is immutable');
END;
CREATE TRIGGER IF NOT EXISTS semantic_artifact_bytes_no_update
BEFORE UPDATE ON semantic_artifact_bytes BEGIN
  SELECT RAISE(ABORT, 'artifact bytes are immutable');
END;
CREATE TRIGGER IF NOT EXISTS semantic_relation_versions_no_update
BEFORE UPDATE ON semantic_relation_versions BEGIN
  SELECT RAISE(ABORT, 'semantic relation is immutable');
END;
CREATE TRIGGER IF NOT EXISTS semantic_business_node_versions_no_update
BEFORE UPDATE ON semantic_business_node_versions BEGIN
  SELECT RAISE(ABORT, 'semantic business partition is immutable');
END;
CREATE TRIGGER IF NOT EXISTS semantic_business_relation_versions_no_update
BEFORE UPDATE ON semantic_business_relation_versions BEGIN
  SELECT RAISE(ABORT, 'semantic business relation governance is immutable');
END;

-- Authority is additive to the generic ledger.  Signed facts are append-only;
-- mutable key state is reconstructed from authority_ledger rather than by
-- rewriting historical provenance.
CREATE TABLE IF NOT EXISTS authority_keys (
  key_id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  install_id TEXT NOT NULL,
  store_identity TEXT NOT NULL,
  public_key_b64 TEXT NOT NULL,
  public_key_fingerprint TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK(status IN ('active','retired','revoked','compromised')),
  ledger_sequence INTEGER NOT NULL,
  blob_rel_path TEXT NOT NULL UNIQUE,
  blob_sha256 TEXT NOT NULL,
  blob_size INTEGER NOT NULL CHECK(blob_size > 0),
  algorithm_suite TEXT NOT NULL,
  enrollment_nonce TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_authority_key_per_install
  ON authority_keys(operator_id, install_id) WHERE status='active';
CREATE TABLE IF NOT EXISTS authority_ledger (
  sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
  event_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  operator_id TEXT NOT NULL,
  install_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  event_json TEXT NOT NULL,
  event_sha256 TEXT NOT NULL,
  signature_b64 TEXT NOT NULL,
  previous_event_sha256 TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authority_trust_anchor (
  anchor_id INTEGER PRIMARY KEY CHECK(anchor_id = 1),
  operator_id TEXT NOT NULL,
  store_identity TEXT NOT NULL,
  genesis_event_sha256 TEXT NOT NULL,
  recovery_key_id TEXT,
  recovery_public_key_b64 TEXT,
  pinned_sequence INTEGER NOT NULL CHECK(pinned_sequence > 0),
  pinned_head_sha256 TEXT NOT NULL,
  key_state_sha256 TEXT NOT NULL,
  checkpoint_sha256 TEXT,
  checkpoint_json TEXT,
  signer_certificate_sha256 TEXT,
  updated_at TEXT NOT NULL,
  writes_blocked INTEGER NOT NULL DEFAULT 0 CHECK(writes_blocked IN (0,1)),
  block_reason TEXT,
  CHECK((writes_blocked = 0 AND block_reason IS NULL) OR
        (writes_blocked = 1 AND block_reason IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS authority_checkpoint_pins (
  checkpoint_sha256 TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  store_identity TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence > 0),
  event_sha256 TEXT NOT NULL,
  key_state_sha256 TEXT NOT NULL,
  prior_checkpoint_sha256 TEXT,
  signer_certificate_sha256 TEXT NOT NULL,
  checkpoint_json TEXT NOT NULL,
  accepted_at TEXT NOT NULL,
  operation_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authority_transfer_intents (
  ticket_id TEXT PRIMARY KEY,
  checkpoint_sha256 TEXT NOT NULL,
  checkpoint_json TEXT NOT NULL,
  operation_digest TEXT NOT NULL,
  prior_anchor_sha256 TEXT NOT NULL,
  source_store_identity TEXT NOT NULL,
  destination_store_identity TEXT NOT NULL,
  prior_sequence INTEGER NOT NULL CHECK(prior_sequence > 0),
  prior_head_sha256 TEXT NOT NULL,
  candidate_sequence INTEGER NOT NULL CHECK(candidate_sequence > 0),
  candidate_head_sha256 TEXT NOT NULL,
  prepared_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('prepared','finalized','cancelled')),
  finalized_at TEXT
);
CREATE TABLE IF NOT EXISTS authority_pairing_requests (
  request_id TEXT PRIMARY KEY,
  request_json TEXT NOT NULL,
  request_sha256 TEXT NOT NULL UNIQUE,
  key_id TEXT NOT NULL UNIQUE,
  install_id TEXT NOT NULL UNIQUE,
  blob_rel_path TEXT NOT NULL UNIQUE,
  blob_sha256 TEXT NOT NULL,
  blob_size INTEGER NOT NULL CHECK(blob_size > 0),
  enrollment_nonce TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','finalized','cancelled')),
  finalized_at TEXT
);
CREATE TABLE IF NOT EXISTS authority_equivocation_proofs (
  proof_id TEXT PRIMARY KEY,
  conflict_class TEXT NOT NULL,
  local_proof_json TEXT NOT NULL,
  candidate_proof_json TEXT NOT NULL,
  local_proof_sha256 TEXT NOT NULL,
  candidate_proof_sha256 TEXT NOT NULL,
  detected_at TEXT NOT NULL,
  adjudication_event_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS authority_challenges (
  nonce_sha256 TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL,
  challenge_sha256 TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  consumed_provenance_id TEXT
);
CREATE TABLE IF NOT EXISTS authority_prepared_mutations (
  operation_id TEXT PRIMARY KEY,
  command_name TEXT NOT NULL,
  operator_id TEXT NOT NULL,
  request_json TEXT NOT NULL,
  request_sha256 TEXT NOT NULL,
  intent_json TEXT NOT NULL,
  intent_sha256 TEXT NOT NULL,
  prior_state_json TEXT NOT NULL,
  prior_state_sha256 TEXT NOT NULL,
  execution_fields_json TEXT NOT NULL,
  execution_fields_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','executed','expired','cancelled')),
  executed_at TEXT,
  provenance_id TEXT
);
CREATE TRIGGER IF NOT EXISTS authority_prepared_content_immutable
BEFORE UPDATE ON authority_prepared_mutations
WHEN OLD.operation_id != NEW.operation_id
  OR OLD.command_name != NEW.command_name
  OR OLD.operator_id != NEW.operator_id
  OR OLD.request_json != NEW.request_json
  OR OLD.request_sha256 != NEW.request_sha256
  OR OLD.intent_json != NEW.intent_json
  OR OLD.intent_sha256 != NEW.intent_sha256
  OR OLD.prior_state_json != NEW.prior_state_json
  OR OLD.prior_state_sha256 != NEW.prior_state_sha256
  OR OLD.execution_fields_json != NEW.execution_fields_json
  OR OLD.execution_fields_sha256 != NEW.execution_fields_sha256
  OR OLD.created_at != NEW.created_at
  OR OLD.expires_at != NEW.expires_at
BEGIN
  SELECT RAISE(ABORT, 'prepared mutation content is immutable');
END;
CREATE TABLE IF NOT EXISTS authority_provenance (
  provenance_id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL UNIQUE,
  operator_id TEXT NOT NULL,
  install_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  ledger_sequence INTEGER NOT NULL,
  challenge_json TEXT NOT NULL,
  challenge_sha256 TEXT NOT NULL,
  signature_b64 TEXT NOT NULL,
  authority_transition TEXT NOT NULL,
  committed_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS authority_ledger_no_update
BEFORE UPDATE ON authority_ledger BEGIN
  SELECT RAISE(ABORT, 'authority ledger is immutable');
END;
CREATE TRIGGER IF NOT EXISTS authority_ledger_no_delete
BEFORE DELETE ON authority_ledger BEGIN
  SELECT RAISE(ABORT, 'authority ledger is immutable');
END;
CREATE TRIGGER IF NOT EXISTS authority_checkpoint_pins_no_update
BEFORE UPDATE ON authority_checkpoint_pins BEGIN
  SELECT RAISE(ABORT, 'authority checkpoint pins are immutable');
END;
CREATE TRIGGER IF NOT EXISTS authority_checkpoint_pins_no_delete
BEFORE DELETE ON authority_checkpoint_pins BEGIN
  SELECT RAISE(ABORT, 'authority checkpoint pins are immutable');
END;
CREATE TRIGGER IF NOT EXISTS authority_equivocation_proofs_no_update
BEFORE UPDATE ON authority_equivocation_proofs
WHEN OLD.proof_id != NEW.proof_id
  OR OLD.conflict_class != NEW.conflict_class
  OR OLD.local_proof_json != NEW.local_proof_json
  OR OLD.candidate_proof_json != NEW.candidate_proof_json
  OR OLD.local_proof_sha256 != NEW.local_proof_sha256
  OR OLD.candidate_proof_sha256 != NEW.candidate_proof_sha256
  OR OLD.detected_at != NEW.detected_at
BEGIN
  SELECT RAISE(ABORT, 'authority equivocation evidence is immutable');
END;
CREATE TRIGGER IF NOT EXISTS authority_equivocation_proofs_no_delete
BEFORE DELETE ON authority_equivocation_proofs BEGIN
  SELECT RAISE(ABORT, 'authority equivocation evidence is immutable');
END;
CREATE TRIGGER IF NOT EXISTS authority_provenance_no_update
BEFORE UPDATE ON authority_provenance BEGIN
  SELECT RAISE(ABORT, 'authority provenance is immutable');
END;
CREATE TRIGGER IF NOT EXISTS authority_provenance_no_delete
BEFORE DELETE ON authority_provenance BEGIN
  SELECT RAISE(ABORT, 'authority provenance is immutable');
END;
"""
