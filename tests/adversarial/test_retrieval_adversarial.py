import json

import pytest

from imprint.retrieve import (
    RetrievalConfig,
    RetrievalEngine,
    RetrievalRecord,
)


class Source:
    def retrieval_candidates(self, snapshot_id):
        return tuple(
            RetrievalRecord(
                record_id=f"r-{index:04}",
                text=("💥" * 250) + str(index),
                section=("core", "general", "domain")[index % 3],
                domain_id="safe-domain" if index % 3 == 2 else None,
                provenance_status="captured",
                authority_tier="captured_judgment",
                evidence_ids=(f"e-{index}",),
                case_ids=(f"case-{index}",),
                provenance_complete=True,
                pinned=index % 5 == 0,
            )
            for index in range(300)
        )


def test_multibyte_payload_is_byte_bounded_and_json_complete():
    result = RetrievalEngine(Source(), RetrievalConfig(total_budget_bytes=7777)).retrieve(
        snapshot_id="stable", selected_domain="safe-domain"
    )
    assert len(result.payload) <= 7777
    for line in result.payload.splitlines():
        json.loads(line.decode("utf-8"))


def test_private_extension_partition_cannot_cross_the_public_boundary():
    engine = RetrievalEngine(Source(), RetrievalConfig(authority_mode="analytical"))
    with pytest.raises(ValueError, match="unsupported ontology partitions"):
        engine.retrieve(
            snapshot_id="stable",
            ontology_partitions=("private:extension",),
        )
