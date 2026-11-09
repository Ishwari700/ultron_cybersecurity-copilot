"""Automated Byte-for-Byte Parity Regression Tests: Oracle vs. Production P4 Serializer.

Enforces M3.10 Invariant (Criterion 43 & Section 13.6):
CanonicalP4CapacityOracle(pack) == ProductionP4Serializer(pack) byte-for-byte.
"""

import json
from pathlib import Path
import pytest

from src.eval.p4_capacity_oracle import CanonicalP4CapacityOracle
from src.knowledge.models import QueryRendererId
from src.knowledge.retriever import OnnxVectorFts5Retriever
from src.knowledge.serializer import ProductionP4Serializer


def test_oracle_serializer_exact_byte_parity_on_gold():
    """
    Verify 100% byte-for-byte identity between CanonicalP4CapacityOracle
    and ProductionP4Serializer across all gold evaluation queries.
    """
    gold_file = Path("data/eval/retrieval_gold.json")
    db_file = Path("data/vapt_corpus/vapt_knowledge.db")
    assert gold_file.exists()
    assert db_file.exists()

    with open(gold_file, "r", encoding="utf-8") as f:
        records = json.load(f)

    oracle = CanonicalP4CapacityOracle(chars_per_token=4.0)
    serializer = ProductionP4Serializer(chars_per_token=4.0)
    retriever = OnnxVectorFts5Retriever(db_file)

    for rec in records:
        query = rec["expected_rendered_query"]["RENDERER_S"]
        retrieved_items = retriever.retrieve(query, top_k=5, query_id=rec["query_id"])

        for budget in [256, 768]:
            # Run Oracle
            oracle_wire, oracle_tokens, oracle_accepted = oracle.serialize_pack(
                retrieval_items=retrieved_items,
                token_budget=budget,
            )

            # Run Production Serializer
            prod_wire, prod_tokens, prod_accepted = serializer.serialize_pack(
                retrieval_items=retrieved_items,
                token_budget=budget,
            )

            # 1. Byte-for-byte string identity
            assert oracle_wire == prod_wire, f"Byte divergence on {rec['query_id']} at budget {budget}"
            # 2. Token count identity
            assert oracle_tokens == prod_tokens
            # 3. Accepted items identity
            assert [item.chunk.chunk_id for item in oracle_accepted] == [item.chunk.chunk_id for item in prod_accepted]

    retriever.close()


def test_oracle_serializer_empty_pack_parity():
    """Verify empty-pack behavior matches byte-for-byte: strictly empty string ""."""
    oracle = CanonicalP4CapacityOracle()
    serializer = ProductionP4Serializer()

    o_wire, o_tok, o_acc = oracle.serialize_pack([], token_budget=256)
    p_wire, p_tok, p_acc = serializer.serialize_pack([], token_budget=256)

    assert o_wire == p_wire == ""
    assert o_tok == p_tok == 0
    assert o_acc == p_acc == []


def test_knowledge_pack_provenance_and_schema():
    """Verify VaptKnowledgePack creation and provenance metadata."""
    db_file = Path("data/vapt_corpus/vapt_knowledge.db")
    retriever = OnnxVectorFts5Retriever(db_file)
    serializer = ProductionP4Serializer(chars_per_token=4.0)

    query = "Method: GET | Route: /api/v1/accounts/{account_id}/profile | Evidence Gap: Missing Cross Identity Object Verification"
    items = retriever.retrieve(query, top_k=5)

    pack = serializer.build_knowledge_pack(
        retrieval_items=items,
        token_budget=256,
        retrieval_query=query,
        query_renderer_id="RENDERER_S",
    )

    assert pack.schema_version == "3.0.0"
    assert pack.pack_id.startswith("PACK-")
    assert pack.provenance_hash is not None
    assert len(pack.provenance_hash) == 64
    assert pack.total_tokens <= 256
    assert len(pack.items) > 0

    retriever.close()
