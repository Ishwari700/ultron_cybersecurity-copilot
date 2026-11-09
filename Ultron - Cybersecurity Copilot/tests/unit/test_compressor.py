"""Unit tests for the SemanticCompressor."""

import json
from src.evidence.compressor import SemanticCompressor


def test_compress_large_json_list():
    """Verify large lists are sampled rather than exploded."""
    compressor = SemanticCompressor(max_summary_chars=1000)

    items = [
        {"id": f"item_{i}", "uuid": "d290f1ee-6c54-4b01-90e6-d701748f0851", "details": "repeated string content"}
        for i in range(500)
    ]
    raw_json = json.dumps({"data": items, "total": 500})

    compressed = compressor.compress(raw_json, content_type="application/json")
    parsed = json.loads(compressed)

    assert parsed["total"] == 500
    assert parsed["data"]["_list_count"] == 500
    sample = parsed["data"]["_sample_item"]
    assert sample["id"] == "item_0"
    assert sample["uuid"] == "<UUID: d290f1ee-6c54-4b01-90e6-d701748f0851>"


def test_compress_plain_text_truncation():
    """Verify long non-JSON text is truncated cleanly with notice."""
    compressor = SemanticCompressor(max_summary_chars=100)
    long_text = "A" * 500

    compressed = compressor.compress(long_text)
    assert len(compressed) < 200
    assert "TRUNCATED" in compressed
