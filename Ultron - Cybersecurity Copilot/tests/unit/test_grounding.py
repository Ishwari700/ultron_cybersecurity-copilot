"""Unit tests for Grounding Validator: ID validation, relationship checks, and claim checks."""

from pathlib import Path
from src.database.manager import DatabaseManager
from src.engine.models import HypothesisDecision, HypothesisModelOutput
from src.validation.grounding import GroundingValidator, ValidationStatus


def setup_test_database(db: DatabaseManager):
    """Seed test database with known assets, parameters, identities, and facts."""
    db.insert_asset({
        "asset_id": "ASSET-REAL-1",
        "method": "GET",
        "host": "api.target.com",
        "raw_path": "/users/10",
        "normalized_path": "/users/{id}",
    })
    db.insert_asset({
        "asset_id": "ASSET-REAL-2",
        "method": "POST",
        "host": "api.target.com",
        "raw_path": "/orders",
        "normalized_path": "/orders",
    })

    db.insert_parameter({
        "param_id": "PARAM-USER-ID",
        "asset_id": "ASSET-REAL-1",
        "param_name": "id",
        "location": "path",
    })
    db.insert_parameter({
        "param_id": "PARAM-ORDER-ID",
        "asset_id": "ASSET-REAL-2",
        "param_name": "order_id",
        "location": "body",
    })

    db.insert_identity({"identity_id": "user_alice", "role": "user"})
    db.insert_identity({"identity_id": "user_bob", "role": "user"})

    db.insert_evidence_item({
        "fact_id": "FACT-REAL-01",
        "certainty": "OBSERVED",
        "statement": "Valid observed invoice fact",
        "source_tool": "burp",
    })


def test_grounding_valid_hypothesis(tmp_path: Path):
    """Verify completely grounded and structurally valid hypothesis passes."""
    db_manager = DatabaseManager(db_path=tmp_path / "ground_test.db")
    db_manager.initialize_schema()
    setup_test_database(db_manager)

    validator = GroundingValidator(db_manager)

    output = HypothesisModelOutput(
        reasoning_summary="All parameters, identities, and evidence exist and match.",
        decision=HypothesisDecision.HYPOTHESIS,
        category="API-BOLA-001",
        asset_id="ASSET-REAL-1",
        parameter_ids=["PARAM-USER-ID"],
        actor_identity_id="user_alice",
        target_identity_id="user_bob",
        supporting_evidence_ids=["FACT-REAL-01"],
    )

    result = validator.validate(output)
    assert result.valid is True
    assert result.status == ValidationStatus.VALID
    assert result.final_decision == HypothesisDecision.HYPOTHESIS


def test_grounding_hallucinated_asset(tmp_path: Path):
    """Verify nonexistent asset_id causes DISCARD."""
    db_manager = DatabaseManager(db_path=tmp_path / "ground_test.db")
    db_manager.initialize_schema()
    setup_test_database(db_manager)

    validator = GroundingValidator(db_manager)

    output = HypothesisModelOutput(
        reasoning_summary="Invented asset.",
        decision=HypothesisDecision.HYPOTHESIS,
        category="API-BOLA-001",
        asset_id="ASSET-NONEXISTENT",
    )
    result = validator.validate(output)
    assert result.valid is False
    assert result.status == ValidationStatus.DISCARD
    assert "hallucinated_asset" in result.reason


def test_grounding_parameter_asset_mismatch(tmp_path: Path):
    """Verify parameter belonging to ASSET-2 cited against ASSET-1 causes DISCARD."""
    db_manager = DatabaseManager(db_path=tmp_path / "ground_test.db")
    db_manager.initialize_schema()
    setup_test_database(db_manager)

    validator = GroundingValidator(db_manager)

    # PARAM-ORDER-ID belongs to ASSET-REAL-2, but model cites it under ASSET-REAL-1!
    output = HypothesisModelOutput(
        reasoning_summary="Mismatched parameter.",
        decision=HypothesisDecision.HYPOTHESIS,
        category="API-BOLA-001",
        asset_id="ASSET-REAL-1",
        parameter_ids=["PARAM-ORDER-ID"],
        supporting_evidence_ids=["FACT-REAL-01"],
    )
    result = validator.validate(output)
    assert result.valid is False
    assert result.status == ValidationStatus.DISCARD
    assert "parameter_asset_mismatch" in result.reason


def test_grounding_required_evidence_unmet_causes_downgrade(tmp_path: Path):
    """Verify missing distinct identity pair for BOLA downgrades HYPOTHESIS to INSUFFICIENT_EVIDENCE."""
    db_manager = DatabaseManager(db_path=tmp_path / "ground_test.db")
    db_manager.initialize_schema()
    setup_test_database(db_manager)

    validator = GroundingValidator(db_manager)

    # Model omits target_identity_id
    output = HypothesisModelOutput(
        reasoning_summary="BOLA without comparison victim identity.",
        decision=HypothesisDecision.HYPOTHESIS,
        category="API-BOLA-001",
        asset_id="ASSET-REAL-1",
        parameter_ids=["PARAM-USER-ID"],
        actor_identity_id="user_alice",
        target_identity_id=None, # Missing comparison identity!
        supporting_evidence_ids=["FACT-REAL-01"],
    )
    result = validator.validate(output)
    assert result.valid is True
    assert result.status == ValidationStatus.DOWNGRADE
    assert result.final_decision == HypothesisDecision.INSUFFICIENT_EVIDENCE
    assert "required_evidence_unmet" in result.reason


def test_grounding_exact_valid_fact_id_passes(tmp_path: Path):
    """Verify exact valid fact ID passes validation."""
    db_manager = DatabaseManager(db_path=tmp_path / "ground_test.db")
    db_manager.initialize_schema()
    setup_test_database(db_manager)

    validator = GroundingValidator(db_manager)
    output = HypothesisModelOutput(
        reasoning_summary="Valid exact fact citation.",
        decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
        category="API-BOLA-001",
        asset_id="ASSET-REAL-1",
        parameter_ids=["PARAM-USER-ID"],
        supporting_evidence_ids=["FACT-REAL-01"],
    )
    result = validator.validate(output)
    assert result.valid is True
    assert result.status == ValidationStatus.VALID


def test_grounding_non_canonical_substring_rejected(tmp_path: Path):
    """Verify substring fact IDs like 'INV', 'A', '01' are rejected (DISCARD)."""
    db_manager = DatabaseManager(db_path=tmp_path / "ground_test.db")
    db_manager.initialize_schema()
    setup_test_database(db_manager)

    validator = GroundingValidator(db_manager)

    for invalid_substring in ["INV", "A", "01", "REAL"]:
        output = HypothesisModelOutput(
            reasoning_summary=f"Substring fact citation: {invalid_substring}",
            decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
            category="API-BOLA-001",
            asset_id="ASSET-REAL-1",
            parameter_ids=["PARAM-USER-ID"],
            supporting_evidence_ids=[invalid_substring],
        )
        result = validator.validate(output)
        assert result.valid is False, f"Expected {invalid_substring} to be rejected"
        assert result.status == ValidationStatus.DISCARD
        assert "hallucinated_evidence" in result.reason


def test_grounding_malformed_and_unknown_fact_ids_rejected(tmp_path: Path):
    """Verify malformed and unknown fact IDs are rejected (DISCARD)."""
    db_manager = DatabaseManager(db_path=tmp_path / "ground_test.db")
    db_manager.initialize_schema()
    setup_test_database(db_manager)

    validator = GroundingValidator(db_manager)

    for malformed in ["", "   ", "FACT-DOES-NOT-EXIST-999"]:
        output = HypothesisModelOutput(
            reasoning_summary=f"Malformed citation: '{malformed}'",
            decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
            category="API-BOLA-001",
            asset_id="ASSET-REAL-1",
            parameter_ids=["PARAM-USER-ID"],
            supporting_evidence_ids=[malformed],
        )
        result = validator.validate(output)
        assert result.valid is False
        assert result.status == ValidationStatus.DISCARD
        assert "hallucinated_evidence" in result.reason


def test_grounding_valid_normalization_preserved(tmp_path: Path):
    """Verify supported canonical normalizations (omitted FACT- prefix and legacy aliases) pass."""
    db_manager = DatabaseManager(db_path=tmp_path / "ground_test.db")
    db_manager.initialize_schema()
    setup_test_database(db_manager)
    # Seed simulation fact for alias testing
    db_manager.insert_evidence_item({
        "fact_id": "FACT-SIM-EXEC-01",
        "certainty": "OBSERVED",
        "statement": "Simulated execution fact",
        "source_tool": "simulator",
    })

    validator = GroundingValidator(db_manager)

    # 1. Missing 'FACT-' prefix (e.g. 'REAL-01')
    output1 = HypothesisModelOutput(
        reasoning_summary="Omitted FACT- prefix.",
        decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
        category="API-BOLA-001",
        asset_id="ASSET-REAL-1",
        parameter_ids=["PARAM-USER-ID"],
        supporting_evidence_ids=["REAL-01"],
    )
    result1 = validator.validate(output1)
    assert result1.valid is True
    assert result1.status == ValidationStatus.VALID

    # 2. Execution legacy alias ('EMP-001' -> 'FACT-SIM-EXEC-01')
    output2 = HypothesisModelOutput(
        reasoning_summary="Empirical alias.",
        decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
        category="API-BOLA-001",
        asset_id="ASSET-REAL-1",
        parameter_ids=["PARAM-USER-ID"],
        supporting_evidence_ids=["EMP-001"],
    )
    result2 = validator.validate(output2)
    assert result2.valid is True
    assert result2.status == ValidationStatus.VALID
