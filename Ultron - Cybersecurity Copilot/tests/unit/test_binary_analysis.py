"""Unit tests for M7 Binary Reverse Engineering Pipeline and Agent.

Verifies:
1. Function analysis: basic blocks, parameter signatures, dangerous C sink detection.
2. Call graph analysis: BFS reachability tracing from public export to dangerous sink.
3. Binary evidence adapter: cryptographic provenance and CanonicalObservation generation.
4. Binary Reverse Engineering Agent: hypothesis formulation with negative controls without
   declaring exploitability solely from decompiled warnings.
"""

import pytest
from src.agents.binary import BinaryReverseEngineeringAgent
from src.agents.schemas import AgentTask, AgentType
from src.assessment.models import EpistemicStatus
from src.binary.artifacts import CallRelationship
from src.binary.evidence import BinaryEvidenceAdapter
from src.binary.functions import FunctionAnalyzer
from src.binary.relationships import CallGraphAnalyzer


def test_function_analyzer_dangerous_sinks():
    sample_funcs = [
        {
            "name": "parse_packet",
            "address": "0x401000",
            "parameters": ["char* buf", "int len"],
            "calls": ["memcpy", "strcpy"],
            "is_exported": True,
        },
        {
            "name": "safe_helper",
            "address": "0x401200",
            "calls": ["strlen"],
            "is_exported": False,
        },
    ]

    funcs, sinks = FunctionAnalyzer.analyze_functions(sample_funcs)
    assert len(funcs) == 2
    assert len(sinks) == 1
    assert sinks[0].sink_type == "BUFFER_OVERFLOW"
    assert "strcpy" in sinks[0].instruction_or_call


def test_call_graph_reachability_bfs():
    # Graph: main -> handle_req -> vulnerable_worker -> system
    # Graph: safe_route -> exit
    rels = [
        CallRelationship(caller="main", callee="handle_req"),
        CallRelationship(caller="handle_req", callee="vulnerable_worker"),
        CallRelationship(caller="vulnerable_worker", callee="system"),
        CallRelationship(caller="main", callee="safe_route"),
    ]
    analyzer = CallGraphAnalyzer(rels)

    # Reachable query
    reachable, path = analyzer.is_reachable("main", "system")
    assert reachable is True
    assert path == ["main", "handle_req", "vulnerable_worker", "system"]

    # Unreachable query
    unreachable, empty_path = analyzer.is_reachable("safe_route", "system")
    assert unreachable is False
    assert empty_path == []


def test_binary_evidence_adapter():
    sample_funcs = [
        {"name": "process_input", "calls": ["sprintf"], "is_exported": True}
    ]
    sample_calls = [{"caller": "process_input", "callee": "sprintf"}]

    artifact, obs = BinaryEvidenceAdapter.process_binary_analysis(
        assessment_id="ASM-BIN-001",
        binary_name="libnative.so",
        architecture="arm64-v8a",
        format_type="ELF",
        raw_functions=sample_funcs,
        raw_call_graph=sample_calls,
        exports=["process_input"],
    )

    assert artifact.binary_name == "libnative.so"
    assert len(artifact.sinks) == 1
    assert obs.observation_id.startswith("OBS-")
    assert obs.scope_decision.value == "IN_SCOPE"
    assert obs.normalized_data["function_count"] == 1
    assert "BIN-" in artifact.compute_hash()


def test_binary_agent_hypotheses_with_reachability():
    agent = BinaryReverseEngineeringAgent(assessment_id="ASM-BIN-001")
    task = AgentTask(
        task_id="TASK-BIN-01",
        agent_type=AgentType.BINARY,
        assessment_id="ASM-BIN-001",
        objective="Analyze native library for reachable unsafe memory sinks",
        target_asset="libsecure.so",
        authorization_id="AUTH-001",
    )

    # Context with a reachable dangerous sink
    context = {
        "observations": [
            {
                "observation_id": "OBS-BIN-01",
                "normalized_data": {
                    "binary_name": "libsecure.so",
                    "functions": [
                        {"name": "Java_com_app_Native_parseData", "calls": ["strcpy"], "is_exported": True}
                    ],
                    "call_graph": [
                        {"caller": "Java_com_app_Native_parseData", "callee": "strcpy"}
                    ],
                    "exports": ["Java_com_app_Native_parseData"],
                },
            }
        ]
    }

    out = agent.run(task, context)
    assert out.agent_type == AgentType.BINARY
    assert out.epistemic_status == EpistemicStatus.MODEL_HYPOTHESIS
    assert len(out.hypotheses) >= 1
    hyp = out.hypotheses[0]
    assert "strcpy" in hyp.description
    assert hyp.negative_control != ""
    assert len(out.proposed_experiments) >= 1
    assert out.proposed_experiments[0].requires_human_execution is True


def test_pe_analyzer_malformed_rejection():
    from src.binary.pe_analyzer import PeAnalyzer, PeParsingError

    # Too small
    with pytest.raises(PeParsingError, match="too small"):
        PeAnalyzer.parse_pe_bytes(b"MZ123")

    # Invalid DOS magic
    with pytest.raises(PeParsingError, match="Invalid DOS header magic"):
        PeAnalyzer.parse_pe_bytes(b"NOPE" + b"\x00" * 60)

    # Valid DOS magic but invalid PE offset
    fake_dos = b"MZ" + b"\x00" * 58 + (0x1000).to_bytes(4, "little")
    with pytest.raises(PeParsingError, match="Invalid PE header offset"):
        PeAnalyzer.parse_pe_bytes(fake_dos)

