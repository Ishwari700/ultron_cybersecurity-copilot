"""M5 Output Protocol Contract & Execution Pipeline Abstraction.

Milestone M5: Reasoning Interface & Protocol Reconciliation.
Defines:
- OutputProtocolIdentifier (JSON_BAIR, BAIR_XML, S0_JSON)
- OutputProtocolContract
- get_protocol_contract()
- ReasoningExecutionContract
- validate_reasoning_contract() (Deterministic 16-check pre-flight gate)
"""

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Union

from src.engine.models import (
    BairJsonObject,
    ContractCompilationError,
    HypothesisModelOutput,
    OutputProtocolIdentifier,
)
from src.engine.bair_extractor import (
    map_bair_json_to_s0,
    map_bair_to_s0,
    parse_bair,
    parse_bair_json,
    validate_bair,
    validate_bair_json,
)

JSON_BAIR_PROMPT_INSTRUCTION = """OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - JSON_BAIR):
Emit your evaluation strictly as a single JSON object with these fields:
{
  "invariant": "Security invariant statement evaluated against target",
  "evidence_gap": "Missing observation or gap in evidence (null if none)",
  "affected_target": "Target endpoint, asset ID, or parameter",
  "decision": "HYPOTHESIS" | "INSUFFICIENT_EVIDENCE" | "NO_RELEVANT_FUNCTIONALITY",
  "empirical_facts": ["FACT-xxx", "FACT-yyy"],
  "methodology_references": ["CHK-xxx"],
  "experiment_action": "SUBSTITUTE_RESOURCE_IDENTIFIER" | "EXECUTE_OUT_OF_ORDER_TRANSITION" | "REPLAY_STEP_WITH_LOWER_ROLE" | "INVOKE_WITHOUT_CREDENTIALS" | "TAMPER_REQUEST_PARAMETER" | null,
  "supporting_outcome": "HTTP_200_OK" | "CROSS_IDENTITY_OBJECT_ACCESSIBLE" | "STATE_TRANSITION_ACCEPTED" | "PRIVILEGE_ELEVATION_SUCCEEDS" | "STATUS_SUCCESS_2XX" | null,
  "disproving_outcome": "HTTP_403_FORBIDDEN" | "CROSS_IDENTITY_OBJECT_DENIED" | "STATE_TRANSITION_REJECTED" | "PRIVILEGE_ELEVATION_DENIED" | "HTTP_404_NOT_FOUND" | "HTTP_409_CONFLICT" | "STATUS_CLIENT_ERROR_4XX" | null,
  "falsification_description": "Brief explanation of verification experiment (or null if none)"
}

FIELD CONSTRAINTS & NAMESPACE RULES:
- 'empirical_facts': cite ONLY valid FACT-xxx IDs from available target evidence.
- 'methodology_references': cite ONLY valid CHK-* identifiers actually supplied by available methodology guidance. If no methodology guidance is supplied, emit an empty list: []. Do NOT make up or invent CHK identifiers.
- A CHK citation MUST NEVER be placed in 'empirical_facts'.
- A FACT citation MUST NEVER be placed in 'methodology_references'.
- For HYPOTHESIS: 'experiment_action', 'supporting_outcome', and 'disproving_outcome' are MANDATORY and must be chosen from the closed taxonomy. 'supporting_outcome' must represent an observation demonstrating invariant breach; 'disproving_outcome' must represent an observation demonstrating the invariant holds safely.
- For INSUFFICIENT_EVIDENCE or NO_RELEVANT_FUNCTIONALITY: experiment fields may be null.
- Note: Legacy unanchored 'falsification_plan' is replaced by typed fields ('experiment_action', 'supporting_outcome', 'disproving_outcome', 'falsification_description').
- Do NOT invent or manufacture IDs or enum values.
- NEVER emit CONFIRMED as the decision.
- Do NOT wrap output in markdown formatting or add extra keys."""

BAIR_XML_PROMPT_INSTRUCTION = """OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - BAIR):
Emit your evaluation strictly as XML enclosed in a single <bair>...</bair> block with exactly these seven slots:
<bair>
  <invariant>Security invariant statement evaluated against target</invariant>
  <evidence_gap>Missing observation or gap in evidence</evidence_gap>
  <affected_target>Target endpoint, asset ID, or parameter</affected_target>
  <decision>HYPOTHESIS | INSUFFICIENT_EVIDENCE | NO_RELEVANT_FUNCTIONALITY</decision>
  <facts>FACT-xxx, FACT-yyy</facts>
  <methodology>CHK-xxx</methodology>
  <falsification>observation supporting hypothesis AND observation disproving/falsifying hypothesis</falsification>
</bair>

DECISION POLICIES & SLOT RULES:
- HYPOTHESIS: Observed evidence indicates an unverified gap or potential violation requiring experiment verification.
  * Required slots: <invariant>, <evidence_gap>, <affected_target>, <decision>, <facts>, <falsification>.
  * <falsification> MUST contain both a concrete observation that would support the hypothesis AND an observation that would disprove/falsify it.
  * <facts> MUST cite valid FACT-xxx IDs from available target evidence.
- INSUFFICIENT_EVIDENCE: Relevant functionality exists, but available evidence is incomplete.
  * Required slots: <invariant>, <evidence_gap>, <affected_target>, <decision>, <falsification>.
- NO_RELEVANT_FUNCTIONALITY: Asset lacks functionality relevant to this category.
  * Required slots: <invariant>, <affected_target>, <decision>.
- NEVER emit CONFIRMED.
- Do NOT wrap <bair> in markdown formatting or add extra slots."""

S0_JSON_PROMPT_INSTRUCTION = """OUTPUT FORMAT (CANONICAL S0 HYPOTHESIS JSON):
Emit your evaluation strictly as a single JSON object matching the canonical schema:
{
  "decision": "HYPOTHESIS" | "INSUFFICIENT_EVIDENCE" | "NO_RELEVANT_FUNCTIONALITY",
  "invariant": "Statement of relevant security invariant evaluated",
  "evidence_gap": "Identified gap or missing observation",
  "affected_target": "Target endpoint, asset ID, or parameter under evaluation",
  "supporting_evidence_ids": ["FACT-xxx"],
  "methodology_references": ["CHK-xxx"],
  "reasoning_summary": "Concise human-readable rationale",
  "experiment_proposal": "Concrete verification experiment with supporting observation and falsifying observation"
}
- NEVER emit CONFIRMED.
- Do NOT wrap output in markdown formatting."""


@dataclass(frozen=True)
class OutputProtocolContract:
    """
    Explicit M5 Output Protocol Contract.
    Deterministically binds protocol identifier to prompt instructions,
    runtime schema, parser, validator, and adapter.
    """
    identifier: OutputProtocolIdentifier
    name: str
    prompt_formatting_instruction: str
    runtime_schema_factory: Callable[[bool], Optional[Dict[str, Any]]]
    parser: Callable[[str], Any]
    validator: Callable[..., Any]
    adapter: Callable[..., HypothesisModelOutput]


def _s0_adapter(obj: Any, **kwargs: Any) -> HypothesisModelOutput:
    if isinstance(obj, HypothesisModelOutput):
        return obj
    if isinstance(obj, dict):
        return HypothesisModelOutput.model_validate(obj)
    raise TypeError(f"Expected HypothesisModelOutput or dict, got {type(obj).__name__}")


def get_protocol_contract(identifier: Union[OutputProtocolIdentifier, str]) -> OutputProtocolContract:
    """Retrieve the authoritative OutputProtocolContract for a given protocol identifier."""
    if isinstance(identifier, str):
        try:
            identifier = OutputProtocolIdentifier(identifier)
        except ValueError:
            raise ContractCompilationError(f"Unsupported output protocol identifier: {identifier}")

    if identifier == OutputProtocolIdentifier.JSON_BAIR:
        return OutputProtocolContract(
            identifier=OutputProtocolIdentifier.JSON_BAIR,
            name="JSON-Native Bounded Analytical Intermediate Representation (JSON_BAIR)",
            prompt_formatting_instruction=JSON_BAIR_PROMPT_INSTRUCTION,
            runtime_schema_factory=lambda enable_i1: BairJsonObject.get_inference_schema() if enable_i1 else None,
            parser=parse_bair_json,
            validator=validate_bair_json,
            adapter=map_bair_json_to_s0,
        )
    elif identifier == OutputProtocolIdentifier.BAIR_XML:
        def xml_schema_factory(enable_i1: bool) -> Optional[Dict[str, Any]]:
            if enable_i1:
                raise ContractCompilationError("BAIR_XML protocol does not support I1 schema-constrained decoding")
            return None

        return OutputProtocolContract(
            identifier=OutputProtocolIdentifier.BAIR_XML,
            name="XML-Native Bounded Analytical Intermediate Representation (BAIR_XML)",
            prompt_formatting_instruction=BAIR_XML_PROMPT_INSTRUCTION,
            runtime_schema_factory=xml_schema_factory,
            parser=parse_bair,
            validator=validate_bair,
            adapter=map_bair_to_s0,
        )
    elif identifier == OutputProtocolIdentifier.S0_JSON:
        return OutputProtocolContract(
            identifier=OutputProtocolIdentifier.S0_JSON,
            name="Canonical S0 Hypothesis JSON (S0_JSON)",
            prompt_formatting_instruction=S0_JSON_PROMPT_INSTRUCTION,
            runtime_schema_factory=lambda enable_i1: HypothesisModelOutput.get_inference_schema() if enable_i1 else None,
            parser=json.loads,
            validator=HypothesisModelOutput.model_validate,
            adapter=_s0_adapter,
        )
    else:
        raise ContractCompilationError(f"Unrecognized output protocol identifier: {identifier}")


@dataclass
class ReasoningExecutionContract:
    """Complete pre-flight reasoning contract payload for M5 validation."""
    protocol: OutputProtocolIdentifier
    enable_i1: bool = False
    enable_i2: bool = False
    enable_i3: bool = False
    enable_i4: bool = False
    enable_i5: bool = False
    enable_i6: bool = False
    system_prompt: str = ""
    user_prompt: str = ""
    runtime_schema: Optional[Dict[str, Any]] = None
    parser: Optional[Callable] = None
    validator: Optional[Callable] = None
    adapter: Optional[Callable] = None
    budget_tier: int = 4096
    total_tokens: int = 0
    floor_tokens: int = 0
    protected_handoff_present: bool = False
    category_id: Optional[str] = None


def validate_reasoning_contract(contract: ReasoningExecutionContract) -> None:
    """
    Deterministic Pre-Flight Contract Compilation Validator (M5 Phase 4H).
    Enforces all 16 architectural invariants before any LLM inference call:
    1. Exactly one output protocol
    2. Protocol has a parser
    3. Protocol has a validator
    4. Protocol has an adapter
    5. Prompt protocol instruction matches selected protocol
    6. Runtime schema matches selected protocol
    7. Parser matches selected protocol
    8. Validator matches selected protocol
    9. Adapter matches selected protocol
    10. All enabled interventions are composable
    11. No intervention silently shadows another
    12. No contradictory formatting instructions exist
    13. Mandatory prompt sections fit budget
    14. I6 protected handoff is present when enabled
    15. No forbidden ground-truth tokens occur
    16. No secret-bearing content enters the model-visible context

    Fails closed: raises ContractCompilationError on any discrepancy.
    """
    # 1. Exactly one output protocol
    if not isinstance(contract.protocol, OutputProtocolIdentifier):
        raise ContractCompilationError(f"Invalid or missing output protocol: {contract.protocol}")

    proto_contract = get_protocol_contract(contract.protocol)

    # 2. Protocol has a parser
    if contract.parser is None or not callable(contract.parser):
        raise ContractCompilationError("Protocol contract is missing a callable parser")

    # 3. Protocol has a validator
    if contract.validator is None or not callable(contract.validator):
        raise ContractCompilationError("Protocol contract is missing a callable validator")

    # 4. Protocol has an adapter
    if contract.adapter is None or not callable(contract.adapter):
        raise ContractCompilationError("Protocol contract is missing a callable adapter")

    full_prompt = f"{contract.system_prompt}\n{contract.user_prompt}"

    # 5. Prompt protocol instruction matches selected protocol
    if contract.protocol == OutputProtocolIdentifier.JSON_BAIR:
        if "OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - JSON_BAIR)" not in full_prompt:
            raise ContractCompilationError("Prompt missing JSON_BAIR protocol formatting instruction")
        if "<bair>" in full_prompt or "</bair>" in full_prompt:
            raise ContractCompilationError("Prompt contains XML <bair> tags while JSON_BAIR is selected")
    elif contract.protocol == OutputProtocolIdentifier.BAIR_XML:
        if "<bair>" not in full_prompt or "</bair>" not in full_prompt:
            raise ContractCompilationError("Prompt missing BAIR XML tags while BAIR_XML is selected")
        if "OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - JSON_BAIR)" in full_prompt:
            raise ContractCompilationError("Prompt contains JSON_BAIR instruction while BAIR_XML is selected")
    elif contract.protocol == OutputProtocolIdentifier.S0_JSON:
        if "<bair>" in full_prompt:
            raise ContractCompilationError("Prompt contains XML <bair> tags while S0_JSON is selected")

    # 6. Runtime schema matches selected protocol
    if contract.enable_i1:
        if contract.protocol == OutputProtocolIdentifier.BAIR_XML:
            raise ContractCompilationError("I1 schema-constrained decoding is incompatible with BAIR_XML")
        if contract.runtime_schema is None:
            raise ContractCompilationError("I1 is enabled but runtime schema is None")
        expected_schema = proto_contract.runtime_schema_factory(True)
        if contract.runtime_schema != expected_schema:
            raise ContractCompilationError("Runtime schema does not match selected protocol schema")
    else:
        if contract.runtime_schema is not None:
            raise ContractCompilationError("I1 is disabled but runtime schema is not None")

    # 7. Parser matches selected protocol
    if contract.parser != proto_contract.parser:
        raise ContractCompilationError(
            f"Parser mismatch: contract has {contract.parser.__name__}, expected {proto_contract.parser.__name__}"
        )

    # 8. Validator matches selected protocol
    if contract.validator != proto_contract.validator:
        raise ContractCompilationError(
            f"Validator mismatch: contract has {contract.validator.__name__}, expected {proto_contract.validator.__name__}"
        )

    # 9. Adapter matches selected protocol
    if contract.adapter != proto_contract.adapter:
        raise ContractCompilationError(
            f"Adapter mismatch: contract has {contract.adapter.__name__}, expected {proto_contract.adapter.__name__}"
        )

    # 10. All enabled interventions are composable
    if contract.enable_i1 and contract.protocol == OutputProtocolIdentifier.BAIR_XML:
        raise ContractCompilationError("Interventions I1 and BAIR_XML are mutually incompatible")

    # 11. No intervention silently shadows another
    if contract.enable_i2:
        if "EPISTEMIC BOUNDARY RULES" not in full_prompt and "empirical_target_evidence" not in full_prompt:
            raise ContractCompilationError("Intervention I2 enabled but I2 semantics are missing from prompt")
    if contract.enable_i3:
        if "COUNTERFACTUAL" not in full_prompt and "EVALUATION FRAMEWORK" not in full_prompt:
            raise ContractCompilationError("Intervention I3 enabled but I3 counterfactual semantics are missing from prompt")
    if contract.enable_i5:
        if "CALIBRATED ABSTENTION CONTRACT" not in full_prompt and "DECISION POLICY" not in full_prompt:
            raise ContractCompilationError("Intervention I5 enabled but I5 decision policy semantics are missing from prompt")

    # 12. No contradictory formatting instructions exist
    has_xml_instruction = "<bair>" in contract.system_prompt or "Emit your evaluation strictly as XML" in contract.system_prompt
    has_json_instruction = "JSON_BAIR" in contract.system_prompt or "strictly as a single JSON object" in contract.system_prompt
    if has_xml_instruction and has_json_instruction:
        raise ContractCompilationError("Contradictory formatting instructions detected in system prompt (both XML and JSON specified)")

    # 13. Mandatory prompt sections fit budget
    if contract.floor_tokens > contract.budget_tier:
        raise ContractCompilationError(
            f"Mandatory floor tokens ({contract.floor_tokens}) exceed budget tier ({contract.budget_tier})"
        )
    if contract.total_tokens > contract.budget_tier:
        raise ContractCompilationError(
            f"Total prompt tokens ({contract.total_tokens}) exceed budget tier ({contract.budget_tier})"
        )

    # 14. I6 protected handoff is present when enabled
    if contract.enable_i6:
        if not contract.protected_handoff_present:
            raise ContractCompilationError("I6 is enabled but protected handoff is not marked present")
        has_handoff_header = (
            "PROTECTED 3B -> 7B INVARIANT HANDOFF" in contract.user_prompt
            or "PROTECTED 3B->7B INVARIANT HANDOFF" in contract.user_prompt
            or "PROTECTED INVARIANT HANDOFF" in contract.user_prompt
            or "PROTECTED HANDOFF" in contract.user_prompt
        )
        if not has_handoff_header:
            raise ContractCompilationError("I6 is enabled but protected handoff block is missing from user prompt")

    # 15. No forbidden ground-truth tokens occur
    forbidden_tokens = [
        "is_vulnerable: true",
        "is_vulnerable: false",
        "ground_truth",
        "vulnerable_label",
        "expected_label",
    ]
    for tok in forbidden_tokens:
        if tok.lower() in full_prompt.lower():
            raise ContractCompilationError(f"Forbidden ground-truth token detected in prompt: {tok}")

    # 16. No secret-bearing content enters the model-visible context
    secret_patterns = [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"-----BEGIN\s+PRIVATE\s+KEY-----"),
        re.compile(r"bearer\s+eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+", re.IGNORECASE),
    ]
    for pat in secret_patterns:
        if pat.search(full_prompt):
            raise ContractCompilationError("Secret-bearing credential token detected in model-visible prompt")
