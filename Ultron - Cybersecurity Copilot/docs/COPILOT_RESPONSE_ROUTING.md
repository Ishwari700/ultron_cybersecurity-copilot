# Copilot Response Routing & Pipeline Repair Specification

## 1. Problem Statement & Root Cause Diagnosis

### 1.1 The Generic-Response Defect
In the post-M13 build, distinct user inquiries such as:
- *"tell me how can i check my androids security"*
- *"tell me about android security"*
- *"Explain volumetric DDoS attacks and how organizations defend against them"*

both received the exact same generic introductory string attributed to `local_rule_engine`:
> *"I'm your local security research assistant. You can provide target observations, ask conceptual questions, or instruct me to analyze verified evidence."*

### 1.2 Root Cause Analysis
Code tracing through `src/dashboard/service.py` revealed the exact failure mechanism:
1. **Query Classification:** In `_is_conversational_query`, queries lacking pipeline action verbs (e.g. `gaps`, `hypothesis`, `experiment`, `provenance`) were correctly identified as conversational/conceptual queries (`is_conversational = True`).
2. **Missing Local Knowledge Integration:** The `CybersecurityKnowledgeOrchestrator` (the Milestone M9 multi-domain authoritative VAPT RAG subsystem) was never instantiated or utilized in `WorkspaceService`.
3. **Offline Fallback Failure:** In `_handle_conversational_query`, the code checked if Ollama was available (`self.cascade_orchestrator.ollama_client.is_available()`). When Ollama was offline or unreachable at `127.0.0.1:11434`, execution fell through a series of hardcoded checks (`"hello"`, `"who are you"`, `"bola"`, `"grounding"`).
4. **Canned Greeting Catch-All:** Any conceptual query that did not match those exact keywords hit the final default return at line 1070:
   ```python
   return (
       "I'm your local security research assistant. You can provide target observations, "
       "ask conceptual questions, or instruct me to analyze verified evidence.",
       "local_rule_engine",
       None,
   )
   ```
5. **False Completion Marking:** `send_message` wrapped this fallback into a `ChatMessage` with `status="COMPLETED"`, misleading the user into believing the system had successfully answered the question.

---

## 2. Repaired Response Pipeline Architecture

### 2.1 Complete Request Flow Before vs. After

#### Before Fix:
```
User Input
  │
  ▼
send_message()
  │
  ▼
_is_conversational_query() -> True
  │
  ▼
_handle_conversational_query()
  ├─ Ollama offline? ──► Skip LLM
  ├─ Matches 'bola'/'grounding'? ──► No
  └─ DEFAULT FALLBACK ──► Hardcoded canned intro string!
  │
  ▼
Frontend receives canned string with status="COMPLETED"
```

#### After Fix:
```
User Input
  │
  ▼
send_message()
  │
  ▼
_is_conversational_query() [Handles conceptual starters: explain, what is, how to, checklist for, etc.]
  │
  ├─ Pipeline Action Query (e.g., "analyze target traffic", "show evidence gaps")
  │     └─► _handle_investigation_query() [Requires target observations; honest abstention if empty]
  │
  └─ Conversational / Conceptual Query
        │
        ▼
     _handle_conversational_query()
        │
        ├─ Meta/Identity/History Query? ──► local_assistant deterministic response
        │
        ├─ Ollama Online (127.0.0.1:11434 available)?
        │     ├─ Retrieve M9 authoritative knowledge context (claims & citations)
        │     ├─ Assemble bounded conversation history
        │     ├─ Direct to LongResponseEngine (qwen2.5-coder:7b with continuation enabled)
        │     └─► Model-generated substantive Markdown response (model_name="qwen2.5-coder:7b")
        │
        └─ Ollama Offline or Inference Fails?
              │
              ├─ Pure Greeting ("hello", "hi") ──► local_assistant friendly security assistant greeting
              │
              ├─ Local VAPT Knowledge Match (M9 CybersecurityKnowledgeOrchestrator)?
              │     ├─ Expand query with CybersecurityQueryRewriter (acronyms, canonical terms)
              │     ├─ Lexical/semantic search against VaptDomainCorpus (32 domains, 120+ chunks)
              │     ├─ KnowledgeSufficiencyEvaluator check
              │     └─► Grounded synthesis with citations (model_name="local_knowledge_engine", status="COMPLETED")
              │
              └─ Out-of-Domain or Insufficient Knowledge?
                    └─► Honest availability message (model_name="system_status", status="SERVICE_UNAVAILABLE")
                        (Explicitly informs user that Ollama is offline at 127.0.0.1:11434 and provides guidance)
```

---

## 3. Knowledge Corpus Expansion

To ensure comprehensive, accurate coverage for primary cybersecurity research domains, authoritative chunks were added to `src/knowledge/vapt_corpus.py` and acronym expansions added to `src/retrieval/query_rewriter.py`:

1. **`MOB-ANDROID-SECURITY-REVIEW` (Mobile Security):**
   - Covers APK static analysis workflow, `AndroidManifest.xml` inspection (exported components, debuggable flags), local storage leakage (`SharedPreferences`, SQLite), Android Keystore provider usage, Network Security Configuration (`res/xml/network_security_config.xml`), and decompilation tooling (`jadx`, `apktool`).
2. **`NET-DDOS-VOLUMETRIC` (Network Security):**
   - Covers volumetric DDoS mechanics (UDP reflection/amplification, DNS, NTP, Memcached), transport layer protocol attacks (SYN floods), application layer (L7) HTTP floods, and organizational mitigations (Anycast BGP scrubbing centers, Cloudflare/AWS Shield, SYN cookies RFC 4987, adaptive WAF rate limiting).
3. **`AUTH-AUTH-VS-AUTHZ` (Authentication vs. Authorization):**
   - Authoritative conceptual separation: Authentication (AuthN, HTTP 401, identity verification) vs. Authorization (AuthZ, HTTP 403, permission evaluation on specific objects).
4. **Query Rewriter Expansion:**
   - Added acronym normalization for `ddos`, `dos`, `authn`, `authz` to ensure non-hallucinatory search expansions.

---

## 4. Honest Status & Provenance Guarantees

1. **No Canned Concealment:** The system never conceals an unavailable model behind an unrelated greeting.
2. **Status Accuracy:**
   - Valid knowledge answers return `status="COMPLETED"`.
   - Offline out-of-domain queries return `status="SERVICE_UNAVAILABLE"`.
   - Partial responses during model interruption maintain `status="TOKEN_LIMIT"` or `status="USER_STOPPED"`.
3. **Provenance Integrity:**
   - Real local model inference: `model_name="qwen2.5-coder:7b"`
   - Offline knowledge RAG engine: `model_name="local_knowledge_engine"`
   - General assistant meta responses: `model_name="local_assistant"`
   - System error and offline diagnostics: `model_name="system_status"`
