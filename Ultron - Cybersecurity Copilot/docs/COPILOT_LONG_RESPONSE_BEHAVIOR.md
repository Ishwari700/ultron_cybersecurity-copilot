# Copilot Long-Response & Continuation Engine Behavior

## 1. Overview & Architectural Principles

Milestone M11.5 introduced the `LongResponseEngine` to enable Bug Bounty AI to generate complete, in-depth, multi-section security explanations and technical reports without silent truncation.

During the Copilot UX restoration, this backend continuation engine is **fully preserved and reinforced**. The simplification of the frontend message display removes only the artificial document card styling, retaining all underlying continuation, streaming, and persistence mechanics.

---

## 2. Continuation Mechanics & Finite Guard Rails

### 2.1 Bounded Continuation Budget
- **Maximum Chunks:** Bounded to 8 continuation chunks per generation session.
- **Cumulative Token Budget:** Maximum 4,096 tokens across all chunks for a single session.
- **Single Concurrent Inference Invariant:** All model inference calls acquire `INFERENCE_LOCK` to respect the 4GB workstation VRAM constraint.

### 2.2 Natural Completion vs. Termination Detection
The `ResponseCompletenessDetector` distinguishes between:
1. **Natural Completion:**
   - Generation terminates with complete sentences (punctuation: `.`, `?`, `!`, or markdown heading completion).
   - Code fences are properly closed (balanced triple backticks).
   - In this case, `stop_reason="stop"` and `status="COMPLETED"`.
2. **Token Limit Interruption:**
   - Generation ends abruptly mid-word or mid-sentence without closing punctuation.
   - An open code block remains unclosed.
   - In this case, `stop_reason="length"` and `status="TOKEN_LIMIT"`.

### 2.3 Continuation Context & Overlap Deduplication
When automatic or manual continuation triggers:
1. **Context Preservation:** The `ContinuationPromptBuilder` passes the trailing tokens of the prior output into the continuation prompt, instructing the model to resume seamlessly without repeating prior sentences.
2. **Overlap Removal:** The `ChunkMerger` executes both character-level and token-level suffix-prefix matching. If the model repeats the beginning of the last sentence, the repeated prefix is automatically stripped before appending the new chunk.
3. **Meta Preface Stripping:** Canned conversational filler emitted by models (e.g., *"Continuing where I left off...", "Here is the rest of the response:"*) is stripped.

---

## 3. Storage & Presentation Lifecycle

### 3.1 SQLite Persistence
Each response session persists:
- **`response_sessions`:** Master record linking `session_id`, `investigation_id`, `user_prompt`, `final_content`, `token_count`, `active_version`, and `status`.
- **`response_chunks`:** Individual chunk entries recording sequence number, raw text, content hash (SHA-256), token count, latency, and stop reason.
- **`response_versions`:** Versioned revisions allowing users to compare regenerated answers.
- **`chat_messages`:** The assembled, secret-redacted text mapped to SQLite chat messages for fast conversation retrieval.

### 3.2 Frontend Natural Scrolling & UI Integration
1. **No Artificial Height Clipping:** Answers expand naturally with the conversation view, scrolling cleanly within the main message viewport.
2. **Streaming Resilience:** Streaming chunk updates append smoothly to the active message content without re-rendering or jumping user scroll position.
3. **Manual Continuation Support:** If automatic continuation exhausts its initial pass while `TOKEN_LIMIT` persists, a subtle `[▶ Continue]` action button enables the user to request additional chunks.
4. **Cancellation:** If the user clicks `[Stop]`, a `CancellationToken` signals the generator, stopping further model invocation while safely persisting the partial output with `status="USER_STOPPED"`.
