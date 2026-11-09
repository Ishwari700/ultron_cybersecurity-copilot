"""Deterministic duplicate and overlap detection and chunk merging for M11.5 Long Response Subsystem.
Guarantees exact chunk provenance reconstruction while producing clean, seamless combined responses.
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel


class OverlapDetectionResult(BaseModel):
    """Details of overlap detection between adjacent chunks."""
    overlap_detected: bool
    overlap_type: str  # 'exact', 'sentence', 'paragraph', 'normalized_whitespace', 'meta_preface', 'none'
    overlap_length: int
    overlap_snippet: str
    cleaned_chunk: str
    original_chunk: str
    confidence: float


class ResponseMerger:
    """
    Detects and resolves accidental repetitive overlaps between sequential chunks
    without discarding legitimate repeated technical content.
    """

    # Common meta prefaces models occasionally generate upon continuation requests
    META_PREFACES = [
        re.compile(r"^(?:here is the continuation[:\s]*)+", re.IGNORECASE),
        re.compile(r"^(?:continuing from (?:above|where (?:we|i) left off)[:\s]*)+", re.IGNORECASE),
        re.compile(r"^(?:to continue(?: the (?:explanation|analysis|code))?[:\s]*)+", re.IGNORECASE),
        re.compile(r"^(?:resuming from (?:the )?interruption[:\s]*)+", re.IGNORECASE),
    ]

    def __init__(self, min_exact_overlap: int = 4, max_overlap_window: int = 1500) -> None:
        self.min_exact_overlap = min_exact_overlap
        self.max_overlap_window = max_overlap_window

    @staticmethod
    def _normalize_whitespace_cmp(text: str) -> str:
        """Normalize internal and external whitespace for robust content comparison."""
        return re.sub(r"\s+", " ", text).strip().lower()

    @staticmethod
    def deduplicate_response_content(text: str) -> str:
        """
        Conservative, deterministic normalization for generated long responses:
        1. Removes duplicate sections where identical headings have duplicate or subset bodies.
        2. Removes adjacent and repeated identical substantive paragraphs (>= 40 chars).
        3. Preserves valid lists, tables, code blocks, citations, and unique explanations in original order.
        """
        if not text or not text.strip():
            return text

        # Step 1: Protect and extract code blocks so they are never broken or modified
        code_blocks: Dict[str, str] = {}
        code_placeholder_prefix = "___CODE_BLOCK_PLACEHOLDER_"

        def repl_code(match: re.Match) -> str:
            idx = len(code_blocks)
            key = f"{code_placeholder_prefix}{idx}___"
            code_blocks[key] = match.group(0)
            return key

        masked_text = re.sub(r"```[\s\S]*?```", repl_code, text)

        # Ensure markdown headings preceded by non-newlines have proper paragraph separation
        masked_text = re.sub(r"(?<=[^\n])\s*(#{1,6}\s+[^\n]+)", r"\n\n\1", masked_text)

        # Separate bold list items that were fused inline after a complete sentence with dangling cut-off words
        masked_text = re.sub(
            r"([.!?])\s+[A-Za-z0-9_\-]+(?:\s+[a-z0-9_\-]+){1,4}\s+(\d{1,2}\.\s+\*\*[^*]+\*\*)",
            r"\1\n\n\2",
            masked_text,
        )
        # Separate bold list items that were fused directly onto a sentence end without a newline
        masked_text = re.sub(
            r"([.!?])\s*(\d{1,2}\.\s+\*\*[^*]+\*\*)",
            r"\1\n\n\2",
            masked_text,
        )

        # Step 2: Parse text into sections by markdown headings (^#{1,6}\s+.+)
        lines = masked_text.split("\n")
        sections: List[Dict[str, Any]] = []
        current_heading: Optional[str] = None
        current_lines: List[str] = []

        def flush_section() -> None:
            nonlocal current_heading, current_lines
            body_text = "\n".join(current_lines).strip()
            if current_heading is not None or body_text:
                sections.append({
                    "heading": current_heading,
                    "body": body_text,
                })
            current_heading = None
            current_lines = []

        for line in lines:
            m = re.match(r"^(#{1,6}\s+[^\n]+)$", line)
            if m:
                flush_section()
                current_heading = m.group(1).strip()
            else:
                current_lines.append(line)
        flush_section()

        # Step 3: Deduplicate sections with identical or normalized headings
        deduped_sections: List[Dict[str, Any]] = []
        seen_headings: Dict[str, int] = {}  # norm_heading -> index in deduped_sections
        seen_substantive_paras: set = set()

        for sec in sections:
            heading = sec["heading"]
            body = sec["body"]
            norm_h = None
            if heading:
                cleaned_h = re.sub(r"^#{1,6}\s*(\d+\.?\s*)?", "", heading)
                norm_h = ResponseMerger._normalize_whitespace_cmp(cleaned_h)

            if norm_h and norm_h in seen_headings:
                prev_idx = seen_headings[norm_h]
                prev_sec = deduped_sections[prev_idx]
                prev_body = prev_sec["body"]

                norm_prev_body = ResponseMerger._normalize_whitespace_cmp(prev_body)
                norm_curr_body = ResponseMerger._normalize_whitespace_cmp(body)

                # Case A: Current body is identical, empty, or a subset of previous body -> skip entirely
                if not norm_curr_body or norm_curr_body == norm_prev_body or norm_curr_body in norm_prev_body:
                    continue

                # Case B: Previous body is subset of current body -> update previous body to the fuller one
                if norm_prev_body in norm_curr_body:
                    prev_sec["body"] = body
                    continue

                # Case C: Both have substantive content: split into paragraphs and deduplicate
                prev_paras = [p.strip() for p in prev_body.split("\n\n") if p.strip()]
                curr_paras = [p.strip() for p in body.split("\n\n") if p.strip()]
                unique_curr_paras = []
                for cp in curr_paras:
                    norm_cp = ResponseMerger._normalize_whitespace_cmp(cp)
                    core_cp = re.sub(r"^\s*(\d+\.|[-*+])\s+", "", norm_cp).strip(" .!?:;")
                    is_dupe = any(
                        core_cp == re.sub(r"^\s*(\d+\.|[-*+])\s+", "", ResponseMerger._normalize_whitespace_cmp(pp)).strip(" .!?:;")
                        for pp in prev_paras
                    )
                    if is_dupe or (len(core_cp) >= 30 and core_cp in seen_substantive_paras):
                        continue
                    unique_curr_paras.append(cp)

                if unique_curr_paras:
                    prev_sec["body"] = prev_body + "\n\n" + "\n\n".join(unique_curr_paras)
                continue

            if norm_h:
                seen_headings[norm_h] = len(deduped_sections)

            # Paragraph and list item deduplication within section body
            if body:
                paras = [p.strip() for p in body.split("\n\n") if p.strip()]
                cleaned_paras = []
                for p in paras:
                    is_table = p.startswith("|") and "|" in p
                    is_code = code_placeholder_prefix in p
                    is_list = bool(re.search(r"(^|\n)\s*(\d+\.|[-*+])\s+", p))

                    if is_code or is_table:
                        cleaned_paras.append(p)
                        continue

                    if is_list:
                        # Process list items to prune duplicate bullet points/remediation lines
                        list_lines = p.split("\n")
                        kept_lines = []
                        for line in list_lines:
                            stripped_line = line.strip()
                            if not stripped_line:
                                continue
                            core_item = re.sub(r"^\s*(\d+\.|[-*+])\s+", "", stripped_line)
                            norm_item = ResponseMerger._normalize_whitespace_cmp(core_item).strip(" .!?:;")
                            if len(norm_item) >= 28 and norm_item in seen_substantive_paras:
                                continue
                            if len(norm_item) >= 28:
                                seen_substantive_paras.add(norm_item)
                            kept_lines.append(line)
                        if kept_lines:
                            cleaned_paras.append("\n".join(kept_lines))
                        continue

                    # Standard paragraph
                    norm_p = ResponseMerger._normalize_whitespace_cmp(p)
                    core_p = re.sub(r"^\s*(\d+\.|[-*+])\s+", "", norm_p).strip(" .!?:;")

                    if len(core_p) >= 35:
                        if core_p in seen_substantive_paras:
                            continue
                        seen_substantive_paras.add(core_p)

                    # Skip adjacent exact duplicates
                    if cleaned_paras and ResponseMerger._normalize_whitespace_cmp(cleaned_paras[-1]) == norm_p:
                        continue

                    cleaned_paras.append(p)

                raw_body = "\n\n".join(cleaned_paras)
                sec["body"] = ResponseMerger._normalize_and_renumber_lists(raw_body)

            # Only append section if it has a heading or non-empty body
            if sec["heading"] or sec["body"]:
                deduped_sections.append(sec)

        # Step 4: Reassemble document
        result_parts = []
        for sec in deduped_sections:
            h = sec["heading"]
            b = sec["body"]
            if h and b:
                result_parts.append(f"{h}\n\n{b}")
            elif h and not b:
                # If section has only a heading and no body, check if it's the last section or followed by content
                result_parts.append(h)
            elif b:
                result_parts.append(b)

        reassembled = "\n\n".join(result_parts)

        # Step 5: Restore code blocks
        for key, code_content in code_blocks.items():
            reassembled = reassembled.replace(key, code_content)

        return reassembled.strip()

    @staticmethod
    def _normalize_and_renumber_lists(body_text: str) -> str:
        """
        Normalize ordered lists within section body:
        1. Ensures items in sequential numbered lists are consecutively numbered (1, 2, 3...).
        2. Prunes verbatim duplicate category items within the same list.
        3. Preserves nested lists, bullet points, code blocks, tables, and markdown structure.
        """
        if not body_text:
            return body_text

        paras = body_text.split("\n\n")
        new_paras = []
        in_numbered_sequence = False
        seq_num = 1
        seen_bold_categories = set()

        for p in paras:
            lines = p.split("\n")
            first_line_match = re.match(r"^\s*(\d+)\.\s+(\S.*)$", lines[0])
            if first_line_match:
                bold_m = re.match(r"^\s*(\d+)\.\s+\*\*([^*]+)\*\*", lines[0])
                if bold_m:
                    cat_key = ResponseMerger._normalize_whitespace_cmp(bold_m.group(2))
                    if cat_key in seen_bold_categories:
                        continue
                    seen_bold_categories.add(cat_key)

                if not in_numbered_sequence:
                    in_numbered_sequence = True
                    seq_num = 1

                rest_of_first = first_line_match.group(2)
                lines[0] = f"{seq_num}. {rest_of_first}"
                seq_num += 1

                for li in range(1, len(lines)):
                    sub_match = re.match(r"^(\d+)\.\s+(\S.*)$", lines[li])
                    if sub_match:
                        bold_sub = re.match(r"^(\d+)\.\s+\*\*([^*]+)\*\*", lines[li])
                        if bold_sub:
                            sub_key = ResponseMerger._normalize_whitespace_cmp(bold_sub.group(2))
                            if sub_key in seen_bold_categories:
                                lines[li] = ""
                                continue
                            seen_bold_categories.add(sub_key)
                        lines[li] = f"{seq_num}. {sub_match.group(2)}"
                        seq_num += 1

                cleaned_lines = [l for l in lines if l]
                if cleaned_lines:
                    new_paras.append("\n".join(cleaned_lines))
            else:
                if not lines[0].startswith((" ", "\t", "-", "*", "+", ">")):
                    in_numbered_sequence = False
                new_paras.append(p)

        return "\n\n".join(new_paras)

    def merge_chunks(self, accumulated_text: str, next_chunk: str) -> Tuple[str, OverlapDetectionResult]:
        """
        Merge next_chunk onto accumulated_text, removing accidental overlaps.
        Returns (merged_text, OverlapDetectionResult).
        """
        if not accumulated_text:
            return next_chunk, OverlapDetectionResult(
                overlap_detected=False,
                overlap_type="none",
                overlap_length=0,
                overlap_snippet="",
                cleaned_chunk=next_chunk,
                original_chunk=next_chunk,
                confidence=1.0,
            )

        if not next_chunk:
            return accumulated_text, OverlapDetectionResult(
                overlap_detected=False,
                overlap_type="none",
                overlap_length=0,
                overlap_snippet="",
                cleaned_chunk="",
                original_chunk="",
                confidence=1.0,
            )

        raw_chunk = next_chunk
        working_chunk = next_chunk

        # 1. Check and prune meta preface if present
        for pattern in self.META_PREFACES:
            m = pattern.match(working_chunk)
            if m:
                preface = m.group(0)
                working_chunk = working_chunk[len(preface):].lstrip()
                break

        # 2. Exact Suffix-Prefix overlap
        # Check window: trailing tail of accumulated_text vs leading head of working_chunk
        tail_window = accumulated_text[-self.max_overlap_window:]
        head_window = working_chunk[:self.max_overlap_window]

        exact_overlap_len = 0
        # Find longest matching suffix of tail_window that is a prefix of head_window
        max_possible = min(len(tail_window), len(head_window))
        for l in range(max_possible, self.min_exact_overlap - 1, -1):
            if tail_window.endswith(head_window[:l]):
                exact_overlap_len = l
                break

        if exact_overlap_len >= self.min_exact_overlap:
            overlap_str = head_window[:exact_overlap_len]
            cleaned = working_chunk[exact_overlap_len:]
            merged = accumulated_text + cleaned
            return merged, OverlapDetectionResult(
                overlap_detected=True,
                overlap_type="exact",
                overlap_length=exact_overlap_len,
                overlap_snippet=overlap_str,
                cleaned_chunk=cleaned,
                original_chunk=raw_chunk,
                confidence=0.99,
            )

        # 3. Sentence-level Overlap
        # If the continuation repeats the entire final sentence of accumulated_text
        sentences = re.split(r"(?<=[.!?])\s+", accumulated_text.strip())
        if sentences:
            last_sentence = sentences[-1].strip()
            if len(last_sentence) >= 15:  # Require meaningful length to avoid false positives
                norm_chunk = working_chunk.lstrip()
                if norm_chunk.lower().startswith(last_sentence.lower()):
                    overlap_len = len(last_sentence)
                    cleaned = norm_chunk[overlap_len:].lstrip()
                    merged = accumulated_text + ("\n" if not accumulated_text.endswith(("\n", " ")) else "") + cleaned
                    return merged, OverlapDetectionResult(
                        overlap_detected=True,
                        overlap_type="sentence",
                        overlap_length=overlap_len,
                        overlap_snippet=last_sentence,
                        cleaned_chunk=cleaned,
                        original_chunk=raw_chunk,
                        confidence=0.95,
                    )

        # 3.5. Duplicate Heading & Body Detection
        # Detect if working_chunk starts by repeating a markdown heading in the recent tail
        tail_headings = re.findall(r"(^|\n)(#{1,6}\s+[^\n]+)", tail_window)
        if tail_headings:
            # Check most recent headings backwards
            for _, candidate_heading_match in reversed(tail_headings):
                candidate_heading = candidate_heading_match.strip()
                norm_chunk = working_chunk.lstrip()
                if norm_chunk.startswith(candidate_heading):
                    # Found matching heading
                    h_idx = accumulated_text.rfind(candidate_heading)
                    existing_after_h = accumulated_text[h_idx + len(candidate_heading):].strip()
                    incoming_after_h = norm_chunk[len(candidate_heading):].lstrip()

                    # Check if incoming also repeats the body under this heading
                    overlap_len = len(candidate_heading)
                    if existing_after_h and incoming_after_h:
                        # Find exact or sentence-level overlap between existing and incoming body
                        if incoming_after_h.startswith(existing_after_h):
                            overlap_len += (len(norm_chunk[len(candidate_heading):]) - len(incoming_after_h)) + len(existing_after_h)
                            cleaned = norm_chunk[overlap_len:].lstrip()
                        else:
                            # Check if the first paragraph under the heading is repeated
                            existing_first_p = existing_after_h.split("\n\n")[0].strip()
                            if len(existing_first_p) >= 20 and incoming_after_h.lower().startswith(existing_first_p.lower()):
                                p_overlap = len(existing_first_p)
                                cleaned = incoming_after_h[p_overlap:].lstrip()
                                overlap_len += (len(norm_chunk[len(candidate_heading):]) - len(incoming_after_h)) + p_overlap
                            else:
                                cleaned = incoming_after_h
                    else:
                        cleaned = incoming_after_h

                    merged = accumulated_text + ("\n\n" if not accumulated_text.endswith("\n\n") else "") + cleaned
                    return merged, OverlapDetectionResult(
                        overlap_detected=True,
                        overlap_type="duplicate_heading",
                        overlap_length=overlap_len,
                        overlap_snippet=candidate_heading,
                        cleaned_chunk=cleaned,
                        original_chunk=raw_chunk,
                        confidence=0.98,
                    )

        # 4. Paragraph-level Overlap
        paragraphs = [p.strip() for p in accumulated_text.split("\n\n") if p.strip()]
        if paragraphs:
            last_para = paragraphs[-1]
            if len(last_para) >= 30:
                norm_chunk = working_chunk.lstrip()
                if norm_chunk.lower().startswith(last_para.lower()):
                    overlap_len = len(last_para)
                    cleaned = norm_chunk[overlap_len:].lstrip()
                    merged = accumulated_text + "\n\n" + cleaned
                    return merged, OverlapDetectionResult(
                        overlap_detected=True,
                        overlap_type="paragraph",
                        overlap_length=overlap_len,
                        overlap_snippet=last_para[:60] + "...",
                        cleaned_chunk=cleaned,
                        original_chunk=raw_chunk,
                        confidence=0.95,
                    )

        # 5. Normalized Whitespace Overlap
        tail_words = tail_window.split()
        head_words = head_window.split()
        if len(tail_words) >= 3 and len(head_words) >= 3:
            max_words = min(len(tail_words), len(head_words), 20)
            for w in range(max_words, 2, -1):
                if [tw.lower() for tw in tail_words[-w:]] == [hw.lower() for hw in head_words[:w]]:
                    matched_phrase = " ".join(head_words[:w])
                    match_pos = 0
                    for token in head_words[:w]:
                        idx = working_chunk.lower().find(token.lower(), match_pos)
                        if idx != -1:
                            match_pos = idx + len(token)
                    cleaned = working_chunk[match_pos:].lstrip()
                    merged = accumulated_text + " " + cleaned
                    return merged, OverlapDetectionResult(
                        overlap_detected=True,
                        overlap_type="normalized_whitespace",
                        overlap_length=len(matched_phrase),
                        overlap_snippet=matched_phrase,
                        cleaned_chunk=cleaned,
                        original_chunk=raw_chunk,
                        confidence=0.88,
                    )

        # No overlap detected; natural concatenation with clean boundary separation
        if working_chunk.startswith((",", ";", ":", ")", "]", "}", "!", "?", ".")):
            merged = accumulated_text + working_chunk
            return merged, OverlapDetectionResult(
                overlap_detected=False,
                overlap_type="none",
                overlap_length=0,
                overlap_snippet="",
                cleaned_chunk=working_chunk,
                original_chunk=raw_chunk,
                confidence=1.0,
            )

        stripped_working = working_chunk.lstrip()
        is_incoming_list_item = bool(re.match(r"^(\d+\.|[-*+])\s+", stripped_working))
        is_incoming_heading = stripped_working.startswith("#")

        if is_incoming_list_item or is_incoming_heading:
            # Check if accumulated_text ended with dangling cut-off words after a period
            # e.g. "... server takeover. Applications using" before "10. **Broken Authentication**"
            cut_m = re.search(r"([.!?])\s+([A-Za-z0-9_\-]+(?:\s+[a-z0-9_\-]+){1,4})$", accumulated_text)
            clean_accum = accumulated_text[:cut_m.start(2)].rstrip() if cut_m else accumulated_text
            sep = "\n\n" if not clean_accum.endswith("\n\n") else ""
            if clean_accum.endswith("\n") and not clean_accum.endswith("\n\n"):
                sep = "\n"
            merged = clean_accum + sep + stripped_working
        elif not accumulated_text.endswith(("\n", " ")) and working_chunk and not working_chunk.startswith(("\n", " ")):
            if accumulated_text.endswith((".", "!", "?", ":")):
                merged = accumulated_text + "\n\n" + stripped_working
            else:
                merged = accumulated_text + " " + stripped_working
        elif accumulated_text.endswith("\n") and not accumulated_text.endswith("\n\n") and is_incoming_heading:
            merged = accumulated_text + "\n" + stripped_working
        else:
            merged = accumulated_text + working_chunk
        return merged, OverlapDetectionResult(
            overlap_detected=False,
            overlap_type="none",
            overlap_length=0,
            overlap_snippet="",
            cleaned_chunk=working_chunk,
            original_chunk=raw_chunk,
            confidence=1.0,
        )
