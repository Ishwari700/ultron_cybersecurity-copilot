"""Unit tests for multi-format knowledge parsers (Milestone M9 Stage B).

Covers:
- UnifiedDocumentParser format routing and size ceiling limits.
- MarkdownDocumentParser with and without YAML frontmatter.
- PlainTextDocumentParser decoding and title extraction.
- PdfDocumentParser multi-page extraction, physical page indexing, empty page handling,
  encrypted document detection, and corrupt/empty file handling.
"""

import io
from pathlib import Path
import pytest
import pypdf

from src.knowledge.parsers import (
    CorruptDocumentError,
    EncryptedDocumentError,
    ExtractedDocument,
    ExtractedPage,
    MarkdownDocumentParser,
    MAX_FILE_SIZE_BYTES,
    OversizedFileError,
    PdfDocumentParser,
    PlainTextDocumentParser,
    UnifiedDocumentParser,
    UnsupportedFormatError,
)


def _generate_test_pdf(pages_text: list[str], password: str | None = None) -> bytes:
    """Helper to generate a standards-compliant multi-page PDF using pypdf.PdfWriter."""
    writer = pypdf.PdfWriter()
    for text in pages_text:
        if text:
            raw = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> /Contents 4 0 R >> endobj
4 0 obj << /Length {len(text) + 40} >> stream
BT /F1 12 Tf 72 712 Td ({text}) Tj ET
endstream endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000057 00000 n 
0000000114 00000 n 
0000000267 00000 n 
trailer << /Size 5 /Root 1 0 R >>
startxref
{350 + len(text)}
%%EOF"""
        else:
            raw = """%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents 4 0 R >> endobj
4 0 obj << /Length 0 >> stream
endstream endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000057 00000 n 
0000000114 00000 n 
0000000220 00000 n 
trailer << /Size 5 /Root 1 0 R >>
startxref
270
%%EOF"""
        reader = pypdf.PdfReader(io.BytesIO(raw.encode("latin1")))
        writer.add_page(reader.pages[0])

    if password:
        writer.encrypt(password)

    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Unified Document Parser Routing & Boundaries
# ---------------------------------------------------------------------------

def test_unified_parser_dispatches_by_extension():
    """Verify UnifiedDocumentParser delegates correctly across PDF, MD, and TXT."""
    md_content = b"# Security Guide\nContent here."
    doc_md = UnifiedDocumentParser.parse(md_content, filename="guide.md")
    assert doc_md.format == "MARKDOWN"
    assert doc_md.title == "Security Guide"

    txt_content = b"Single line plain text."
    doc_txt = UnifiedDocumentParser.parse(txt_content, filename="notes.txt")
    assert doc_txt.format == "PLAIN_TEXT"

    pdf_bytes = _generate_test_pdf(["Chapter 1"])
    doc_pdf = UnifiedDocumentParser.parse(pdf_bytes, filename="book.pdf")
    assert doc_pdf.format == "PDF"


def test_unified_parser_rejects_unsupported_extensions():
    """Verify unsupported formats raise UnsupportedFormatError."""
    with pytest.raises(UnsupportedFormatError, match="Unsupported file format"):
        UnifiedDocumentParser.parse(b"dummy content", filename="malicious.exe")

    with pytest.raises(UnsupportedFormatError, match="Unsupported file format"):
        UnifiedDocumentParser.parse(b"dummy content", filename="report.docx")


def test_unified_parser_enforces_size_ceiling():
    """Verify files exceeding maximum size ceiling raise OversizedFileError."""
    oversized = b"A" * 1024
    with pytest.raises(OversizedFileError, match="exceeds the maximum allowed ceiling"):
        UnifiedDocumentParser.parse(oversized, filename="large.txt", max_size_bytes=512)


# ---------------------------------------------------------------------------
# Markdown Document Parser
# ---------------------------------------------------------------------------

def test_markdown_parser_with_frontmatter():
    """Verify YAML frontmatter extraction, metadata parsing, and heading splitting."""
    raw_md = b"""---
title: "OWASP Top 10 - Injection"
author: "Security Team"
version: "2026.1"
---

# Overview
Injection flaws occur when untrusted data is sent to an interpreter.

## SQL Injection
SQL injection is a critical vulnerability.
"""
    doc = MarkdownDocumentParser.parse_bytes(raw_md)
    assert doc.format == "MARKDOWN"
    assert doc.title == "OWASP Top 10 - Injection"
    assert doc.author == "Security Team"
    assert doc.metadata.get("version") == "2026.1"
    assert doc.page_count >= 2
    assert doc.status == "SUCCESS"
    assert doc.pages[0].has_text is True


def test_markdown_parser_without_frontmatter():
    """Verify fallback title deduction from first markdown heading."""
    raw_md = b"""# Cross-Site Scripting (XSS)

XSS allows attackers to execute arbitrary JavaScript in victim browsers.
"""
    doc = MarkdownDocumentParser.parse_bytes(raw_md)
    assert doc.title == "Cross-Site Scripting (XSS)"
    assert doc.format == "MARKDOWN"
    assert doc.status == "SUCCESS"


# ---------------------------------------------------------------------------
# Plain Text Document Parser
# ---------------------------------------------------------------------------

def test_plain_text_parser():
    """Verify plain text whitespace normalization and title extraction."""
    raw_txt = b"Port Scan Results\nHost 192.168.1.1 has open ports: 22, 80, 443."
    doc = PlainTextDocumentParser.parse_bytes(raw_txt)
    assert doc.format == "PLAIN_TEXT"
    assert doc.title == "Port Scan Results"
    assert doc.page_count == 1
    assert doc.pages_with_text == 1
    assert "open ports: 22, 80, 443" in doc.raw_content


def test_plain_text_parser_empty():
    """Verify empty text document yields truthful FAILED status."""
    doc = PlainTextDocumentParser.parse_bytes(b"   \n  \t  ")
    assert doc.status == "FAILED"
    assert doc.pages_with_text == 0
    assert doc.error is not None


# ---------------------------------------------------------------------------
# PDF Document Parser: Multi-Page Extraction & Physical Index Provenance
# ---------------------------------------------------------------------------

def test_pdf_multi_page_extraction_and_provenance():
    """Verify physical 1-indexed page numbering and content association."""
    pages = [
        "Page 1: Fundamentals of Network Security and Firewall Architectures",
        "Page 2: Cryptographic Protocols, TLS 1.3 Handshake Mechanics",
        "Page 3: Vulnerability Assessment and Penetration Testing Workflows",
    ]
    pdf_bytes = _generate_test_pdf(pages)
    doc = PdfDocumentParser.parse_bytes(pdf_bytes)

    assert doc.format == "PDF"
    assert doc.page_count == 3
    assert doc.pages_with_text == 3
    assert len(doc.empty_pages) == 0
    assert doc.status == "SUCCESS"

    for i, expected_text in enumerate(pages, start=1):
        extracted_page = doc.pages[i - 1]
        assert extracted_page.page_number == i
        assert extracted_page.has_text is True
        assert expected_text in extracted_page.text
        assert extracted_page.char_count > 0
        assert extracted_page.token_estimate > 0


def test_pdf_empty_and_partial_extraction():
    """Verify mixed PDF with empty pages yields truthful PARTIAL status."""
    pages = [
        "Page 1: Active content",
        "",  # Empty Page 2
        "Page 3: Active content continuation",
    ]
    pdf_bytes = _generate_test_pdf(pages)
    doc = PdfDocumentParser.parse_bytes(pdf_bytes)

    assert doc.page_count == 3
    assert doc.pages_with_text == 2
    assert doc.empty_pages == [2]
    assert doc.status == "PARTIAL"
    assert "2/3 pages contain text" in (doc.error or "")

    assert doc.pages[0].has_text is True
    assert doc.pages[1].has_text is False
    assert doc.pages[1].text == ""
    assert doc.pages[2].has_text is True


def test_pdf_scanned_or_zero_text_handling():
    """Verify PDF with 0 extractable characters across all pages fails with OCR notice."""
    pages = ["", ""]
    pdf_bytes = _generate_test_pdf(pages)
    doc = PdfDocumentParser.parse_bytes(pdf_bytes)

    assert doc.page_count == 2
    assert doc.pages_with_text == 0
    assert doc.status == "FAILED"
    assert "OCR required" in (doc.error or "")


def test_pdf_encrypted_fails_closed():
    """Verify password-protected PDF fails closed with truthful encryption status."""
    pdf_bytes = _generate_test_pdf(["Confidential vulnerability data"], password="strong_password_123")
    doc = PdfDocumentParser.parse_bytes(pdf_bytes)

    assert doc.status == "FAILED"
    assert doc.is_encrypted is True
    assert "encrypted or password-protected" in (doc.error or "")


def test_pdf_corrupt_structure_handling():
    """Verify corrupt PDF byte sequences produce truthful failure and is_corrupt flag."""
    corrupt_bytes = b"%PDF-1.4 \x00\xff invalid truncated stream without xref"
    doc = PdfDocumentParser.parse_bytes(corrupt_bytes)

    assert doc.status == "FAILED"
    assert doc.is_corrupt is True
    assert "Corrupt PDF" in (doc.error or "")


def test_pdf_empty_byte_handling():
    """Verify zero-byte input fails cleanly without unhandled exception."""
    doc = PdfDocumentParser.parse_bytes(b"")

    assert doc.status == "FAILED"
    assert doc.is_corrupt is True
    assert "0 bytes received" in (doc.error or "")


# ---------------------------------------------------------------------------
# CFF Type1 Font Support (fontTools Verification)
# ---------------------------------------------------------------------------

def test_pypdf_detects_fonttools_in_active_interpreter():
    """Verify pypdf detects fontTools in the active Ultron runtime environment."""
    import pypdf.generic._font as pypdf_font
    assert pypdf_font.HAS_FONTTOOLS is True, "pypdf must detect fontTools in active interpreter"
    from fontTools.cffLib import CFFFontSet
    assert CFFFontSet is not None


def test_pdf_cff_font_encoding_does_not_emit_fonttools_warning(caplog):
    """
    Verify parsing a PDF font dictionary with embedded CFF Type1 font (/FontFile3 /Type1C,
    e.g. MinionPro-Regular) uses fontTools and does not emit fontTools missing warnings.
    """
    import logging
    from pypdf.generic import DictionaryObject, NameObject, StreamObject
    from pypdf._cmap import _parse_to_unicode

    font_desc = DictionaryObject()
    ff3 = StreamObject()
    ff3[NameObject("/Subtype")] = NameObject("/Type1C")
    ff3._data = b""
    font_desc[NameObject("/FontFile3")] = ff3
    font_desc[NameObject("/FontName")] = NameObject("/MinionPro-Regular")

    ft = DictionaryObject()
    ft[NameObject("/FontDescriptor")] = font_desc
    ft[NameObject("/BaseFont")] = NameObject("/MinionPro-Regular")

    with caplog.at_level(logging.WARNING, logger="pypdf"):
        _parse_to_unicode(ft)

    warning_msgs = [r.message for r in caplog.records if "fontTools is required" in r.message]
    assert len(warning_msgs) == 0, f"Unexpected fontTools warnings emitted: {warning_msgs}"

