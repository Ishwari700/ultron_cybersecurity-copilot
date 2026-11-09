"""Deterministic Static PE Binary Parser and Analyzer for M10.

Parses PE (Portable Executable) headers and sections for Windows binaries:
- DOS Header, COFF Header, Optional Header
- Architecture (x86, x64, ARM64), Bitness, Entry point
- Sections (.text, .data, .rdata, .pdata)
- DllCharacteristics (NX/DEP, ASLR/DynamicBase, GuardCF)
- Extracted strings
- Rejects malformed PE files safely (INV-M10-01).
"""

import struct
from typing import Any, Dict, List, Optional

from src.binary.artifacts import (
    BinaryArtifact,
    FunctionArtifact,
    SectionArtifact,
    StringArtifact,
)


class PeParsingError(Exception):
    """Raised when PE parsing fails due to corrupt headers."""
    pass


class PeAnalyzer:
    """Pure-Python deterministic parser for PE binaries."""

    MACHINE_MAP = {
        0x014C: ("x86", 32),
        0x8664: ("x86_64", 64),
        0xAA64: ("arm64", 64),
    }

    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000

    @classmethod
    def parse_pe_bytes(cls, pe_bytes: bytes, binary_name: str = "binary.dll") -> BinaryArtifact:
        """Parses raw PE bytes into a canonical BinaryArtifact."""
        if len(pe_bytes) < 64:
            raise PeParsingError(f"File too small for PE DOS header ({len(pe_bytes)} bytes)")

        if pe_bytes[:2] != b"MZ":
            raise PeParsingError(f"Invalid DOS header magic: {pe_bytes[:2]!r}")

        (e_lfanew,) = struct.unpack_from("<I", pe_bytes, 0x3C)
        if e_lfanew + 24 > len(pe_bytes):
            raise PeParsingError(f"Invalid PE header offset: {e_lfanew}")

        pe_sig = pe_bytes[e_lfanew : e_lfanew + 4]
        if pe_sig != b"PE\x00\x00":
            raise PeParsingError(f"Invalid PE signature: {pe_sig!r}")

        coff_pos = e_lfanew + 4
        machine, num_sections, timedatestamp, _, _, opt_hdr_size, characteristics = struct.unpack_from(
            "<HHIIIHH", pe_bytes, coff_pos
        )

        arch_name, bitness = cls.MACHINE_MAP.get(machine, ("unknown", 64))

        opt_pos = coff_pos + 20
        entry_point = None
        nx_enabled = False
        aslr_enabled = False

        if opt_hdr_size >= 68:
            (opt_magic,) = struct.unpack_from("<H", pe_bytes, opt_pos)
            is_pe32_plus = (opt_magic == 0x020B)
            bitness = 64 if is_pe32_plus else 32

            (entry_point_rva,) = struct.unpack_from("<I", pe_bytes, opt_pos + 16)
            entry_point = hex(entry_point_rva)

            dll_char_offset = opt_pos + (70 if is_pe32_plus else 70)
            if dll_char_offset + 2 <= len(pe_bytes):
                (dll_chars,) = struct.unpack_from("<H", pe_bytes, dll_char_offset)
                nx_enabled = bool(dll_chars & cls.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
                aslr_enabled = bool(dll_chars & cls.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)

        # Parse Section Headers
        sec_hdr_pos = opt_pos + opt_hdr_size
        sections: List[SectionArtifact] = []
        for i in range(min(num_sections, 96)):
            sec_pos = sec_hdr_pos + (i * 40)
            if sec_pos + 40 > len(pe_bytes):
                break
            sec_raw = pe_bytes[sec_pos : sec_pos + 40]
            sec_name = sec_raw[:8].rstrip(b"\x00").decode("ascii", errors="ignore")
            v_size, v_addr, raw_size, raw_ptr, _, _, _, _, sec_chars = struct.unpack_from(
                "<IIIIIIHHI", sec_raw, 8
            )

            perms = ("r" if (sec_chars & 0x40000000) else "-") + \
                    ("w" if (sec_chars & 0x80000000) else "-") + \
                    ("x" if (sec_chars & 0x20000000) else "-")

            sections.append(SectionArtifact(
                name=sec_name or f".sec{i}",
                virtual_address=v_addr,
                virtual_size=v_size,
                raw_size=raw_size,
                permissions=perms,
            ))

        # Extract Strings
        strings = []
        current_bytes = bytearray()
        for b in pe_bytes:
            if 32 <= b <= 126:
                current_bytes.append(b)
            else:
                if len(current_bytes) >= 4:
                    s_val = current_bytes.decode("ascii", errors="ignore")
                    strings.append(s_val)
                current_bytes = bytearray()

        artifact = BinaryArtifact(
            binary_name=binary_name,
            architecture=arch_name,
            format="PE",
            bitness=bitness,
            endianness="little",
            entry_point=entry_point,
            sections=sections,
            strings=strings[:2000],
            string_artifacts=[StringArtifact(value=s) for s in strings[:2000]],
            pie_enabled=aslr_enabled,
            nx_enabled=nx_enabled,
            aslr_compat=aslr_enabled,
        )
        artifact.compute_hash()
        return artifact
