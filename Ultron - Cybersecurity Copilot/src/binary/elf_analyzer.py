"""Deterministic Static ELF Binary Parser and Analyzer for M10.

Parses ELF32 and ELF64 binaries to extract:
- Format, Architecture, Bitness, Endianness, Entry point
- Program Headers (Segments: PT_LOAD, PT_GNU_STACK, PT_GNU_RELRO, PT_DYNAMIC)
- Section Headers (.text, .rodata, .dynsym, .symtab, .got, .plt)
- Symbols (Imports, Exports, Functions, Objects)
- Extracted ASCII/UTF-8 strings
- Security mitigations (NX, PIE, RELRO, Stack canaries, Stripping)
- Rejects malformed or corrupted ELFs safely without crashing (INV-M10-01).
"""

import hashlib
import struct
from typing import Any, Dict, List, Optional, Tuple

from src.binary.artifacts import (
    BinaryArtifact,
    ExportArtifact,
    FunctionArtifact,
    ImportArtifact,
    SectionArtifact,
    StringArtifact,
    SymbolArtifact,
)


class ElfParsingError(Exception):
    """Raised when ELF parsing fails due to corrupt or invalid headers."""
    pass


class ElfAnalyzer:
    """Pure-Python deterministic parser for ELF binaries."""

    MACHINE_MAP = {
        0x03: ("x86", "32"),
        0x3E: ("x86_64", "64"),
        0x28: ("arm", "32"),
        0xB7: ("arm64", "64"),
        0x08: ("mips", "32"),
    }

    # Program header types
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_GNU_STACK = 0x6474E551
    PT_GNU_RELRO = 0x6474E552

    # Section header types
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_DYNSYM = 11

    @classmethod
    def parse_elf_bytes(cls, elf_bytes: bytes, binary_name: str = "binary.so") -> BinaryArtifact:
        """Parses raw ELF bytes into a canonical BinaryArtifact."""
        if len(elf_bytes) < 52:
            raise ElfParsingError(f"File too small for ELF header ({len(elf_bytes)} bytes)")

        magic = elf_bytes[:4]
        if magic != b"\x7fELF":
            raise ElfParsingError(f"Invalid ELF magic: {magic!r}")

        ei_class = elf_bytes[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = elf_bytes[5]   # 1 = Little-endian, 2 = Big-endian

        if ei_class not in (1, 2):
            raise ElfParsingError(f"Invalid ELF class: {ei_class}")
        if ei_data not in (1, 2):
            raise ElfParsingError(f"Invalid ELF endianness: {ei_data}")

        bitness = 64 if ei_class == 2 else 32
        endian_char = "<" if ei_data == 1 else ">"
        endian_str = "little" if ei_data == 1 else "big"

        try:
            # Unpack ELF Header
            if bitness == 32:
                hdr_fmt = f"{endian_char}16sHHIIIIIHHHHHH"
                (
                    _,
                    e_type,
                    e_machine,
                    e_version,
                    e_entry,
                    e_phoff,
                    e_shoff,
                    e_flags,
                    e_ehsize,
                    e_phentsize,
                    e_phnum,
                    e_shentsize,
                    e_shnum,
                    e_shstrndx,
                ) = struct.unpack_from(hdr_fmt, elf_bytes, 0)
            else:
                hdr_fmt = f"{endian_char}16sHHIQQQIHHHHHH"
                (
                    _,
                    e_type,
                    e_machine,
                    e_version,
                    e_entry,
                    e_phoff,
                    e_shoff,
                    e_flags,
                    e_ehsize,
                    e_phentsize,
                    e_phnum,
                    e_shentsize,
                    e_shnum,
                    e_shstrndx,
                ) = struct.unpack_from(hdr_fmt, elf_bytes, 0)

            arch_name, _ = cls.MACHINE_MAP.get(e_machine, ("unknown", str(bitness)))

            # Check PIE: ET_DYN (3) = PIE or shared library, ET_EXEC (2) = non-PIE
            pie_enabled = (e_type == 3)

            # 1. Parse Program Headers (Segments)
            nx_enabled = None
            has_gnu_relro = False
            for i in range(min(e_phnum, 100)):
                ph_pos = e_phoff + (i * e_phentsize)
                if ph_pos + e_phentsize > len(elf_bytes):
                    break
                if bitness == 32:
                    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
                        f"{endian_char}IIIIIIII", elf_bytes, ph_pos
                    )
                else:
                    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                        f"{endian_char}IIQQQQQQ", elf_bytes, ph_pos
                    )

                if p_type == cls.PT_GNU_STACK:
                    # PF_X = 1 (executable). If executable bit is NOT set, stack is NX!
                    nx_enabled = (p_flags & 1) == 0

                if p_type == cls.PT_GNU_RELRO:
                    has_gnu_relro = True

            # 2. Parse Section Headers
            section_headers = []
            shstrtab_data = b""
            # Locate shstrtab first
            if 0 <= e_shstrndx < e_shnum:
                shstr_pos = e_shoff + (e_shstrndx * e_shentsize)
                if shstr_pos + e_shentsize <= len(elf_bytes):
                    if bitness == 32:
                        _, _, _, _, s_off, s_size, _, _, _, _ = struct.unpack_from(
                            f"{endian_char}IIIIIIIIII", elf_bytes, shstr_pos
                        )
                    else:
                        _, _, _, _, s_off, s_size, _, _, _, _ = struct.unpack_from(
                            f"{endian_char}IIQQQQIIQQ", elf_bytes, shstr_pos
                        )
                    if s_off + s_size <= len(elf_bytes):
                        shstrtab_data = elf_bytes[s_off : s_off + s_size]

            sections: List[SectionArtifact] = []
            symtab_info: Optional[Tuple[int, int, int, int]] = None  # (off, size, entsize, link)
            dynsym_info: Optional[Tuple[int, int, int, int]] = None
            has_symtab = False

            for i in range(min(e_shnum, 200)):
                sh_pos = e_shoff + (i * e_shentsize)
                if sh_pos + e_shentsize > len(elf_bytes):
                    break
                if bitness == 32:
                    sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                        f"{endian_char}IIIIIIIIII", elf_bytes, sh_pos
                    )
                else:
                    sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                        f"{endian_char}IIQQQQIIQQ", elf_bytes, sh_pos
                    )

                # Extract section name
                sec_name = f"section_{i}"
                if shstrtab_data and sh_name_idx < len(shstrtab_data):
                    null_idx = shstrtab_data.find(b"\x00", sh_name_idx)
                    if null_idx != -1:
                        sec_name = shstrtab_data[sh_name_idx:null_idx].decode("ascii", errors="ignore")

                # Permissions string
                perms = ("r" if (sh_flags & 0x2 or sh_flags & 0x1) else "-") + \
                        ("w" if (sh_flags & 0x1) else "-") + \
                        ("x" if (sh_flags & 0x4) else "-")

                sections.append(SectionArtifact(
                    name=sec_name,
                    virtual_address=sh_addr,
                    virtual_size=sh_size,
                    raw_size=sh_size,
                    permissions=perms,
                ))

                if sh_type == cls.SHT_SYMTAB or sec_name == ".symtab":
                    symtab_info = (sh_offset, sh_size, sh_entsize, sh_link)
                    has_symtab = True
                elif sh_type == cls.SHT_DYNSYM or sec_name == ".dynsym":
                    dynsym_info = (sh_offset, sh_size, sh_entsize, sh_link)

            # 3. Parse Symbols (Imports & Exports)
            imports: List[str] = []
            exports: List[str] = []
            import_records: List[ImportArtifact] = []
            export_records: List[ExportArtifact] = []
            symbol_records: List[SymbolArtifact] = []
            functions: List[FunctionArtifact] = []

            target_sym = dynsym_info or symtab_info
            if target_sym:
                s_off, s_size, s_entsize, s_link = target_sym
                # Get linked strtab for symbol names
                strtab_data = b""
                if 0 <= s_link < e_shnum:
                    link_pos = e_shoff + (s_link * e_shentsize)
                    if link_pos + e_shentsize <= len(elf_bytes):
                        if bitness == 32:
                            _, _, _, _, st_off, st_size, _, _, _, _ = struct.unpack_from(
                                f"{endian_char}IIIIIIIIII", elf_bytes, link_pos
                            )
                        else:
                            _, _, _, _, st_off, st_size, _, _, _, _ = struct.unpack_from(
                                f"{endian_char}IIQQQQIIQQ", elf_bytes, link_pos
                            )
                        if st_off + st_size <= len(elf_bytes):
                            strtab_data = elf_bytes[st_off : st_off + st_size]

                sym_count = s_size // (s_entsize if s_entsize > 0 else (24 if bitness == 64 else 16))
                for idx in range(min(sym_count, 5000)):
                    sym_pos = s_off + (idx * (24 if bitness == 64 else 16))
                    if sym_pos + (24 if bitness == 64 else 16) > len(elf_bytes):
                        break

                    if bitness == 32:
                        st_name, st_value, st_size_val, st_info, st_other, st_shndx = struct.unpack_from(
                            f"{endian_char}IIIBBH", elf_bytes, sym_pos
                        )
                    else:
                        st_name, st_info, st_other, st_shndx, st_value, st_size_val = struct.unpack_from(
                            f"{endian_char}IBBHQQ", elf_bytes, sym_pos
                        )

                    sym_name = ""
                    if strtab_data and st_name < len(strtab_data):
                        null_idx = strtab_data.find(b"\x00", st_name)
                        if null_idx != -1:
                            sym_name = strtab_data[st_name:null_idx].decode("ascii", errors="ignore")

                    if not sym_name:
                        continue

                    st_type = st_info & 0xF
                    st_bind = st_info >> 4
                    type_str = "FUNC" if st_type == 2 else ("OBJECT" if st_type == 1 else "OTHER")
                    bind_str = "GLOBAL" if st_bind == 1 else ("WEAK" if st_bind == 2 else "LOCAL")

                    symbol_records.append(SymbolArtifact(
                        name=sym_name,
                        address=hex(st_value) if st_value > 0 else None,
                        symbol_type=type_str,
                        binding=bind_str,
                        section_index=st_shndx,
                    ))

                    # Undefined symbol (st_shndx == 0) -> IMPORT
                    if st_shndx == 0:
                        imports.append(sym_name)
                        import_records.append(ImportArtifact(symbol_name=sym_name))
                    # Defined global symbol with address -> EXPORT
                    elif st_bind in (1, 2) and st_shndx != 0:
                        exports.append(sym_name)
                        export_records.append(ExportArtifact(symbol_name=sym_name, address=hex(st_value)))

                    if type_str == "FUNC":
                        functions.append(FunctionArtifact(
                            name=sym_name,
                            address=hex(st_value) if st_value > 0 else None,
                            is_exported=st_shndx != 0 and st_bind in (1, 2),
                        ))

            # 4. Extract Strings
            strings = []
            string_artifacts = []
            current_bytes = bytearray()
            for b in elf_bytes:
                if 32 <= b <= 126:
                    current_bytes.append(b)
                else:
                    if len(current_bytes) >= 4:
                        s_val = current_bytes.decode("ascii", errors="ignore")
                        strings.append(s_val)
                        string_artifacts.append(StringArtifact(value=s_val))
                    current_bytes = bytearray()

            # 5. Determine Mitigations
            relro_level = "FULL" if (has_gnu_relro and "BIND_NOW" in strings) else ("PARTIAL" if has_gnu_relro else "NONE")
            stack_canary = any("__stack_chk_fail" in s for s in imports)
            fortified_count = sum(1 for s in imports if "_chk" in s)

            artifact = BinaryArtifact(
                binary_name=binary_name,
                architecture=arch_name,
                format="ELF",
                bitness=bitness,
                endianness=endian_str,
                entry_point=hex(e_entry) if e_entry > 0 else None,
                functions=functions,
                sections=sections,
                symbols=symbol_records,
                imports=imports,
                exports=exports,
                import_records=import_records,
                export_records=export_records,
                string_artifacts=string_artifacts[:2000],
                strings=strings[:2000],
                pie_enabled=pie_enabled,
                nx_enabled=nx_enabled if nx_enabled is not None else False,
                relro_level=relro_level,
                stack_canary_present=stack_canary,
                symbols_stripped=not has_symtab,
                fortified_functions_count=fortified_count,
            )
            artifact.compute_hash()
            return artifact

        except struct.error as e:
            raise ElfParsingError(f"ELF struct unpack failed (corrupt header): {str(e)}") from e
        except Exception as e:
            raise ElfParsingError(f"Unexpected error parsing ELF binary: {str(e)}") from e
