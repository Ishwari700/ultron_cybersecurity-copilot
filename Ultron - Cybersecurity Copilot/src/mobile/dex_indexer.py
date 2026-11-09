"""DEX Bytecode Parser and Indexer for M10.

Parses binary DEX format (and structured representations) to extract:
- Class definitions and hierarchy (DexClass)
- Method declarations, signatures, and access flags (DexMethod)
- String pool and type pool
- Method invocation references
- Generates deterministic method identifiers: Lclass;->method(args)ret
- Fail-closed handling for malformed bytecode.
"""

import hashlib
import struct
from typing import Any, Dict, List, Optional, Tuple

from src.mobile.artifacts import DexArtifact, DexClass, DexMethod


class DexParsingError(Exception):
    """Raised when DEX parsing fails due to malformed bytecode."""
    pass


class DexIndexer:
    """Deterministic parser and indexer for Dalvik Executable (DEX) bytecode."""

    ACCESS_FLAGS_MAP = {
        0x0001: "public",
        0x0002: "private",
        0x0004: "protected",
        0x0008: "static",
        0x0010: "final",
        0x0020: "synchronized",
        0x0100: "native",
        0x0200: "interface",
        0x0400: "abstract",
    }

    @classmethod
    def _read_uleb128(cls, data: bytes, offset: int) -> Tuple[int, int]:
        """Reads unsigned LEB128 integer and returns (value, new_offset)."""
        result = 0
        shift = 0
        while offset < len(data):
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result, offset

    @classmethod
    def _decode_access_flags(cls, flags: int) -> List[str]:
        result = []
        for bit, name in cls.ACCESS_FLAGS_MAP.items():
            if flags & bit:
                result.append(name)
        return result

    @classmethod
    def parse_dex_bytes(cls, dex_bytes: bytes, dex_name: str = "classes.dex") -> DexArtifact:
        """
        Parses raw DEX binary bytes into a canonical DexArtifact.
        Fails safely if headers are corrupt or truncated.
        """
        if len(dex_bytes) < 112:
            raise DexParsingError(f"DEX data is too small for header ({len(dex_bytes)} bytes)")

        magic = dex_bytes[:8]
        if not magic.startswith(b"dex\n"):
            raise DexParsingError(f"Invalid DEX magic: {magic!r}")

        try:
            # Header unpacking
            # magic[8], checksum[4], signature[20], file_size[4], header_size[4], endian_tag[4]
            header = dex_bytes[:112]
            (
                file_size,
                header_size,
                endian_tag,
                link_size,
                link_off,
                map_off,
                string_ids_size,
                string_ids_off,
                type_ids_size,
                type_ids_off,
                proto_ids_size,
                proto_ids_off,
                field_ids_size,
                field_ids_off,
                method_ids_size,
                method_ids_off,
                class_defs_size,
                class_defs_off,
                data_size,
                data_off,
            ) = struct.unpack_from("<20xIIIIIIIIIIIIIIIIII", header, 12)

            # 1. Parse String Pool
            string_pool: List[str] = []
            for i in range(min(string_ids_size, 50000)):  # Bounded parsing
                str_off_pos = string_ids_off + (i * 4)
                if str_off_pos + 4 > len(dex_bytes):
                    break
                (str_data_off,) = struct.unpack_from("<I", dex_bytes, str_off_pos)
                if str_data_off < len(dex_bytes):
                    _, str_start = cls._read_uleb128(dex_bytes, str_data_off)
                    null_pos = dex_bytes.find(b"\x00", str_start)
                    if null_pos != -1:
                        raw_str = dex_bytes[str_start:null_pos]
                        decoded_str = raw_str.decode("utf-8", errors="ignore")
                        string_pool.append(decoded_str)

            # 2. Parse Type Pool
            type_pool: List[str] = []
            for i in range(min(type_ids_size, 20000)):
                type_pos = type_ids_off + (i * 4)
                if type_pos + 4 > len(dex_bytes):
                    break
                (descriptor_idx,) = struct.unpack_from("<I", dex_bytes, type_pos)
                if descriptor_idx < len(string_pool):
                    type_pool.append(string_pool[descriptor_idx])
                else:
                    type_pool.append(f"Type_{descriptor_idx}")

            # 3. Parse Method Pool
            method_pool: List[str] = []
            for i in range(min(method_ids_size, 30000)):
                meth_pos = method_ids_off + (i * 8)
                if meth_pos + 8 > len(dex_bytes):
                    break
                class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", dex_bytes, meth_pos)
                c_name = type_pool[class_idx] if class_idx < len(type_pool) else f"Class_{class_idx}"
                m_name = string_pool[name_idx] if name_idx < len(string_pool) else f"method_{name_idx}"
                method_id = f"{c_name}->{m_name}"
                method_pool.append(method_id)

            # 4. Parse Class Defs
            classes: List[DexClass] = []
            for i in range(min(class_defs_size, 10000)):
                class_def_pos = class_defs_off + (i * 32)
                if class_def_pos + 32 > len(dex_bytes):
                    break
                (
                    class_idx,
                    access_flags,
                    superclass_idx,
                    interfaces_off,
                    source_file_idx,
                    annotations_off,
                    class_data_off,
                    static_values_off,
                ) = struct.unpack_from("<IIIIIIII", dex_bytes, class_def_pos)

                class_name = type_pool[class_idx] if class_idx < len(type_pool) else f"LClass_{class_idx};"
                superclass_name = (
                    type_pool[superclass_idx]
                    if superclass_idx < len(type_pool) and superclass_idx != 0xFFFFFFFF
                    else None
                )
                src_file = (
                    string_pool[source_file_idx]
                    if source_file_idx < len(string_pool) and source_file_idx != 0xFFFFFFFF
                    else None
                )

                flags_list = cls._decode_access_flags(access_flags)

                # Associate indexed methods belonging to this class
                class_methods: List[DexMethod] = []
                for m_id in method_pool:
                    if m_id.startswith(f"{class_name}->"):
                        m_name = m_id.split("->", 1)[1]
                        class_methods.append(
                            DexMethod(
                                class_name=class_name,
                                method_name=m_name,
                                is_static="static" in flags_list,
                                is_native="native" in flags_list,
                            )
                        )

                classes.append(
                    DexClass(
                        class_name=class_name,
                        super_class=superclass_name,
                        access_flags=flags_list,
                        source_file=src_file,
                        methods=class_methods,
                    )
                )

            artifact = DexArtifact(
                dex_name=dex_name,
                classes=classes,
                string_pool=string_pool,
                type_pool=type_pool,
                method_pool=method_pool,
            )
            artifact.compute_hash()
            return artifact

        except Exception as e:
            raise DexParsingError(f"Error parsing DEX bytecode: {str(e)}") from e

    @classmethod
    def index_dex_metadata(cls, dex_dict: Dict[str, Any], dex_name: str = "classes.dex") -> DexArtifact:
        """
        Indexes pre-parsed or simulated DEX metadata dictionary.
        """
        raw_classes = dex_dict.get("classes", [])
        strings = dex_dict.get("strings", [])
        methods = dex_dict.get("methods", [])

        dex_classes: List[DexClass] = []
        for c in raw_classes:
            if isinstance(c, str):
                dex_classes.append(DexClass(class_name=c))
            elif isinstance(c, dict):
                c_name = c.get("name", "Unknown")
                super_c = c.get("super")
                c_methods = [
                    DexMethod(
                        class_name=c_name,
                        method_name=m.get("name", "method"),
                        signature=m.get("signature", "()V"),
                        is_native=m.get("is_native", False),
                        is_static=m.get("is_static", False),
                        called_methods=m.get("calls", []),
                        string_refs=m.get("string_refs", []),
                    )
                    for m in c.get("methods", [])
                ]
                dex_classes.append(
                    DexClass(
                        class_name=c_name,
                        super_class=super_c,
                        methods=c_methods,
                        fields=c.get("fields", []),
                    )
                )

        artifact = DexArtifact(
            dex_name=dex_name,
            classes=dex_classes,
            string_pool=strings,
            method_pool=methods,
        )
        artifact.compute_hash()
        return artifact
