#!/usr/bin/env python3
"""Generate 20 deformed (anti-unpacker tampered) UPX samples.

Every sample is derived from a genuine UPX-packed PE file by applying ONE
well-defined deformation that real-world packers/malware use:
  - UPX magic tampering / fuzzy-magic cases
  - pack-header checksum tampering
  - single byte corruption of header fields (stale authentic checksum)
  - multi-byte header corruption
  - PE section name wiping/renaming
  - one genuinely destroyed compressed stream (negative control)

Only standard library is used.  Output:
  deform/samples/<id>_<name>.exe
  deform/samples/manifest.json
"""
from __future__ import annotations

import hashlib
import json
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFORM = ROOT / "deform"
SAMPLES = DEFORM / "samples"
# self-contained copies live in deform/base; fall back to the working copies
_BASE_PACKED_CANDIDATES = [
    DEFORM / "base" / "base_cmd.upx.exe",
    ROOT / "work" / "base_cmd.exe",
]
_BASE_UNPACKED_CANDIDATES = [
    DEFORM / "base" / "base_cmd.unpacked.exe",
    ROOT / "work" / "base_cmd_unpacked.exe",
]
BASE_PACKED = next((p for p in _BASE_PACKED_CANDIDATES if p.exists()),
                   _BASE_PACKED_CANDIDATES[0])
BASE_UNPACKED = next((p for p in _BASE_UNPACKED_CANDIDATES if p.exists()),
                     _BASE_UNPACKED_CANDIDATES[0])

UPX_MAGIC = b"UPX!"


def hdr_checksum(header32: bytes | bytearray) -> int:
    """UPX pack-header additive checksum: sum(p[4:size-1]) % 251."""
    return sum(header32[4:31]) % 251


def fix_checksum(buf: bytearray, hdr_off: int) -> None:
    buf[hdr_off + 31] = hdr_checksum(buf[hdr_off : hdr_off + 32])


def pe_section_offsets(data: bytes) -> list[tuple[int, int]]:
    """Return [(name_file_offset, header_offset), ...] for PE sections."""
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe_off : pe_off + 4] == b"PE\0\0", "not a PE file"
    nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    sec_table = pe_off + 24 + opt_size
    return [(sec_table + 40 * i, sec_table + 40 * i) for i in range(nsec)]


def section_name_offset(data: bytes, index: int) -> int:
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
    assert index < nsec
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    sec_table = pe_off + 24 + opt_size
    return sec_table + 40 * index


class Mutations:
    """Each mutator receives the mutable buffer and useful anchors."""

    def __init__(self, buf: bytearray, hdr: int):
        self.b = buf
        self.h = hdr

    # ---- magic deformations (do not affect header checksum) ----
    def m01_magic_bitflip(self):
        self.b[self.h + 3] ^= 0x01  # '!' 0x21 -> 0x20

    def m02_magic_lowercase(self):
        for i in range(4):
            self.b[self.h + i] ^= 0x20

    def m03_magic_zeroed(self):
        self.b[self.h : self.h + 4] = b"\0\0\0\0"

    def m04_magic_replaced(self):
        self.b[self.h : self.h + 4] = b"YTS!"

    def m05_magic_xor_encoded(self):
        for i in range(4):
            self.b[self.h + i] ^= 0x5A

    # ---- header checksum byte deformations ----
    def m06_checksum_zero(self):
        self.b[self.h + 31] = 0x00

    def m07_checksum_ff(self):
        self.b[self.h + 31] = 0xFF

    # ---- single header field byte corruption, checksum left STALE.
    # The stale checksum mathematically encodes the original byte because
    # checksum = sum(bytes 4..30) mod 251.
    def m08_level_junk_bit(self):
        self.b[self.h + 7] ^= 0x40

    def m09_version_poke(self):
        self.b[self.h + 4] ^= 0x01

    def m10_format_poke(self):
        self.b[self.h + 5] = 70  # 9 -> 70 (unassigned/invalid format id)

    def m11_method_poke(self):
        self.b[self.h + 6] = 0xFF  # 8 -> 255 (invalid method)

    def m12_uadler_byte(self):
        self.b[self.h + 9] ^= 0xFF  # one byte of u_adler

    def m13_cadler_byte(self):
        self.b[self.h + 13] ^= 0xA5  # one byte of c_adler

    def m14_ulen_byte(self):
        self.b[self.h + 17] ^= 0x10  # one byte of u_len

    # ---- multi-byte header corruption (no unique modular solution) ----
    def m15_both_adlers_multibyte(self):
        self.b[self.h + 8] ^= 0x11
        self.b[self.h + 12] ^= 0x22
        # stale checksum on purpose: fields are untrusted, but lengths and
        # method are intact so unverified decompression still succeeds.

    # ---- PE section name deformations ----
    def m16_rename_upx0(self):
        off = section_name_offset(bytes(self.b), 0)
        self.b[off : off + 8] = b".text\0\0\0"

    def m17_rename_all_sections(self):
        for idx, name in enumerate((b".text\0\0\0", b".data\0\0\0", b".rsrc2\0\0")):
            off = section_name_offset(bytes(self.b), idx)
            self.b[off : off + 8] = name

    def m18_rename_and_magic(self):
        off0 = section_name_offset(bytes(self.b), 0)
        off1 = section_name_offset(bytes(self.b), 1)
        self.b[off0 : off0 + 8] = b".text\0\0\0"
        self.b[off1 : off1 + 8] = b".data\0\0\0"
        self.b[self.h + 0] ^= 0x08  # 'U' -> ']'
        self.b[self.h + 3] ^= 0x01

    def m19_section_names_zeroed(self):
        for idx in range(3):
            off = section_name_offset(bytes(self.b), idx)
            self.b[off : off + 8] = b"\0" * 8

    # ---- extra (not part of the 20): fuzzy magic, two bytes damaged ----
    def extra_magic_twobitflip(self):
        self.b[self.h + 0] ^= 0x01
        self.b[self.h + 1] ^= 0x02

    # ---- negative control: compressed payload actually destroyed.
    # Header stays fully valid, so authentic Adler-32 proves payload damage.
    def m20_payload_destroyed(self):
        # PE path reads c_len bytes starting at section[1].rawdataptr (0x400).
        pe_off = struct.unpack_from("<I", self.b, 0x3C)[0]
        opt_size = struct.unpack_from("<H", self.b, pe_off + 20)[0]
        sec1 = pe_off + 24 + opt_size + 40
        raw_ptr = struct.unpack_from("<I", self.b, sec1 + 20)[0]
        self.b[raw_ptr + 0x1234] ^= 0xFF


# Exactly 20 acceptance samples (the negative control is the 20th).
# rows: id, output name slug, mutator method, category, description
CATALOG: list[tuple[str, str, str, str, str]] = [
    ("01", "magic_bitflip", "m01_magic_bitflip", "magic", "one bit flipped in UPX! last byte"),
    ("02", "magic_lowercase", "m02_magic_lowercase", "magic", "UPX! XOR 0x20 -> upx!"),
    ("03", "magic_zeroed", "m03_magic_zeroed", "magic", "all four magic bytes zeroed"),
    ("04", "magic_replaced", "m04_magic_replaced", "magic", "magic replaced with YTS!"),
    ("05", "magic_xor_encoded", "m05_magic_xor_encoded", "magic", "magic XOR-encoded with key 0x5A"),
    ("06", "hdr_checksum_zero", "m06_checksum_zero", "header-checksum", "header checksum byte set to 0"),
    ("07", "hdr_checksum_ff", "m07_checksum_ff", "header-checksum", "header checksum byte set to 0xFF"),
    ("08", "level_junk_bit", "m08_level_junk_bit", "header-field", "ignored level bit set; stale checksum"),
    ("09", "version_poke", "m09_version_poke", "header-field", "version byte 13 -> 12; stale checksum"),
    ("10", "format_poke", "m10_format_poke", "header-field", "format byte -> 42 invalid; stale checksum"),
    ("11", "method_poke", "m11_method_poke", "header-field", "method byte -> 0xFF invalid; stale checksum"),
    ("12", "uadler_byte", "m12_uadler_byte", "header-field", "u_adler corrupted; stale checksum"),
    ("13", "cadler_byte", "m13_cadler_byte", "header-field", "c_adler corrupted; stale checksum"),
    ("14", "ulen_byte", "m14_ulen_byte", "header-field", "u_len byte corrupted; stale checksum"),
    ("15", "both_adlers_multibyte", "m15_both_adlers_multibyte", "header-field", "two Adler fields damaged; stale checksum"),
    ("16", "rename_upx0", "m16_rename_upx0", "section-name", "PE section UPX0 renamed"),
    ("17", "rename_all_sections", "m17_rename_all_sections", "section-name", "UPX0/UPX1/.rsrc renamed"),
    ("18", "rename_and_magic", "m18_rename_and_magic", "combined", "sections renamed plus 2 magic bits flipped"),
    ("19", "section_names_zeroed", "m19_section_names_zeroed", "section-name", "all PE section names zeroed"),
    ("20", "payload_destroyed", "m20_payload_destroyed", "negative-control", "compressed stream byte flipped (unrepairable)"),
]


def main() -> int:
    if not BASE_PACKED.exists():
        raise SystemExit(f"missing base packed sample: {BASE_PACKED}")
    SAMPLES.mkdir(parents=True, exist_ok=True)

    base = BASE_PACKED.read_bytes()
    hdr_off = base.find(UPX_MAGIC)
    if hdr_off < 0:
        raise SystemExit("base file is not UPX packed")

    expected_sha = None
    if BASE_UNPACKED.exists():
        expected_sha = hashlib.sha256(BASE_UNPACKED.read_bytes()).hexdigest()

    manifest = {
        "base_packed": str(BASE_PACKED.relative_to(ROOT)),
        "base_sha256": hashlib.sha256(base).hexdigest(),
        "header_offset": hdr_off,
        "expected_unpacked_sha256": expected_sha,
        "sample_count": len(CATALOG),
        "samples": [],
    }

    for num, slug, method_name, category, desc in CATALOG:
        buf = bytearray(base)
        m = Mutations(buf, hdr_off)
        getattr(m, method_name)()
        name = f"{num}_{slug}.exe"
        out = SAMPLES / name
        out.write_bytes(buf)
        manifest["samples"].append(
            {
                "id": num,
                "file": f"deform/samples/{name}",
                "mutation": slug,
                "category": category,
                "description": desc,
                "sha256": hashlib.sha256(buf).hexdigest(),
            }
        )
        print(f"wrote {out.relative_to(ROOT)}  ({category}: {desc})")

    (SAMPLES / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"\n{len(CATALOG)} samples written; expected unpacked sha256={expected_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
