from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

WARNING_NO_FONT = "FONT(ERROR): no font data for code=%04X(EUC)\n"


@dataclass
class CFT:
    raw: bytes
    flags: int
    count: int
    offsets: memoryview  # u32[count]
    data: memoryview  # packed glyph stream


def _u16le(b: bytes, off: int) -> int:
    return b[off] | (b[off + 1] << 8)


def _u32le(b: bytes, off: int) -> int:
    return b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)


def load_cft_exact(path: str | Path) -> CFT:
    raw = Path(path).read_bytes()
    if len(raw) < 0x14:
        raise ValueError("CFT too small")

    if _u16le(raw, 0x00) != 0x4643:
        raise ValueError("FONT(ERROR): not a CFT file")
    if raw[0x02] != 2:
        raise ValueError(
            f"FONT(ERROR): unexpected CFT version {raw[0x02]} (expected=2)"
        )

    flags = raw[0x03]
    count = _u32le(raw, 0x04)
    off_offsets = _u32le(raw, 0x0C)
    off_data = _u32le(raw, 0x10)

    if off_offsets > len(raw) or off_data > len(raw):
        raise ValueError("CFT pointer out of range")

    need = off_offsets + count * 4
    if need > len(raw):
        raise ValueError("CFT offsets table out of range")

    return CFT(
        raw=raw,
        flags=flags | 0x01,
        count=count,
        offsets=memoryview(raw)[off_offsets : off_offsets + count * 4],
        data=memoryview(raw)[off_data:],
    )


def euc_index_exact(code_euc_u16: int) -> int:
    hi = (code_euc_u16 >> 8) & 0xFF
    lo = code_euc_u16 & 0xFF
    return (hi - 0xA1) * 94 + (lo - 0xA1)


def validate_euc_exact(cft: CFT, code_euc_u16: int) -> Tuple[bool, Optional[str]]:
    idx = euc_index_exact(code_euc_u16)
    if idx < 0 or idx >= cft.count:
        return False, WARNING_NO_FONT % (code_euc_u16 & 0xFFFF)
    return True, None


def _iter_u16_be(data: bytes):
    for i in range(0, len(data) - 1, 2):
        b0 = data[i]
        b1 = data[i + 1]
        if b0 == 0 or b1 == 0:
            break
        yield (b0 << 8) | b1


def validate_euc_stream(cft: CFT, data: bytes) -> Tuple[bool, list[str]]:
    warnings: list[str] = []
    ok = True
    for code in _iter_u16_be(data):
        valid, warn = validate_euc_exact(cft, code)
        if not valid:
            ok = False
            warnings.append(warn or "")
    return ok, warnings


def _default_cft_path() -> Path:
    return Path(__file__).with_name("dfp5.cft")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate EUC-JP codes against Mojibribon CFT table."
    )
    parser.add_argument(
        "--cft",
        type=Path,
        default=_default_cft_path(),
        help="Path to CFT file (default: ./dfp5.cft)",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--hex", dest="hex_bytes", help="EUC bytes as hex, e.g. A4A2A4A4"
    )
    group.add_argument("--text", help="Unicode text to encode as euc_jp then validate")
    args = parser.parse_args()

    cft = load_cft_exact(args.cft)
    if args.hex_bytes is not None:
        raw = bytes.fromhex(args.hex_bytes)
    else:
        raw = args.text.encode("euc_jp")

    ok, warnings = validate_euc_stream(cft, raw)
    if ok:
        print("OK")
        return 0

    for w in warnings:
        print(w, end="")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
