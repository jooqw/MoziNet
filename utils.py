import json
import secrets
from pathlib import Path
from typing import Any

PROFILE_QA_FIELD_BYTES = [16, 32, 16, 32, 64]
DEFAULT_GLOBALS: dict[str, Any] = {
    "SERVER_MAINTENANCE": False,
    "ALLOW_LOGIN_RECOVERY_IF_PLAYER_MISSING": True,
    "MAILBOX_MAX_MESSAGES": 50,
    "STAGE_DOWNLOAD_REWARD_TOKU": 300,
    "MAIL_EXPIRY_SECONDS": 30 * 24 * 60 * 60,
    "STAGE_MAX_PUBLIC_STAGES": 90,
}
_GLOBALS_PATH = Path(__file__).parent / "data/globals.json"


def trim_zero(data: bytes) -> bytes:
    return data.split(b"\x00", 1)[0]


def decode_euc_jp_safe(data: bytes) -> str:
    return trim_zero(data).decode("euc_jp", errors="replace")


def encode_euc_jp_fixed(text: str, size: int) -> bytes:
    raw = (text or "").encode("euc_jp", errors="ignore")
    if len(raw) >= size:
        return raw[:size]
    return raw + (b"\x00" * (size - len(raw)))


def build_unique_mail_field() -> bytes:
    # Mojib-Ribbon email can be only 8 hiragana chars
    # EUC-JP keeps it in this range(ぁ to ん)
    hiragana_chars = [chr(c) for c in range(0x3041, 0x3094)]
    rng = secrets.SystemRandom()
    text = "".join(rng.sample(hiragana_chars, 8))

    return text.encode("euc_jp")


def normalize_profile_qa_value(value: str, field_bytes: int) -> str:
    raw = "".join(ch for ch in str(value or "") if ch >= " " and ch != "\x7f")
    clipped = encode_euc_jp_fixed(raw, field_bytes)
    return decode_euc_jp_safe(clipped)


def parse_profile_qa_fields(description_raw: bytes) -> list[str]:
    values: list[str] = []
    offset = 0
    for field_size in PROFILE_QA_FIELD_BYTES:
        chunk = description_raw[offset : offset + field_size]
        values.append(normalize_profile_qa_value(decode_euc_jp_safe(chunk), field_size))
        offset += field_size
    return values


def default_profile_qa_fields() -> list[str]:
    return ["" for _ in PROFILE_QA_FIELD_BYTES]


def normalize_profile_qa_fields(raw: Any) -> list[str]:
    if isinstance(raw, list):
        values = [str(v) for v in raw]
        if len(values) == 10:
            values = [
                values[0],
                values[1] + values[2],
                values[3],
                values[4] + values[5],
                values[6] + values[7] + values[8] + values[9],
            ]
        out = default_profile_qa_fields()
        for i in range(min(len(values), len(PROFILE_QA_FIELD_BYTES))):
            out[i] = decode_euc_jp_safe(
                encode_euc_jp_fixed(values[i], PROFILE_QA_FIELD_BYTES[i])
            )
        return out

    if isinstance(raw, str):
        b = encode_euc_jp_fixed(raw, sum(PROFILE_QA_FIELD_BYTES))
        fields: list[str] = []
        offset = 0
        for field_size in PROFILE_QA_FIELD_BYTES:
            fields.append(decode_euc_jp_safe(b[offset : offset + field_size]))
            offset += field_size
        return fields

    return default_profile_qa_fields()


def encode_profile_qa_160(raw: Any) -> bytes:
    fields = normalize_profile_qa_fields(raw)
    out = bytearray()
    for i, field_size in enumerate(PROFILE_QA_FIELD_BYTES):
        out.extend(encode_euc_jp_fixed(fields[i], field_size))
    return bytes(out)


def _load_globals_raw() -> dict[str, Any]:
    try:
        if not _GLOBALS_PATH.exists():
            _GLOBALS_PATH.parent.mkdir(parents=True, exist_ok=True)
            _GLOBALS_PATH.write_text(
                json.dumps(DEFAULT_GLOBALS, indent=2), encoding="utf-8"
            )
        raw = json.loads(_GLOBALS_PATH.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return raw
    except Exception:
        pass
    return {}


def get_global_value(name: str, default: Any = None) -> Any:
    if default is None and name in DEFAULT_GLOBALS:
        default = DEFAULT_GLOBALS[name]
    return _load_globals_raw().get(name, default)


def get_global_bool(name: str, default: bool = False) -> bool:
    value = get_global_value(name, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def get_global_int(name: str, default: int = 0) -> int:
    value = get_global_value(name, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
