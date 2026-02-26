from __future__ import annotations

import importlib
import json
import os
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import utils

REGISTER_PAYLOAD_SIZE = 214
LOGIN_PAYLOAD_SIZE = 246
SCORE_PAYLOAD_SIZE = 24


def _load_euc_checker_module():
    checker_dir = Path(__file__).parent / "euc-jp"
    checker_path = checker_dir / "checker.py"
    if not checker_path.exists():
        raise RuntimeError(f"failed to load EUC checker from {checker_path}")
    if str(checker_dir) not in sys.path:
        sys.path.insert(0, str(checker_dir))
    return importlib.import_module("checker")


@dataclass
class RegisterResult:
    player_id: str
    valid_description: bool
    warnings: list[str]
    reply_payload: bytes


@dataclass
class LoginResult:
    player_id: str
    email: str
    secret_key_hex: str
    valid_description: bool
    warnings: list[str]


class PlayerManager:
    def __init__(self, base_dir: str | Path | None = None) -> None:
        root = (
            Path(base_dir) if base_dir else Path(__file__).parent / "data" / "players"
        )
        self.players_dir = root
        self.players_dir.mkdir(parents=True, exist_ok=True)

        checker = _load_euc_checker_module()
        cft_path = Path(__file__).parent / "euc-jp" / "dfp5v.cft"
        self._validate_euc_stream = checker.validate_euc_stream
        self._cft = checker.load_cft_exact(cft_path)
        self._lock = threading.RLock()

    def _player_path(self, player_id: str) -> Path:
        safe = (
            "".join(ch for ch in player_id if ch.isalnum() or ch in ("-", "_"))
            or "unknown"
        )
        return self.players_dir / f"{safe}.json"

    def _load_player(self, player_id: str) -> dict[str, Any]:
        with self._lock:
            path = self._player_path(player_id)
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
            return {"secret_key_hex": player_id}

    def _save_player(self, player_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            path = self._player_path(player_id)
            path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
            )

    def _validate_description_chunks(
        self, description_raw: bytes
    ) -> tuple[bool, list[str]]:
        warnings, valid = [], True
        offset = 0
        for i, field_size in enumerate(utils.PROFILE_QA_FIELD_BYTES, 1):
            chunk = description_raw[offset : offset + field_size]
            offset += field_size

            ok, chunk_warnings = self._validate_euc_stream(self._cft, chunk)
            if not ok:
                valid = False
                warnings.extend(
                    f"[desc chunk {i}] {w.rstrip()}" for w in chunk_warnings
                )

            if b"\x00\x00" in chunk:
                _, trailing = chunk.split(b"\x00\x00", 1)
                if any(b != 0 for b in trailing):
                    valid = False
                    warnings.append(
                        f"[desc chunk {i}] trailing non-zero bytes after terminator"
                    )
        return valid, warnings

    def _parse_and_update_player(
        self,
        player_id: str,
        dnas: bytes,
        name: bytes,
        dan: bytes,
        desc: bytes,
        toku: bytes,
    ) -> tuple[bool, list[str]]:

        valid_desc, warnings = self._validate_description_chunks(desc)

        player = self._load_player(player_id)
        player.update(
            {
                "dnas_id": utils.trim_zero(dnas).decode("ascii", errors="ignore"),
                "player_name": utils.decode_euc_jp_safe(name),
                "dan": int.from_bytes(dan, "little") & 0xFFFF,
                "hesori_toku": int.from_bytes(toku, "little") & 0xFFFFFFFF,
                "profile_qa": utils.parse_profile_qa_fields(desc),
                "description_valid_euc_jp": valid_desc,
                "banned_permanent": player.get("banned_permanent", False),
                "temp_ban_seconds": player.get("temp_ban_seconds", 0),
                "temp_ban_started_at": player.get("temp_ban_started_at", 0),
            }
        )

        self._save_player(player_id, player)
        return valid_desc, warnings

    def has_player(self, player_id: str) -> bool:
        return self._player_path(player_id).exists()

    def get_player(self, player_id: str) -> dict[str, Any] | None:
        return self._load_player(player_id) if self.has_player(player_id) else None

    def handle_register(self, payload: bytes) -> RegisterResult:
        if len(payload) < REGISTER_PAYLOAD_SIZE:
            raise ValueError("Payload too short")

        secret_key = os.urandom(16)
        player_id = secret_key.hex()
        email_raw = utils.build_unique_mail_field()

        valid, warnings = self._parse_and_update_player(
            player_id,
            payload[0:32],
            payload[32:48],
            payload[48:50],
            payload[50:210],
            payload[210:214],
        )

        player = self._load_player(player_id)
        player["email_hiragana"] = utils.decode_euc_jp_safe(email_raw)
        self._save_player(player_id, player)

        return RegisterResult(player_id, valid, warnings, email_raw + secret_key)

    def handle_login(self, payload: bytes) -> LoginResult:
        if len(payload) < LOGIN_PAYLOAD_SIZE:
            raise ValueError("Payload too short")

        email = utils.decode_euc_jp_safe(payload[0:16])
        player_id = payload[16:32].hex()

        if not self.has_player(player_id) and not utils.get_global_bool(
            "ALLOW_LOGIN_RECOVERY_IF_PLAYER_MISSING", True
        ):
            raise ValueError("Unknown secret key")

        valid, warnings = self._parse_and_update_player(
            player_id,
            payload[32:64],
            payload[64:80],
            payload[80:82],
            payload[82:242],
            payload[242:246],
        )

        return LoginResult(player_id, email, player_id, valid, warnings)

    def handle_score(self, player_id: str, payload: bytes) -> dict[str, int]:
        if len(payload) < SCORE_PAYLOAD_SIZE:
            raise ValueError("Payload too short")

        vals = [int.from_bytes(payload[i : i + 4], "little") for i in range(0, 24, 4)]
        score = {
            "hesori_toku": vals[0],
            "stages_beaten_toku": vals[1],
            "dan": vals[2],
            "stages_beaten": vals[3],
            "toku_sent_email": vals[4],
            "retrieved_score_toku": vals[5],
        }

        player = self._load_player(player_id)
        player["hesori_toku"] = score["hesori_toku"]
        player["dan"] = score["dan"] & 0xFFFF
        player["score_last"] = {
            k: v for k, v in score.items() if k not in ("hesori_toku", "dan")
        }
        self._save_player(player_id, player)
        return score

    def add_retrieve_result(
        self, player_id: str, gained_toku: int = 0, returned_toku: int = 0
    ) -> None:
        player = self._load_player(player_id)
        player["retrieve_pending_gained_toku"] = (
            player.get("retrieve_pending_gained_toku", 0) + gained_toku
        ) & 0xFFFFFFFF
        player["retrieve_pending_returned_toku"] = (
            player.get("retrieve_pending_returned_toku", 0) + returned_toku
        ) & 0xFFFFFFFF
        self._save_player(player_id, player)

    def consume_retrieve_payload(self, player_id: str) -> bytes:
        player = self._load_player(player_id)
        g = player.pop("retrieve_pending_gained_toku", 0) & 0xFFFFFFFF
        r = player.pop("retrieve_pending_returned_toku", 0) & 0xFFFFFFFF
        self._save_player(player_id, player)
        return g.to_bytes(4, "little") + r.to_bytes(4, "little")

    def apply_stage_put_player_info(self, player_id: str, **kwargs) -> None:
        player = self._load_player(player_id)
        player["hesori_toku"] = kwargs.get("user_score", 0) & 0xFFFFFFFF
        player["dan"] = kwargs.get("user_dan", 0) & 0xFFFF
        player["score_last"] = {
            "stages_beaten": kwargs.get("beaten_stages", 0),
            "toku_sent_email": kwargs.get("toku_sent_mail", 0),
            "retrieved_score_toku": kwargs.get("retrieved_toku", 0),
        }
        self._save_player(player_id, player)

    def find_player_id_by_email(self, email: str) -> str | None:
        with self._lock:
            for path in self.players_dir.glob("*.json"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    if data.get("email_hiragana") == email:
                        return data.get("secret_key_hex")
                except:
                    continue
        return None

    def get_account_restriction_status(self, player_id: str) -> bytes:
        player = self.get_player(player_id)
        if not player:
            return b"OK"
        if player.get("banned_permanent") or player.get("banned"):
            return b"EX"

        sec = int(player.get("temp_ban_seconds", 0))
        if sec <= 0:
            return b"OK"

        start = int(player.get("temp_ban_started_at", 0))
        if start <= 0:
            player["temp_ban_started_at"] = int(time.time())
            self._save_player(player_id, player)
            return b"DN"

        if time.time() < (start + sec):
            return b"DN"

        player.update({"temp_ban_seconds": 0, "temp_ban_started_at": 0})
        self._save_player(player_id, player)
        return b"OK"

    def list_players(self) -> list[dict[str, Any]]:
        with self._lock:
            players = []
            for path in self.players_dir.glob("*.json"):
                try:
                    players.append(json.loads(path.read_text(encoding="utf-8")))
                except:
                    continue
            return players
