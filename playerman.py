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
PROFILE_QA_FIELD_BYTES = [16, 32, 16, 32, 64]


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

    def _validate_description_chunks(
        self, description_raw: bytes
    ) -> tuple[bool, list[str]]:
        warnings: list[str] = []
        valid = True

        offset = 0
        for chunk_no, field_size in enumerate(utils.PROFILE_QA_FIELD_BYTES, start=1):
            chunk = description_raw[offset : offset + field_size]
            offset += field_size

            chunk_ok, chunk_warnings = self._validate_euc_stream(self._cft, chunk)
            if not chunk_ok:
                valid = False
                warnings.extend(
                    f"[desc chunk {chunk_no}] {w.rstrip()}" for w in chunk_warnings
                )

            # after first 0x0000 pair inside a chunk, all remaining bytes in that chunk must stay zero.
            saw_terminator = False
            for i in range(0, len(chunk), 2):
                b0 = chunk[i]
                b1 = chunk[i + 1]
                if not saw_terminator and b0 == 0x00 and b1 == 0x00:
                    saw_terminator = True
                    continue
                if saw_terminator and (b0 != 0x00 or b1 != 0x00):
                    valid = False
                    warnings.append(
                        f"[desc chunk {chunk_no}] trailing non-zero bytes after 0000 terminator"
                    )
                    break

        return valid, warnings

    def _player_path(self, player_id: str) -> Path:
        safe = "".join(ch for ch in player_id if ch.isalnum() or ch in ("-", "_"))
        if not safe:
            safe = "unknown_player"
        return self.players_dir / f"{safe}.json"

    def _load_player(self, player_id: str) -> dict[str, Any]:
        with self._lock:
            path = self._player_path(player_id)
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
            return {"dnas_id": player_id}

    def has_player(self, player_id: str) -> bool:
        with self._lock:
            return self._player_path(player_id).exists()

    def _save_player(self, player_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            path = self._player_path(player_id)
            path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
            )

    def get_player(self, player_id: str) -> dict[str, Any] | None:
        with self._lock:
            path = self._player_path(player_id)
            if not path.exists():
                return None
            return json.loads(path.read_text(encoding="utf-8"))

    def apply_stage_put_player_info(
        self,
        player_id: str,
        *,
        user_score: int,
        user_dan: int,
        beaten_stages: int,
        toku_sent_mail: int,
        retrieved_toku: int,
    ) -> None:
        player = self._load_player(player_id)
        player["hesori_toku"] = int(user_score) & 0xFFFFFFFF
        player["dan"] = int(user_dan) & 0xFFFF
        player["score_last"] = {
            "stages_beaten": int(beaten_stages) & 0xFFFFFFFF,
            "toku_sent_email": int(toku_sent_mail) & 0xFFFFFFFF,
            "retrieved_score_toku": int(retrieved_toku) & 0xFFFFFFFF,
        }
        self._save_player(player_id, player)

    def add_hesori_toku(self, player_id: str, delta: int) -> None:
        player = self._load_player(player_id)
        current = int(player.get("hesori_toku", 0) or 0)
        player["hesori_toku"] = (current + int(delta)) & 0xFFFFFFFF
        self._save_player(player_id, player)

    def add_retrieve_result(
        self, player_id: str, *, gained_toku: int = 0, returned_toku: int = 0
    ) -> None:
        player = self._load_player(player_id)
        current_gained = int(player.get("retrieve_pending_gained_toku", 0) or 0)
        current_returned = int(player.get("retrieve_pending_returned_toku", 0) or 0)
        player["retrieve_pending_gained_toku"] = (
            current_gained + int(gained_toku)
        ) & 0xFFFFFFFF
        player["retrieve_pending_returned_toku"] = (
            current_returned + int(returned_toku)
        ) & 0xFFFFFFFF
        self._save_player(player_id, player)

    def consume_retrieve_payload(self, player_id: str) -> bytes:
        player = self._load_player(player_id)
        gained = int(player.get("retrieve_pending_gained_toku", 0) or 0) & 0xFFFFFFFF
        returned = (
            int(player.get("retrieve_pending_returned_toku", 0) or 0) & 0xFFFFFFFF
        )
        player["retrieve_pending_gained_toku"] = 0
        player["retrieve_pending_returned_toku"] = 0
        self._save_player(player_id, player)
        return gained.to_bytes(4, "little", signed=False) + returned.to_bytes(
            4, "little", signed=False
        )

    def handle_register(self, payload_without_command: bytes) -> RegisterResult:
        if len(payload_without_command) < REGISTER_PAYLOAD_SIZE:
            raise ValueError(
                f"REGISTER payload too short: got={len(payload_without_command)} need={REGISTER_PAYLOAD_SIZE}"
            )

        dnas_raw = payload_without_command[0:32]
        name_raw = payload_without_command[32:48]
        dan_raw = payload_without_command[48:50]
        description_raw = payload_without_command[50:210]
        total_toku_raw = payload_without_command[210:214]

        player_name = utils.decode_euc_jp_safe(name_raw)
        email_raw = utils.build_unique_mail_field()
        email = utils.decode_euc_jp_safe(email_raw)
        secret_key_raw = os.urandom(16)
        secret_key_hex = secret_key_raw.hex()
        player_id = secret_key_hex
        dan = int.from_bytes(dan_raw, "little", signed=False)
        hesori_toku = int.from_bytes(total_toku_raw, "little", signed=False)

        valid_description, warnings = self._validate_description_chunks(description_raw)
        if not valid_description:
            for warning in warnings:
                print(warning)

        profile_qa = utils.parse_profile_qa_fields(description_raw)

        player = self._load_player(player_id)
        player["secret_key_hex"] = secret_key_hex
        player["dnas_id"] = utils.trim_zero(dnas_raw).decode("ascii", errors="ignore")
        player["player_name"] = player_name
        player["email_hiragana"] = email
        player["dan"] = dan
        player["hesori_toku"] = hesori_toku
        player["description_valid_euc_jp"] = bool(valid_description)
        player["profile_qa"] = profile_qa
        player["banned_permanent"] = bool(player.get("banned_permanent", False))
        player["temp_ban_seconds"] = int(player.get("temp_ban_seconds", 0) or 0)
        player["temp_ban_started_at"] = int(player.get("temp_ban_started_at", 0) or 0)

        self._save_player(player_id, player)
        return RegisterResult(
            player_id=player_id,
            valid_description=bool(valid_description),
            warnings=warnings,
            reply_payload=email_raw + secret_key_raw,
        )

    def handle_login(self, payload_without_command: bytes) -> LoginResult:
        if len(payload_without_command) < LOGIN_PAYLOAD_SIZE:
            raise ValueError(
                f"LOGIN payload too short: got={len(payload_without_command)} need={LOGIN_PAYLOAD_SIZE}"
            )

        email_raw = payload_without_command[0:16]
        secret_key_raw = payload_without_command[16:32]
        dnas_raw = payload_without_command[32:64]
        name_raw = payload_without_command[64:80]
        dan_raw = payload_without_command[80:82]
        description_raw = payload_without_command[82:242]
        total_toku_raw = payload_without_command[242:246]

        email = utils.decode_euc_jp_safe(email_raw)
        secret_key_hex = secret_key_raw.hex()
        player_id = secret_key_hex
        player_exists = self.has_player(player_id)
        if not player_exists and not utils.get_global_bool(
            "ALLOW_LOGIN_RECOVERY_IF_PLAYER_MISSING", True
        ):
            raise ValueError("LOGIN rejected: unknown secret key")
        player_name = utils.decode_euc_jp_safe(name_raw)
        dan = int.from_bytes(dan_raw, "little", signed=False)
        hesori_toku = int.from_bytes(total_toku_raw, "little", signed=False)

        valid_description, warnings = self._validate_description_chunks(description_raw)
        if not valid_description:
            for warning in warnings:
                print(warning)

        profile_qa = utils.parse_profile_qa_fields(description_raw)

        player = self._load_player(player_id) if player_exists else {}
        player["secret_key_hex"] = secret_key_hex
        player["dnas_id"] = utils.trim_zero(dnas_raw).decode("ascii", errors="ignore")
        player["player_name"] = player_name
        player["email_hiragana"] = email
        player["dan"] = dan
        player["hesori_toku"] = hesori_toku
        player["description_valid_euc_jp"] = bool(valid_description)
        player["profile_qa"] = profile_qa
        player["banned_permanent"] = bool(player.get("banned_permanent", False))
        player["temp_ban_seconds"] = int(player.get("temp_ban_seconds", 0) or 0)
        player["temp_ban_started_at"] = int(player.get("temp_ban_started_at", 0) or 0)
        self._save_player(player_id, player)

        return LoginResult(
            player_id=player_id,
            email=email,
            secret_key_hex=secret_key_hex,
            valid_description=bool(valid_description),
            warnings=warnings,
        )

    def handle_score(
        self, player_id: str, payload_without_command: bytes
    ) -> dict[str, int]:
        if len(payload_without_command) < SCORE_PAYLOAD_SIZE:
            raise ValueError(
                f"SCORE payload too short: got={len(payload_without_command)} need={SCORE_PAYLOAD_SIZE}"
            )

        values = [
            int.from_bytes(payload_without_command[i : i + 4], "little", signed=False)
            for i in range(0, SCORE_PAYLOAD_SIZE, 4)
        ]

        score = {
            "hesori_toku": values[0],
            "stages_beaten_toku": values[1], # guess
            "dan": values[2],
            "stages_beaten": values[3],
            "toku_sent_email": values[4],
            "retrieved_score_toku": values[5],
        }

        player = self._load_player(player_id)
        player["score_last"] = {
            "stages_beaten_toku": score["stages_beaten_toku"],
            "stages_beaten": score["stages_beaten"],
            "toku_sent_email": score["toku_sent_email"],
            "retrieved_score_toku": score["retrieved_score_toku"],
        }
        player["hesori_toku"] = score["hesori_toku"]
        player["dan"] = score["dan"]
        self._save_player(player_id, player)
        return score

    def list_players(self) -> list[dict[str, Any]]:
        with self._lock:
            players: list[dict[str, Any]] = []
            for path in self.players_dir.glob("*.json"):
                try:
                    players.append(json.loads(path.read_text(encoding="utf-8")))
                except Exception:
                    continue
            return players

    def find_player_id_by_email(self, email: str) -> str | None:
        target = str(email or "")
        with self._lock:
            for path in self.players_dir.glob("*.json"):
                try:
                    player = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if str(player.get("email_hiragana", "")) == target:
                    pid = str(player.get("secret_key_hex", "") or "")
                    if pid:
                        return pid
            return None

    def get_account_restriction_status(self, player_id: str) -> bytes:
        player = self.get_player(player_id)
        if player is None:
            return b"OK"

        if bool(player.get("banned_permanent", False) or player.get("banned", False)):
            return b"EX"

        temp_ban_seconds = int(player.get("temp_ban_seconds", 0) or 0)
        if temp_ban_seconds <= 0:
            return b"OK"

        started_at = int(player.get("temp_ban_started_at", 0) or 0)
        if started_at <= 0:
            player["temp_ban_started_at"] = int(time.time())
            self._save_player(player_id, player)
            return b"DN"

        now = int(time.time())
        if now < started_at + temp_ban_seconds:
            return b"DN"

        # Auto-clear expired temporary bans.
        player["temp_ban_seconds"] = 0
        player["temp_ban_started_at"] = 0
        self._save_player(player_id, player)
        return b"OK"
