from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import utils
from playerman import PlayerManager

STAGE_RECORD_SIZE = 284
STAGE_HEADER_SIZE = 93
STAGE_DOWNLOAD_REWARD_TOKU = utils.get_global_int("STAGE_DOWNLOAD_REWARD_TOKU", 300)
MAIL_EXPIRY_MS = utils.get_global_int("MAIL_EXPIRY_SECONDS", 30 * 24 * 60 * 60) * 1000
PROFILE_QA_FIELD_BYTES = [16, 32, 16, 32, 64]
MAILPUT_EXTRA_HEADER_SIZE = 20
MAX_LISTED_STAGES = utils.get_global_int("STAGE_MAX_PUBLIC_STAGES", 90)


class MailboxFullError(ValueError):
    pass


class MailRecipientNotFoundError(ValueError):
    pass


@dataclass
class Stage:
    id: str
    title: str
    description: str = ""
    owner_id: str = ""
    stage_number: int = 0
    unkconfetti: int = 0
    unk_value: int = 0
    stage_type: int = 0
    win_cutscene_type: int = 0
    flag2: int = 0
    flag4: int = 0
    IsCustom: int = 1
    unk_numeric3: int = 0
    retrieved_toku: int = 0
    date_created_ms: int = 0
    source_hash: str = ""
    is_mail: bool = False
    receiver_mail: str = ""
    receiver_player_id: str = ""
    attachment_toku: int = 0

    def __post_init__(self) -> None:
        if self.date_created_ms <= 0:
            self.date_created_ms = int(time.time() * 1000)

    def to_record_buffer(
        self, player: dict[str, Any] | None, *, use_attachment_toku: bool = False
    ) -> bytes:
        buf = bytearray(STAGE_RECORD_SIZE)
        id_bytes = bytes.fromhex(self.id)[:4]
        buf[0:4] = id_bytes[::-1]
        buf[4:8] = int(self.date_created_ms // 1000).to_bytes(4, "little", signed=False)

        player_data = player or {}
        player_name = str(player_data.get("player_name", "べべべ"))
        player_mail = str(player_data.get("email_hiragana", ""))
        player_dan = int(player_data.get("dan", 0) or 0) & 0xFFFF
        profile_qa = utils.normalize_profile_qa_fields(player_data.get("profile_qa"))

        buf[8:24] = utils.encode_euc_jp_fixed(player_mail, 16)
        buf[24:40] = utils.encode_euc_jp_fixed(player_name, 16)
        buf[40:42] = player_dan.to_bytes(2, "little", signed=False)

        offset = 42
        for i, field_size in enumerate(utils.PROFILE_QA_FIELD_BYTES):
            buf[offset : offset + field_size] = utils.encode_euc_jp_fixed(
                profile_qa[i], field_size
            )
            offset += field_size

        buf[202:231] = utils.encode_euc_jp_fixed(self.title, 29)
        buf[231] = self.stage_number & 0xFF
        buf[232:236] = int(self.unkconfetti).to_bytes(4, "little", signed=True)
        buf[236] = self.stage_type & 0xFF
        buf[237:241] = int(self.unk_value).to_bytes(4, "little", signed=True)
        buf[241] = self.win_cutscene_type & 0xFF
        buf[242] = self.flag4 & 0xFF
        buf[243] = self.IsCustom & 0xFF
        buf[244:248] = int(self.unk_numeric3).to_bytes(4, "little", signed=False)
        buf[248:280] = utils.encode_euc_jp_fixed(self.description, 32)

        toku_value = int(
            self.attachment_toku if use_attachment_toku else self.retrieved_toku
        )
        buf[280:284] = toku_value.to_bytes(4, "little", signed=False)
        return bytes(buf)


class StageManager:
    def __init__(self, base_dir: str | Path | None = None) -> None:
        root = Path(base_dir) if base_dir else Path(__file__).parent
        self._data_dir = root / "data"
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._stages_dir = root / "stages"
        self._stages_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self._data_dir / "stages.json"
        self._lock = threading.RLock()
        self._stages: dict[str, Stage] = {}
        self._load()

    def _load(self) -> None:
        if not self._index_path.exists():
            return
        try:
            raw = json.loads(self._index_path.read_text(encoding="utf-8"))
            for item in raw:
                stage = Stage(**item)
                self._stages[stage.id] = stage
        except Exception as exc:
            print(f"[stageman] load failed: {exc}")

    def _save(self) -> None:
        raw = [asdict(s) for s in self._stages.values()]
        self._index_path.write_text(
            json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def _delete_stage(self, stage_id: str):
        self._stages.pop(stage_id, None)
        stage_dir = self._stages_dir / stage_id
        try:
            if (stage_dir / "data.txt").exists():
                (stage_dir / "data.txt").unlink()
            if (stage_dir / "data.sht").exists():
                (stage_dir / "data.sht").unlink()
            if stage_dir.exists():
                stage_dir.rmdir()
        except Exception:
            pass

    def _verify_and_read_files(self, stage: Stage) -> bytes:
        stage_dir = self._stages_dir / stage.id
        txt_p, sht_p = stage_dir / "data.txt", stage_dir / "data.sht"
        if not txt_p.exists() or not sht_p.exists():
            raise ValueError("Stage files missing")

        txt_data, sht_data = txt_p.read_bytes(), sht_p.read_bytes()
        if hashlib.sha1(txt_data + sht_data).hexdigest() != stage.source_hash:
            raise ValueError(f"Integrity check failed for stage {stage.id}")

        return (
            len(txt_data).to_bytes(4, "little")
            + txt_data
            + len(sht_data).to_bytes(4, "little")
            + sht_data
        )

    def _process_expired_mail_refunds(
        self, owner_id: str, player_manager: PlayerManager
    ):
        now = int(time.time() * 1000)
        to_delete = []
        for sid, s in self._stages.items():
            if s.is_mail and s.owner_id == owner_id:
                if (now - s.date_created_ms) > MAIL_EXPIRY_MS:
                    player_manager.add_retrieve_result(
                        owner_id,
                        gained_toku=0,
                        returned_toku=s.attachment_toku,
                    )
                    to_delete.append(sid)
        if to_delete:
            for sid in to_delete:
                self._delete_stage(sid)
            self._save()

    def _enforce_public_stage_limit(self) -> None:
        public_stages = sorted(
            (s for s in self._stages.values() if not s.is_mail),
            key=lambda s: s.date_created_ms,
            reverse=True,
        )
        for stale_stage in public_stages[MAX_LISTED_STAGES:]:
            self._delete_stage(stale_stage.id)

    def create_stage(self, stage_blob: bytes, owner_id: str, **kwargs) -> Stage:
        header_size = STAGE_HEADER_SIZE + kwargs.get("extra_after_header", 0)
        txt_size = int.from_bytes(stage_blob[header_size : header_size + 4], "little")
        txt_buf = stage_blob[header_size + 4 : header_size + 4 + txt_size]
        sht_start = header_size + 4 + txt_size
        sht_size = int.from_bytes(stage_blob[sht_start : sht_start + 4], "little")
        sht_buf = stage_blob[sht_start + 4 : sht_start + 4 + sht_size]

        source_hash = hashlib.sha1(txt_buf + sht_buf).hexdigest()
        stage_id = secrets.token_hex(4)

        stage = Stage(
            id=stage_id,
            title=utils.decode_euc_jp_safe(stage_blob[0:29]),
            description=utils.decode_euc_jp_safe(stage_blob[41:73]),
            owner_id=owner_id,
            stage_number=stage_blob[29],
            unkconfetti=int.from_bytes(stage_blob[34:38], "little", signed=True),
            unk_value=int.from_bytes(stage_blob[30:34], "little", signed=True),
            win_cutscene_type=stage_blob[38],
            flag2=stage_blob[39],
            flag4=stage_blob[39],
            IsCustom=stage_blob[40],
            source_hash=source_hash,
            **kwargs,
        )

        stage_dir = self._stages_dir / stage_id
        stage_dir.mkdir(parents=True, exist_ok=True)
        (stage_dir / "data.txt").write_bytes(txt_buf)
        (stage_dir / "data.sht").write_bytes(sht_buf)

        with self._lock:
            self._stages[stage.id] = stage
            if not stage.is_mail:
                self._enforce_public_stage_limit()
            self._save()
        return stage

    def handle_put(
        self, payload: bytes, owner_id: str, player_manager: PlayerManager
    ) -> bytes:
        player_manager.apply_stage_put_player_info(
            owner_id,
            user_score=int.from_bytes(payload[73:77], "little"),
            user_dan=int.from_bytes(payload[77:81], "little"),
            beaten_stages=int.from_bytes(payload[81:85], "little"),
            toku_sent_mail=int.from_bytes(payload[85:89], "little"),
            retrieved_toku=int.from_bytes(payload[89:93], "little"),
        )
        self.create_stage(payload, owner_id)
        with self._lock:
            self._process_expired_mail_refunds(owner_id, player_manager)
        return player_manager.consume_retrieve_payload(owner_id)

    def handle_get(self, payload: bytes, player_manager: PlayerManager) -> bytes:
        stage_id = self._decode_stage_id_from_payload(payload)
        with self._lock:
            stage = self._stages.get(stage_id)
            if not stage or stage.is_mail:
                raise ValueError("Stage not found")

            player_manager.add_retrieve_result(
                stage.owner_id, gained_toku=STAGE_DOWNLOAD_REWARD_TOKU, returned_toku=0
            )
            return self._verify_and_read_files(stage)

    def handle_mailput(
        self, payload: bytes, owner_id: str, player_manager: PlayerManager
    ) -> bytes:
        receiver_mail = utils.decode_euc_jp_safe(payload[93:109])
        attachment_toku = int.from_bytes(payload[109:113], "little")
        recipient_id = player_manager.find_player_id_by_email(receiver_mail)
        if not recipient_id:
            raise MailRecipientNotFoundError("Recipient not found")

        with self._lock:
            mail_count = sum(
                1
                for s in self._stages.values()
                if s.is_mail and s.receiver_player_id == recipient_id
            )
            if mail_count >= utils.get_global_int("MAILBOX_MAX_MESSAGES", 50):
                raise MailboxFullError("Mailbox is full")

        self.create_stage(
            payload,
            owner_id,
            extra_after_header=MAILPUT_EXTRA_HEADER_SIZE,
            is_mail=True,
            receiver_mail=receiver_mail,
            receiver_player_id=recipient_id,
            attachment_toku=attachment_toku,
        )
        recipient = player_manager.get_player(recipient_id) or {}
        return (
            utils.encode_euc_jp_fixed(str(recipient.get("player_name", "")), 16)
            + (int(recipient.get("dan", 0)) & 0xFFFF).to_bytes(2, "little")
            + utils.encode_profile_qa_160(recipient.get("profile_qa"))
        )

    def handle_mailget(
        self, payload: bytes, recipient_id: str, player_manager: PlayerManager
    ) -> bytes:
        stage_id = self._decode_stage_id_from_payload(payload)
        with self._lock:
            stage = self._stages.get(stage_id)
            if (
                not stage
                or not stage.is_mail
                or stage.receiver_player_id != recipient_id
            ):
                raise ValueError("Mail not found")

            toku_header = (int(stage.attachment_toku) & 0xFFFFFFFF).to_bytes(
                4, "little"
            )
            return toku_header + self._verify_and_read_files(stage)

    def handle_maildel(
        self, payload: bytes, recipient_id: str, player_manager: PlayerManager
    ) -> bytes:
        stage_id = self._decode_stage_id_from_payload(payload)
        with self._lock:
            stage = self._stages.get(stage_id)
            if stage and stage.is_mail and stage.receiver_player_id == recipient_id:
                self._delete_stage(stage_id)
                self._save()
        return b"\x00"

    def build_list_payload(self, players: list[dict[str, Any]]) -> bytes:
        player_map = {
            str(p.get("secret_key_hex", "")): p
            for p in players
            if p.get("secret_key_hex")
        }
        with self._lock:
            stages = sorted(
                (s for s in self._stages.values() if not s.is_mail),
                key=lambda s: s.date_created_ms,
                reverse=True,
            )[:MAX_LISTED_STAGES]
            out = bytearray(len(stages).to_bytes(4, "little"))
            for s in stages:
                out.extend(s.to_record_buffer(player_map.get(s.owner_id)))
            return bytes(out)

    def build_maillist_payload(
        self, players: list[dict[str, Any]], recipient_id: str
    ) -> bytes:
        player_map = {
            str(p.get("secret_key_hex", "")): p
            for p in players
            if p.get("secret_key_hex")
        }
        with self._lock:
            stages = [
                s
                for s in self._stages.values()
                if s.is_mail and s.receiver_player_id == recipient_id
            ]
            out = bytearray(len(stages).to_bytes(4, "little"))
            for s in stages:
                out.extend(
                    s.to_record_buffer(
                        player_map.get(s.owner_id), use_attachment_toku=True
                    )
                )
            return bytes(out)

    @staticmethod
    def _decode_stage_id_from_payload(data: bytes) -> str:
        return data[:4][::-1].hex() if len(data) >= 4 else ""
