from __future__ import annotations

from typing import Any

import utils

FULLWIDTH_SPACE = "\u3000"


def _normalize_profile_qa_value(value: str, field_bytes: int) -> str:
    raw = "".join(ch for ch in str(value or "") if ch >= " " and ch != "\x7f")
    clipped = utils.encode_euc_jp_fixed(raw, field_bytes)
    return clipped.decode("euc_jp", errors="replace").split("\x00", 1)[0]


def _normalize_profile_qa_array(values: list[str]) -> list[str]:
    out = [
        _normalize_profile_qa_value(FULLWIDTH_SPACE * (field_bytes // 2), field_bytes)
        for field_bytes in utils.PROFILE_QA_FIELD_BYTES
    ]
    for i in range(min(len(values), len(utils.PROFILE_QA_FIELD_BYTES))):
        out[i] = _normalize_profile_qa_value(values[i], utils.PROFILE_QA_FIELD_BYTES[i])
    return out


def _description_bytes_from_player(player: dict[str, Any]) -> bytes:
    raw_values = player.get("profile_qa")
    if isinstance(raw_values, list):
        values = [str(v) for v in raw_values]
        if len(values) == 10:
            values = [
                values[0],
                values[1] + values[2],
                values[3],
                values[4] + values[5],
                values[6] + values[7] + values[8] + values[9],
            ]
        qa_values = _normalize_profile_qa_array(values)
    else:
        qa_values = _normalize_profile_qa_array([])

    out = bytearray()
    for i, qa in enumerate(qa_values):
        out.extend(utils.encode_euc_jp_fixed(qa, utils.PROFILE_QA_FIELD_BYTES[i]))
    return bytes(out)


class RankManager:
    def build_ranking_payload(self, players: list[dict[str, Any]]) -> bytes:
        sorted_players = sorted(
            players,
            key=lambda p: int(p.get("hesori_toku", 0) or 0),
            reverse=True,
        )

        out = bytearray()
        out.extend(len(sorted_players).to_bytes(4, "little"))

        for player in sorted_players:
            email = utils.encode_euc_jp_fixed(str(player.get("email_hiragana", "")), 16)
            name = utils.encode_euc_jp_fixed(str(player.get("player_name", "")), 16)
            dan = int(player.get("dan", 0) or 0) & 0xFFFF
            description = _description_bytes_from_player(player)
            toku = int(player.get("hesori_toku", 0) or 0)
            toku &= 0xFFFFFFFF

            out.extend(email)
            out.extend(name)
            out.extend(dan.to_bytes(2, "little"))
            out.extend(description)
            out.extend(toku.to_bytes(4, "little"))

        return bytes(out)
